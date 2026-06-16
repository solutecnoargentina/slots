const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const fs = require("fs");
const path = require("path");

require("dotenv").config({ path: "/opt/slot-engine/config/.env" });

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(morgan("combined"));

app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 120
}));

const pool = new Pool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASS
});

function tokenFirmado(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "8h" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "No autorizado" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

function soloSuperadmin(req, res, next) {
  if (req.user.role !== "superadmin") {
    return res.status(403).json({ error: "Acceso solo superadmin" });
  }
  next();
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('superadmin','admin','user')),
      balance NUMERIC(14,2) NOT NULL DEFAULT 0,
      is_active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS engine_config (
      id SERIAL PRIMARY KEY,
      house_percentage NUMERIC(5,2) NOT NULL DEFAULT 13,
      pool_stage_days INTEGER NOT NULL DEFAULT 30,
      small_prize_percentage NUMERIC(5,2) NOT NULL DEFAULT 35,
      medium_prize_percentage NUMERIC(5,2) NOT NULL DEFAULT 25,
      big_prize_percentage NUMERIC(5,2) NOT NULL DEFAULT 15,
      bonus_percentage NUMERIC(5,2) NOT NULL DEFAULT 10,
      multiplier_percentage NUMERIC(5,2) NOT NULL DEFAULT 5,
      pool_percentage NUMERIC(5,2) NOT NULL DEFAULT 10,
      maintenance_mode BOOLEAN NOT NULL DEFAULT false,
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS pool_stages (
      id SERIAL PRIMARY KEY,
      starts_at TIMESTAMP NOT NULL DEFAULT NOW(),
      ends_at TIMESTAMP NOT NULL,
      opening_amount NUMERIC(14,2) NOT NULL DEFAULT 0,
      current_amount NUMERIC(14,2) NOT NULL DEFAULT 0,
      returned_to_house NUMERIC(14,2) NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS wallet_movements (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      type TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL,
      balance_before NUMERIC(14,2) NOT NULL,
      balance_after NUMERIC(14,2) NOT NULL,
      note TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS spins (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      bet_amount NUMERIC(14,2) NOT NULL,
      house_amount NUMERIC(14,2) NOT NULL,
      playable_amount NUMERIC(14,2) NOT NULL,
      prize_amount NUMERIC(14,2) NOT NULL DEFAULT 0,
      result_json JSONB NOT NULL,
      balance_before NUMERIC(14,2) NOT NULL,
      balance_after NUMERIC(14,2) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY,
      actor_user_id INTEGER,
      action TEXT NOT NULL,
      detail JSONB,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  const cfg = await pool.query("SELECT id FROM engine_config LIMIT 1");
  if (cfg.rowCount === 0) {
    await pool.query(`
      INSERT INTO engine_config (
        house_percentage,
        pool_stage_days
      ) VALUES ($1,$2)
    `, [
      Number(process.env.HOUSE_PERCENTAGE || 13),
      Number(process.env.POOL_STAGE_DAYS || 30)
    ]);
  }

  const stage = await pool.query("SELECT id FROM pool_stages WHERE status='active' LIMIT 1");
  if (stage.rowCount === 0) {
    await pool.query(`
      INSERT INTO pool_stages (ends_at)
      VALUES (NOW() + INTERVAL '30 days')
    `);
  }

  const email = process.env.SUPERADMIN_EMAIL;
  const password = process.env.SUPERADMIN_PASSWORD;

  const existing = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
  if (existing.rowCount === 0) {
    const hash = await bcrypt.hash(password, 12);
    await pool.query(`
      INSERT INTO users (email, password_hash, role, balance)
      VALUES ($1,$2,'superadmin',0)
    `, [email, hash]);
  }
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    name: "Slot Engine Backend",
    status: "online"
  });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};

  const q = await pool.query(
    "SELECT * FROM users WHERE email=$1 AND is_active=true",
    [email]
  );

  if (q.rowCount === 0) {
    return res.status(401).json({ error: "Credenciales inválidas" });
  }

  const user = q.rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);

  if (!ok) {
    return res.status(401).json({ error: "Credenciales inválidas" });
  }

  res.json({
    token: tokenFirmado(user),
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
      balance: user.balance
    }
  });
});

app.get("/api/me", auth, async (req, res) => {
  const q = await pool.query(
    "SELECT id,email,role,balance,is_active,created_at FROM users WHERE id=$1",
    [req.user.id]
  );
  res.json(q.rows[0]);
});

app.get("/api/superadmin/config", auth, soloSuperadmin, async (req, res) => {
  const cfg = await pool.query("SELECT * FROM engine_config ORDER BY id DESC LIMIT 1");
  const poolStage = await pool.query("SELECT * FROM pool_stages WHERE status='active' ORDER BY id DESC LIMIT 1");
  res.json({
    config: cfg.rows[0],
    active_pool_stage: poolStage.rows[0]
  });
});

app.put("/api/superadmin/config", auth, soloSuperadmin, async (req, res) => {
  const body = req.body || {};

  const values = {
    house_percentage: Number(body.house_percentage),
    pool_stage_days: Number(body.pool_stage_days),
    small_prize_percentage: Number(body.small_prize_percentage),
    medium_prize_percentage: Number(body.medium_prize_percentage),
    big_prize_percentage: Number(body.big_prize_percentage),
    bonus_percentage: Number(body.bonus_percentage),
    multiplier_percentage: Number(body.multiplier_percentage),
    pool_percentage: Number(body.pool_percentage),
    maintenance_mode: Boolean(body.maintenance_mode)
  };

  if (values.house_percentage < 0 || values.house_percentage > 50) {
    return res.status(400).json({ error: "Porcentaje de casa inválido" });
  }

  const totalDistribucion =
    values.small_prize_percentage +
    values.medium_prize_percentage +
    values.big_prize_percentage +
    values.bonus_percentage +
    values.multiplier_percentage +
    values.pool_percentage;

  if (Math.round(totalDistribucion * 100) / 100 !== 100) {
    return res.status(400).json({
      error: "La distribución del fondo jugable debe sumar 100%",
      total: totalDistribucion
    });
  }

  const updated = await pool.query(`
    UPDATE engine_config SET
      house_percentage=$1,
      pool_stage_days=$2,
      small_prize_percentage=$3,
      medium_prize_percentage=$4,
      big_prize_percentage=$5,
      bonus_percentage=$6,
      multiplier_percentage=$7,
      pool_percentage=$8,
      maintenance_mode=$9,
      updated_at=NOW()
    WHERE id=(SELECT id FROM engine_config ORDER BY id DESC LIMIT 1)
    RETURNING *
  `, [
    values.house_percentage,
    values.pool_stage_days,
    values.small_prize_percentage,
    values.medium_prize_percentage,
    values.big_prize_percentage,
    values.bonus_percentage,
    values.multiplier_percentage,
    values.pool_percentage,
    values.maintenance_mode
  ]);

  await pool.query(
    "INSERT INTO audit_logs (actor_user_id, action, detail) VALUES ($1,$2,$3)",
    [req.user.id, "UPDATE_ENGINE_CONFIG", values]
  );

  res.json({ ok: true, config: updated.rows[0] });
});

app.get("/api/superadmin/stats", auth, soloSuperadmin, async (req, res) => {
  const stats = await pool.query(`
    SELECT
      COALESCE(SUM(bet_amount),0) AS total_bets,
      COALESCE(SUM(house_amount),0) AS total_house,
      COALESCE(SUM(playable_amount),0) AS total_playable,
      COALESCE(SUM(prize_amount),0) AS total_prizes,
      COUNT(*) AS total_spins
    FROM spins
  `);

  const users = await pool.query(`
    SELECT role, COUNT(*) AS total
    FROM users
    GROUP BY role
  `);

  res.json({
    financial: stats.rows[0],
    users: users.rows
  });
});



function randomItemWeighted(items) {
  const total = items.reduce((sum, item) => sum + Number(item.weight), 0);
  let r = Math.random() * total;
  for (const item of items) {
    r -= Number(item.weight);
    if (r <= 0) return item;
  }
  return items[items.length - 1];
}

function generarGrilla(symbols) {
  const grid = [];
  for (let row = 0; row < 3; row++) {
    const line = [];
    for (let reel = 0; reel < 5; reel++) {
      line.push(randomItemWeighted(symbols).code);
    }
    grid.push(line);
  }
  return grid;
}

const PAYLINES_20 = [
  [[0,0],[0,1],[0,2],[0,3],[0,4]],
  [[1,0],[1,1],[1,2],[1,3],[1,4]],
  [[2,0],[2,1],[2,2],[2,3],[2,4]],
  [[0,0],[1,1],[2,2],[1,3],[0,4]],
  [[2,0],[1,1],[0,2],[1,3],[2,4]],
  [[0,0],[0,1],[1,2],[2,3],[2,4]],
  [[2,0],[2,1],[1,2],[0,3],[0,4]],
  [[1,0],[0,1],[0,2],[0,3],[1,4]],
  [[1,0],[2,1],[2,2],[2,3],[1,4]],
  [[0,0],[1,1],[1,2],[1,3],[0,4]],
  [[2,0],[1,1],[1,2],[1,3],[2,4]],
  [[1,0],[0,1],[1,2],[2,3],[1,4]],
  [[1,0],[2,1],[1,2],[0,3],[1,4]],
  [[0,0],[1,1],[0,2],[1,3],[0,4]],
  [[2,0],[1,1],[2,2],[1,3],[2,4]],
  [[0,0],[2,1],[0,2],[2,3],[0,4]],
  [[2,0],[0,1],[2,2],[0,3],[2,4]],
  [[1,0],[1,1],[0,2],[1,3],[1,4]],
  [[1,0],[1,1],[2,2],[1,3],[1,4]],
  [[0,0],[2,1],[2,2],[2,3],[0,4]]
];

function evaluarPremio(grid, paytable, betAmount) {
  let totalPrize = 0;
  const wins = [];

  for (let i = 0; i < PAYLINES_20.length; i++) {
    const line = PAYLINES_20[i];
    const symbols = line.map(([r,c]) => grid[r][c]);

    let base = symbols[0];
    if (base === "W") base = symbols.find(x => x !== "W") || "W";

    let count = 0;
    for (const sym of symbols) {
      if (sym === base || sym === "W") count++;
      else break;
    }

    if (count >= 3 && base !== "B" && base !== "W") {
      const pay = paytable.find(p =>
        p.symbol_code === base &&
        Number(p.match_count) === count
      );

      if (pay) {
        const lineBet = Number(betAmount) / 20;
        const prize = lineBet * Number(pay.multiplier);
        totalPrize += prize;

        wins.push({
          line: i + 1,
          symbol: base,
          count,
          multiplier: Number(pay.multiplier),
          prize: Number(prize.toFixed(2))
        });
      }
    }
  }

  const flat = grid.flat();
  const bonusCount = flat.filter(x => x === "B").length;
  let bonusPrize = 0;
  let freeSpins = 0;

  if (bonusCount >= 3) {
    freeSpins = bonusCount === 3 ? 5 : bonusCount === 4 ? 10 : 15;
    bonusPrize = Number(betAmount) * (bonusCount === 3 ? 2 : bonusCount === 4 ? 5 : 10);
    totalPrize += bonusPrize;
  }

  return {
    totalPrize: Number(totalPrize.toFixed(2)),
    wins,
    bonus: {
      triggered: bonusCount >= 3,
      bonusCount,
      freeSpins,
      bonusPrize: Number(bonusPrize.toFixed(2))
    }
  };
}

function limitarPremioPorVolatilidad(prize, betAmount, volatility) {
  const bet = Number(betAmount);

  let maxMultiplier = 80;
  if (volatility === "low") maxMultiplier = 35;
  if (volatility === "medium") maxMultiplier = 80;
  if (volatility === "high") maxMultiplier = 150;

  const maxPrize = bet * maxMultiplier;
  return Math.min(Number(prize), maxPrize);
}

app.post("/api/superadmin/simulate", auth, soloSuperadmin, async (req, res) => {
  const spinsCount = Math.min(Number(req.body.spins || 1000), 100000);
  const betAmount = Number(req.body.bet_amount || 1000);
  const volatility = req.body.volatility || "medium";

  if (spinsCount < 1 || betAmount <= 0) {
    return res.status(400).json({ error: "Datos inválidos" });
  }

  const cfgQ = await pool.query("SELECT * FROM engine_config ORDER BY id DESC LIMIT 1");
  const cfg = cfgQ.rows[0];

  const symbolsQ = await pool.query("SELECT * FROM game_symbols WHERE is_active=true");
  const paytableQ = await pool.query("SELECT * FROM paytables WHERE is_active=true");

  const symbols = symbolsQ.rows;
  const paytable = paytableQ.rows;

  let totalBets = 0;
  let totalHouse = 0;
  let totalPlayable = 0;
  let totalPrizes = 0;
  let totalPool = 0;
  let bonusHits = 0;
  let winningSpins = 0;
  let biggestPrize = 0;

  const sample = [];

  for (let i = 0; i < spinsCount; i++) {
    const houseAmount = betAmount * Number(cfg.house_percentage) / 100;
    const playableAmount = betAmount - houseAmount;
    const poolAmount = playableAmount * Number(cfg.pool_percentage) / 100;

    const grid = generarGrilla(symbols);
    const evaluation = evaluarPremio(grid, paytable, betAmount);

    let prize = limitarPremioPorVolatilidad(
      evaluation.totalPrize,
      betAmount,
      volatility
    );

    totalBets += betAmount;
    totalHouse += houseAmount;
    totalPlayable += playableAmount;
    totalPool += poolAmount;
    totalPrizes += prize;

    if (prize > 0) winningSpins++;
    if (evaluation.bonus.triggered) bonusHits++;
    if (prize > biggestPrize) biggestPrize = prize;

    if (sample.length < 10) {
      sample.push({
        grid,
        prize: Number(prize.toFixed(2)),
        wins: evaluation.wins,
        bonus: evaluation.bonus
      });
    }
  }

  const theoreticalHouseLocked = totalHouse;
  const playableAfterPrize = totalPlayable - totalPrizes;
  const estimatedStageRemainder = playableAfterPrize > 0 ? playableAfterPrize : 0;
  const riskOverflow = playableAfterPrize < 0 ? Math.abs(playableAfterPrize) : 0;

  res.json({
    ok: true,
    mode: "simulation_only",
    config: {
      reels: 5,
      rows: 3,
      paylines: 20,
      volatility,
      house_percentage: Number(cfg.house_percentage),
      pool_percentage: Number(cfg.pool_percentage)
    },
    input: {
      spins: spinsCount,
      bet_amount: betAmount
    },
    totals: {
      total_bets: Number(totalBets.toFixed(2)),
      house_locked: Number(theoreticalHouseLocked.toFixed(2)),
      playable_fund: Number(totalPlayable.toFixed(2)),
      pool_assigned: Number(totalPool.toFixed(2)),
      prizes_paid: Number(totalPrizes.toFixed(2)),
      estimated_stage_remainder: Number(estimatedStageRemainder.toFixed(2)),
      risk_overflow: Number(riskOverflow.toFixed(2))
    },
    percentages: {
      real_house_percent_over_bets: Number((theoreticalHouseLocked / totalBets * 100).toFixed(2)),
      prize_percent_over_bets: Number((totalPrizes / totalBets * 100).toFixed(2)),
      prize_percent_over_playable: Number((totalPrizes / totalPlayable * 100).toFixed(2)),
      hit_rate_percent: Number((winningSpins / spinsCount * 100).toFixed(2)),
      bonus_rate_percent: Number((bonusHits / spinsCount * 100).toFixed(2))
    },
    highlights: {
      winning_spins: winningSpins,
      losing_spins: spinsCount - winningSpins,
      bonus_hits: bonusHits,
      biggest_prize: Number(biggestPrize.toFixed(2))
    },
    sample
  });
});



// ================= PASO 6: BILLETERA + MOTOR REAL =================

async function getConfig(client) {
  const q = await client.query("SELECT * FROM engine_config ORDER BY id DESC LIMIT 1");
  return q.rows[0];
}

async function getActiveStage(client) {
  let q = await client.query("SELECT * FROM pool_stages WHERE status='active' ORDER BY id DESC LIMIT 1");
  if (q.rowCount === 0) {
    await client.query("INSERT INTO pool_stages (ends_at) VALUES (NOW() + INTERVAL '30 days')");
    q = await client.query("SELECT * FROM pool_stages WHERE status='active' ORDER BY id DESC LIMIT 1");
  }
  return q.rows[0];
}

async function ensureFundTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS stage_funds (
      id SERIAL PRIMARY KEY,
      pool_stage_id INTEGER REFERENCES pool_stages(id),
      fund_type TEXT NOT NULL,
      current_amount NUMERIC(14,2) NOT NULL DEFAULT 0,
      total_in NUMERIC(14,2) NOT NULL DEFAULT 0,
      total_out NUMERIC(14,2) NOT NULL DEFAULT 0,
      UNIQUE(pool_stage_id, fund_type)
    );

    CREATE TABLE IF NOT EXISTS game_rounds (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      bet_amount NUMERIC(14,2) NOT NULL,
      house_amount NUMERIC(14,2) NOT NULL,
      playable_amount NUMERIC(14,2) NOT NULL,
      prize_amount NUMERIC(14,2) NOT NULL DEFAULT 0,
      prize_tier TEXT NOT NULL DEFAULT 'none',
      result_json JSONB NOT NULL,
      balance_before NUMERIC(14,2) NOT NULL,
      balance_after NUMERIC(14,2) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);
}

async function ensureStageFunds(client, stageId) {
  const types = ["small","medium","big","bonus","multiplier","pool"];
  for (const t of types) {
    await client.query(`
      INSERT INTO stage_funds (pool_stage_id, fund_type)
      VALUES ($1,$2)
      ON CONFLICT (pool_stage_id, fund_type) DO NOTHING
    `, [stageId, t]);
  }
}

async function addFund(client, stageId, fundType, amount) {
  await client.query(`
    UPDATE stage_funds
    SET current_amount=current_amount+$1, total_in=total_in+$1
    WHERE pool_stage_id=$2 AND fund_type=$3
  `, [amount, stageId, fundType]);
}

async function removeFund(client, stageId, fundType, amount) {
  await client.query(`
    UPDATE stage_funds
    SET current_amount=current_amount-$1, total_out=total_out+$1
    WHERE pool_stage_id=$2 AND fund_type=$3 AND current_amount >= $1
  `, [amount, stageId, fundType]);
}

async function getFunds(client, stageId) {
  const q = await client.query(`
    SELECT fund_type, current_amount, total_in, total_out
    FROM stage_funds
    WHERE pool_stage_id=$1
  `, [stageId]);

  const obj = {};
  for (const r of q.rows) obj[r.fund_type] = Number(r.current_amount);
  return obj;
}

function choosePrizeTier(funds, betAmount) {
  const bet = Number(betAmount);

  const options = [];

  if ((funds.small || 0) >= bet * 0.5) options.push({ tier:"small", max: Math.min(funds.small, bet * 5), weight: 60 });
  if ((funds.medium || 0) >= bet * 2) options.push({ tier:"medium", max: Math.min(funds.medium, bet * 20), weight: 25 });
  if ((funds.big || 0) >= bet * 10) options.push({ tier:"big", max: Math.min(funds.big, bet * 80), weight: 8 });
  if ((funds.bonus || 0) >= bet * 3) options.push({ tier:"bonus", max: Math.min(funds.bonus, bet * 15), weight: 7 });

  options.push({ tier:"none", max: 0, weight: 100 });

  return randomItemWeighted(options);
}

function generateResultForPrize(tier, prize, betAmount) {
  const symbolsByTier = {
    none: ["F","M","C","G","F","M","C"],
    small: ["F","M","C"],
    medium: ["G","C","T"],
    big: ["A","T"],
    bonus: ["B","B","B","F","M"]
  };

  const grid = generarGrilla([
    { code:"F", weight:25 },
    { code:"M", weight:20 },
    { code:"C", weight:15 },
    { code:"G", weight:10 },
    { code:"T", weight:5 },
    { code:"A", weight:3 },
    { code:"B", weight:4 },
    { code:"W", weight:2 }
  ]);

  if (tier !== "none") {
    const sym = symbolsByTier[tier][0];
    grid[1][0] = sym;
    grid[1][1] = sym;
    grid[1][2] = sym;
    if (tier === "medium" || tier === "big") grid[1][3] = sym;
    if (tier === "big") grid[1][4] = sym;
  }

  return {
    grid,
    prize,
    tier,
    message: prize > 0 ? "Ganaste $" + prize.toFixed(2) : "Sin premio",
    reels: 5,
    rows: 3,
    paylines: 20
  };
}

app.post("/api/superadmin/create-user", auth, soloSuperadmin, async (req, res) => {
  const { email, password, role } = req.body || {};
  if (!email || !password || !["admin","user"].includes(role)) {
    return res.status(400).json({ error: "Datos inválidos" });
  }

  const hash = await bcrypt.hash(password, 12);

  const q = await pool.query(`
    INSERT INTO users (email, password_hash, role, balance)
    VALUES ($1,$2,$3,0)
    RETURNING id,email,role,balance,is_active
  `, [email, hash, role]);

  await pool.query(
    "INSERT INTO audit_logs (actor_user_id, action, detail) VALUES ($1,$2,$3)",
    [req.user.id, "CREATE_USER", { email, role }]
  );

  res.json({ ok:true, user:q.rows[0] });
});

app.post("/api/superadmin/add-balance", auth, soloSuperadmin, async (req, res) => {
  const userId = Number(req.body.user_id);
  const amount = Number(req.body.amount);

  if (!userId || amount <= 0) {
    return res.status(400).json({ error: "Datos inválidos" });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const u = await client.query("SELECT * FROM users WHERE id=$1 FOR UPDATE", [userId]);
    if (u.rowCount === 0) throw new Error("Usuario no existe");

    const before = Number(u.rows[0].balance);
    const after = before + amount;

    await client.query("UPDATE users SET balance=$1 WHERE id=$2", [after, userId]);

    await client.query(`
      INSERT INTO wallet_movements (user_id,type,amount,balance_before,balance_after,note)
      VALUES ($1,'deposit',$2,$3,$4,'Carga manual superadmin')
    `, [userId, amount, before, after]);

    await client.query(
      "INSERT INTO audit_logs (actor_user_id, action, detail) VALUES ($1,$2,$3)",
      [req.user.id, "ADD_BALANCE", { user_id:userId, amount }]
    );

    await client.query("COMMIT");
    res.json({ ok:true, user_id:userId, balance:after });

  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).json({ error:e.message });
  } finally {
    client.release();
  }
});

app.get("/api/superadmin/funds", auth, soloSuperadmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const stage = await getActiveStage(client);
    await ensureStageFunds(client, stage.id);
    const funds = await client.query(`
      SELECT * FROM stage_funds
      WHERE pool_stage_id=$1
      ORDER BY fund_type
    `, [stage.id]);

    res.json({ ok:true, stage, funds:funds.rows });
  } finally {
    client.release();
  }
});

app.post("/api/play/spin", auth, async (req, res) => {
  const betPerLine = Number(req.body.bet_per_line || req.body.bet_amount || 0);
  const selectedLines = Math.max(1, Math.min(20, Number(req.body.lines || 20)));
  const betAmount = Number((betPerLine * selectedLines).toFixed(2));

  if (betPerLine <= 0 || betAmount <= 0) {
    return res.status(400).json({ error: "Apuesta inválida" });
  }

  const PAYLINES = [
    {id:1,name:"Línea 1 central",cells:[[1,0],[1,1],[1,2],[1,3],[1,4]],path:"M10 50 L30 50 L50 50 L70 50 L90 50"},
    {id:2,name:"Línea 2 superior",cells:[[0,0],[0,1],[0,2],[0,3],[0,4]],path:"M10 16 L30 16 L50 16 L70 16 L90 16"},
    {id:3,name:"Línea 3 inferior",cells:[[2,0],[2,1],[2,2],[2,3],[2,4]],path:"M10 84 L30 84 L50 84 L70 84 L90 84"},
    {id:4,name:"Línea 4 V",cells:[[0,0],[1,1],[2,2],[1,3],[0,4]],path:"M10 16 L30 50 L50 84 L70 50 L90 16"},
    {id:5,name:"Línea 5 A",cells:[[2,0],[1,1],[0,2],[1,3],[2,4]],path:"M10 84 L30 50 L50 16 L70 50 L90 84"},
    {id:6,name:"Línea 6",cells:[[0,0],[0,1],[1,2],[2,3],[2,4]],path:"M10 16 L30 16 L50 50 L70 84 L90 84"},
    {id:7,name:"Línea 7",cells:[[2,0],[2,1],[1,2],[0,3],[0,4]],path:"M10 84 L30 84 L50 50 L70 16 L90 16"},
    {id:8,name:"Línea 8",cells:[[1,0],[0,1],[0,2],[0,3],[1,4]],path:"M10 50 L30 16 L50 16 L70 16 L90 50"},
    {id:9,name:"Línea 9",cells:[[1,0],[2,1],[2,2],[2,3],[1,4]],path:"M10 50 L30 84 L50 84 L70 84 L90 50"},
    {id:10,name:"Línea 10",cells:[[0,0],[1,1],[1,2],[1,3],[0,4]],path:"M10 16 L30 50 L50 50 L70 50 L90 16"},
    {id:11,name:"Línea 11",cells:[[2,0],[1,1],[1,2],[1,3],[2,4]],path:"M10 84 L30 50 L50 50 L70 50 L90 84"},
    {id:12,name:"Línea 12",cells:[[1,0],[0,1],[1,2],[2,3],[1,4]],path:"M10 50 L30 16 L50 50 L70 84 L90 50"},
    {id:13,name:"Línea 13",cells:[[1,0],[2,1],[1,2],[0,3],[1,4]],path:"M10 50 L30 84 L50 50 L70 16 L90 50"},
    {id:14,name:"Línea 14",cells:[[0,0],[1,1],[0,2],[1,3],[0,4]],path:"M10 16 L30 50 L50 16 L70 50 L90 16"},
    {id:15,name:"Línea 15",cells:[[2,0],[1,1],[2,2],[1,3],[2,4]],path:"M10 84 L30 50 L50 84 L70 50 L90 84"},
    {id:16,name:"Línea 16",cells:[[0,0],[2,1],[0,2],[2,3],[0,4]],path:"M10 16 L30 84 L50 16 L70 84 L90 16"},
    {id:17,name:"Línea 17",cells:[[2,0],[0,1],[2,2],[0,3],[2,4]],path:"M10 84 L30 16 L50 84 L70 16 L90 84"},
    {id:18,name:"Línea 18",cells:[[1,0],[1,1],[0,2],[1,3],[1,4]],path:"M10 50 L30 50 L50 16 L70 50 L90 50"},
    {id:19,name:"Línea 19",cells:[[1,0],[1,1],[2,2],[1,3],[1,4]],path:"M10 50 L30 50 L50 84 L70 50 L90 50"},
    {id:20,name:"Línea 20",cells:[[0,0],[2,1],[2,2],[2,3],[0,4]],path:"M10 16 L30 84 L50 84 L70 84 L90 16"}
  ];

  const activePaylines = PAYLINES.slice(0, selectedLines);

  const PAY = {
    F:{name:"Pergamino",tier:"small",3:1.2,4:3,5:8},
    M:{name:"Jarrón",tier:"small",3:1.5,4:4,5:10},
    C:{name:"Escarabajo",tier:"medium",3:2,4:6,5:15},
    G:{name:"Ojo de Horus",tier:"medium",3:3,4:8,5:20},
    T:{name:"Anubis",tier:"big",3:4,4:10,5:30},
    A:{name:"Faraón",tier:"big",3:5,4:15,5:50}
  };

  const NORMALS = ["F","M","C","G","T","A","A","A"];
  function pick(a){return a[Math.floor(Math.random()*a.length)]}

  function losingGrid(){
    let g;
    for(let t=0;t<120;t++){
      g=[
        [pick(NORMALS),pick(NORMALS),pick(NORMALS),pick(NORMALS),pick(NORMALS)],
        [pick(NORMALS),pick(NORMALS),pick(NORMALS),pick(NORMALS),pick(NORMALS)],
        [pick(NORMALS),pick(NORMALS),pick(NORMALS),pick(NORMALS),pick(NORMALS)]
      ];
      if(!detectWins(g, betPerLine, activePaylines).length) return g;
    }
    return [["F","G","M","C","T"],["M","C","T","F","G"],["G","T","C","M","F"]];
  }

  function setLineWin(grid,line,symbol,count){
    for(let i=0;i<count;i++){
      const [r,c]=line.cells[i];
      grid[r][c]=symbol;
    }
    if(count<5){
      const [r,c]=line.cells[count];
      grid[r][c]=NORMALS.find(x=>x!==symbol);
    }
  }

  function detectWins(grid,lineBet,lines){
    const wins=[];
    for(const line of lines){
      const arr=line.cells.map(([r,c])=>grid[r][c]);
      let base=arr[0]==="W" ? (arr.find(x=>x!=="W")||"W") : arr[0];
      let count=0;
      const cells=[];
      for(let i=0;i<arr.length;i++){
        const s=arr[i];
        if(s===base || s==="W"){count++;cells.push(line.cells[i]);}
        else break;
      }
      if(count>=3 && PAY[base] && PAY[base][count]){
        const prize=Number((lineBet*PAY[base][count]).toFixed(2));
        wins.push({
          line_id:line.id,
          name:line.name,
          path:line.path,
          symbol:base,
          symbol_name:PAY[base].name,
          count,
          cells,
          multiplier:PAY[base][count],
          prize,
          tier:PAY[base].tier
        });
      }
    }
    return wins;
  }

  function possibleWins(funds){
    const list=[];
    for(const line of activePaylines){
      for(const symbol of NORMALS){
        for(const count of [3,4,5]){
          const p=PAY[symbol];
          const prize=Number((betPerLine*p[count]).toFixed(2));
          if(Number(funds[p.tier]||0)>=prize){
            list.push({
              line,symbol,count,prize,fund:p.tier,
              weight:p.tier==="small"?60:p.tier==="medium"?28:10
            });
          }
        }
      }
    }
    return list;
  }

  function weighted(items){
    const total=items.reduce((s,x)=>s+x.weight,0);
    let r=Math.random()*total;
    for(const i of items){r-=i.weight;if(r<=0)return i}
    return items[0];
  }

  const client=await pool.connect();

  try{
    await client.query("BEGIN");

    const userQ=await client.query("SELECT * FROM users WHERE id=$1 AND is_active=true FOR UPDATE",[req.user.id]);
    if(userQ.rowCount===0) throw new Error("Usuario no encontrado");

    const balanceBefore=Number(userQ.rows[0].balance);
    if(balanceBefore<betAmount) throw new Error("Saldo insuficiente");

    const cfg=await getConfig(client);
    if(cfg.maintenance_mode) throw new Error("Sistema en mantenimiento");

    const stage=await getActiveStage(client);
    await ensureStageFunds(client,stage.id);

    const houseAmount=Number((betAmount*Number(cfg.house_percentage)/100).toFixed(2));
    const playableAmount=Number((betAmount-houseAmount).toFixed(2));

    await addFund(client,stage.id,"small",Number((playableAmount*Number(cfg.small_prize_percentage)/100).toFixed(2)));
    await addFund(client,stage.id,"medium",Number((playableAmount*Number(cfg.medium_prize_percentage)/100).toFixed(2)));
    await addFund(client,stage.id,"big",Number((playableAmount*Number(cfg.big_prize_percentage)/100).toFixed(2)));
    await addFund(client,stage.id,"bonus",Number((playableAmount*Number(cfg.bonus_percentage)/100).toFixed(2)));
    await addFund(client,stage.id,"multiplier",Number((playableAmount*Number(cfg.multiplier_percentage)/100).toFixed(2)));
    await addFund(client,stage.id,"pool",Number((playableAmount*Number(cfg.pool_percentage)/100).toFixed(2)));

    await client.query("INSERT INTO house_ledger (source,amount,note) VALUES ('spin_house_percentage',$1,'Reserva fija de la casa')",[houseAmount]);

    const funds=await getFunds(client,stage.id);
    const candidates=possibleWins(funds);

    let grid=losingGrid();
    const shouldWin=candidates.length>0 && Math.random()<0.38;

    if(shouldWin){
      const s=weighted(candidates);
      grid=losingGrid();
      setLineWin(grid,s.line,s.symbol,s.count);
    }

    let wins=detectWins(grid,betPerLine,activePaylines);
    if(!shouldWin && wins.length){grid=losingGrid();wins=[];}

    const prizeAmount=Number(wins.reduce((s,w)=>s+Number(w.prize),0).toFixed(2));
    const prizeTier=wins.some(w=>w.tier==="big")?"big":wins.some(w=>w.tier==="medium")?"medium":wins.length?"small":"none";

    const byFund={};
    for(const w of wins){byFund[w.tier]=Number(((byFund[w.tier]||0)+w.prize).toFixed(2));}
    for(const [fund,amount] of Object.entries(byFund)){if(amount>0) await removeFund(client,stage.id,fund,amount);}

    const balanceAfterBet=Number((balanceBefore-betAmount).toFixed(2));
    const balanceAfter=Number((balanceAfterBet+prizeAmount).toFixed(2));

    const result={
      grid,
      prize:prizeAmount,
      tier:prizeTier,
      win_lines:wins,
      selected_lines:selectedLines,
      bet_per_line:betPerLine,
      total_bet:betAmount,
      message:prizeAmount>0?"Ganaste $"+prizeAmount.toFixed(2):"Sin premio",
      reels:5,rows:3,paylines:20
    };

    await client.query("UPDATE users SET balance=$1 WHERE id=$2",[balanceAfter,req.user.id]);

    await client.query("INSERT INTO wallet_movements (user_id,type,amount,balance_before,balance_after,note) VALUES ($1,'bet',$2,$3,$4,$5)",[req.user.id,betAmount,balanceBefore,balanceAfterBet,`Apuesta slot ${selectedLines} líneas`]);

    if(prizeAmount>0){
      await client.query("INSERT INTO wallet_movements (user_id,type,amount,balance_before,balance_after,note) VALUES ($1,'prize',$2,$3,$4,'Premio slot')",[req.user.id,prizeAmount,balanceAfterBet,balanceAfter]);
    }

    await client.query(`
      INSERT INTO game_rounds
      (user_id,bet_amount,house_amount,playable_amount,prize_amount,prize_tier,result_json,balance_before,balance_after)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
    `,[req.user.id,betAmount,houseAmount,playableAmount,prizeAmount,prizeTier,result,balanceBefore,balanceAfter]);

    await client.query(`
      INSERT INTO spins
      (user_id,bet_amount,house_amount,playable_amount,prize_amount,result_json,balance_before,balance_after)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
    `,[req.user.id,betAmount,houseAmount,playableAmount,prizeAmount,result,balanceBefore,balanceAfter]);

    await client.query("COMMIT");

    res.json({ok:true,bet_amount:betAmount,bet_per_line:betPerLine,selected_lines:selectedLines,prize_amount:prizeAmount,balance_before:balanceBefore,balance_after:balanceAfter,result});

  }catch(e){
    await client.query("ROLLBACK");
    res.status(400).json({error:e.message});
  }finally{
    client.release();
  }
});


app.get("/api/play/wallet", auth, async (req, res) => {
  const user = await pool.query(
    "SELECT id,email,role,balance FROM users WHERE id=$1",
    [req.user.id]
  );

  const mov = await pool.query(`
    SELECT type,amount,balance_before,balance_after,note,created_at
    FROM wallet_movements
    WHERE user_id=$1
    ORDER BY id DESC
    LIMIT 30
  `, [req.user.id]);

  res.json({ ok:true, user:user.rows[0], movements:mov.rows });
});

ensureFundTables().catch(err => console.error("Error creando tablas paso 6:", err));

// ================= FIN PASO 6 =================



// ================= PASO 7: CIERRE DE POZO + DASHBOARD =================

async function closeExpiredStages() {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const expired = await client.query(`
      SELECT *
      FROM pool_stages
      WHERE status='active' AND ends_at <= NOW()
      FOR UPDATE
    `);

    if (expired.rowCount === 0) {
      await client.query("COMMIT");
      return;
    }

    for (const stage of expired.rows) {
      await ensureStageFunds(client, stage.id);

      const fundsQ = await client.query(`
        SELECT fund_type, current_amount
        FROM stage_funds
        WHERE pool_stage_id=$1
      `, [stage.id]);

      let totalRemainder = 0;

      for (const f of fundsQ.rows) {
        totalRemainder += Number(f.current_amount);
      }

      if (totalRemainder > 0) {
        await client.query(`
          INSERT INTO house_ledger (source, amount, note)
          VALUES ('stage_remainder',$1,$2)
        `, [
          totalRemainder,
          'Remanente transferido a la casa por cierre de etapa #' + stage.id
        ]);
      }

      await client.query(`
        UPDATE pool_stages
        SET status='closed',
            returned_to_house=$1
        WHERE id=$2
      `, [totalRemainder, stage.id]);

      await client.query(`
        INSERT INTO audit_logs (actor_user_id, action, detail)
        VALUES (NULL, 'AUTO_CLOSE_POOL_STAGE', $1)
      `, [{
        stage_id: stage.id,
        returned_to_house: totalRemainder
      }]);
    }

    const cfg = await getConfig(client);
    const days = Number(cfg.pool_stage_days || 30);

    await client.query(`
      INSERT INTO pool_stages (starts_at, ends_at, opening_amount, current_amount, status)
      VALUES (NOW(), NOW() + ($1 || ' days')::interval, 0, 0, 'active')
    `, [days]);

    const newStage = await client.query(`
      SELECT id FROM pool_stages
      WHERE status='active'
      ORDER BY id DESC
      LIMIT 1
    `);

    await ensureStageFunds(client, newStage.rows[0].id);

    await client.query(`
      INSERT INTO audit_logs (actor_user_id, action, detail)
      VALUES (NULL, 'AUTO_CREATE_POOL_STAGE', $1)
    `, [{
      new_stage_id: newStage.rows[0].id,
      duration_days: days
    }]);

    await client.query("COMMIT");

  } catch (e) {
    await client.query("ROLLBACK");
    console.error("Error cerrando etapa:", e);
  } finally {
    client.release();
  }
}

setInterval(closeExpiredStages, 60 * 1000);
closeExpiredStages();

app.post("/api/superadmin/close-stage-now", auth, soloSuperadmin, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const stageQ = await client.query(`
      SELECT *
      FROM pool_stages
      WHERE status='active'
      ORDER BY id DESC
      LIMIT 1
      FOR UPDATE
    `);

    if (stageQ.rowCount === 0) {
      throw new Error("No hay etapa activa");
    }

    const stage = stageQ.rows[0];
    await ensureStageFunds(client, stage.id);

    const fundsQ = await client.query(`
      SELECT fund_type, current_amount
      FROM stage_funds
      WHERE pool_stage_id=$1
    `, [stage.id]);

    let totalRemainder = 0;

    for (const f of fundsQ.rows) {
      totalRemainder += Number(f.current_amount);
    }

    if (totalRemainder > 0) {
      await client.query(`
        INSERT INTO house_ledger (source, amount, note)
        VALUES ('manual_stage_close',$1,$2)
      `, [
        totalRemainder,
        'Cierre manual de etapa #' + stage.id
      ]);
    }

    await client.query(`
      UPDATE pool_stages
      SET status='closed',
          returned_to_house=$1
      WHERE id=$2
    `, [totalRemainder, stage.id]);

    const cfg = await getConfig(client);
    const days = Number(cfg.pool_stage_days || 30);

    const newStageQ = await client.query(`
      INSERT INTO pool_stages (starts_at, ends_at, opening_amount, current_amount, status)
      VALUES (NOW(), NOW() + ($1 || ' days')::interval, 0, 0, 'active')
      RETURNING *
    `, [days]);

    await ensureStageFunds(client, newStageQ.rows[0].id);

    await client.query(`
      INSERT INTO audit_logs (actor_user_id, action, detail)
      VALUES ($1, 'MANUAL_CLOSE_POOL_STAGE', $2)
    `, [
      req.user.id,
      {
        closed_stage_id: stage.id,
        returned_to_house: totalRemainder,
        new_stage_id: newStageQ.rows[0].id
      }
    ]);

    await client.query("COMMIT");

    res.json({
      ok: true,
      closed_stage_id: stage.id,
      returned_to_house: Number(totalRemainder.toFixed(2)),
      new_stage: newStageQ.rows[0]
    });

  } catch (e) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.get("/api/superadmin/dashboard", auth, soloSuperadmin, async (req, res) => {
  const client = await pool.connect();

  try {
    await closeExpiredStages();

    const cfg = await getConfig(client);
    const stage = await getActiveStage(client);
    await ensureStageFunds(client, stage.id);

    const fundsQ = await client.query(`
      SELECT fund_type, current_amount, total_in, total_out
      FROM stage_funds
      WHERE pool_stage_id=$1
      ORDER BY fund_type
    `, [stage.id]);

    const financialQ = await client.query(`
      SELECT
        COALESCE(SUM(bet_amount),0) AS total_bets,
        COALESCE(SUM(house_amount),0) AS house_locked,
        COALESCE(SUM(playable_amount),0) AS playable_total,
        COALESCE(SUM(prize_amount),0) AS prizes_paid,
        COUNT(*) AS total_spins
      FROM spins
    `);

    const houseQ = await client.query(`
      SELECT COALESCE(SUM(amount),0) AS total_house
      FROM house_ledger
    `);

    const usersQ = await client.query(`
      SELECT role, COUNT(*) AS total
      FROM users
      GROUP BY role
      ORDER BY role
    `);

    const recentQ = await client.query(`
      SELECT gr.id, u.email, gr.bet_amount, gr.prize_amount, gr.prize_tier, gr.created_at
      FROM game_rounds gr
      JOIN users u ON u.id = gr.user_id
      ORDER BY gr.id DESC
      LIMIT 20
    `);

    const stagesQ = await client.query(`
      SELECT id, starts_at, ends_at, returned_to_house, status, created_at
      FROM pool_stages
      ORDER BY id DESC
      LIMIT 10
    `);

    const f = financialQ.rows[0];
    const totalBets = Number(f.total_bets);
    const prizesPaid = Number(f.prizes_paid);
    const houseLocked = Number(f.house_locked);
    const realRtp = totalBets > 0 ? (prizesPaid / totalBets) * 100 : 0;
    const housePercentReal = totalBets > 0 ? (houseLocked / totalBets) * 100 : 0;

    let activeFundsTotal = 0;
    for (const fund of fundsQ.rows) {
      activeFundsTotal += Number(fund.current_amount);
    }

    res.json({
      ok: true,
      config: cfg,
      active_stage: stage,
      active_funds_total: Number(activeFundsTotal.toFixed(2)),
      funds: fundsQ.rows,
      financial: {
        total_bets: Number(totalBets.toFixed(2)),
        house_locked: Number(houseLocked.toFixed(2)),
        house_total_ledger: Number(Number(houseQ.rows[0].total_house).toFixed(2)),
        playable_total: Number(Number(f.playable_total).toFixed(2)),
        prizes_paid: Number(prizesPaid.toFixed(2)),
        total_spins: Number(f.total_spins),
        real_rtp_percent: Number(realRtp.toFixed(2)),
        house_percent_real: Number(housePercentReal.toFixed(2))
      },
      users: usersQ.rows,
      recent_rounds: recentQ.rows,
      recent_stages: stagesQ.rows
    });

  } catch (e) {
    res.status(400).json({ error: e.message });
  } finally {
    client.release();
  }
});

// ================= FIN PASO 7 =================



// ================= PASO 13: ADMIN USUARIOS FÁCIL =================

function soloAdminOSuper(req,res,next){
  if(!["superadmin","admin"].includes(req.user.role)){
    return res.status(403).json({error:"Acceso solo admin"});
  }
  next();
}

app.get("/api/admin/users", auth, soloAdminOSuper, async (req,res)=>{
  const q = await pool.query(`
    SELECT id,email,role,balance,is_active,created_at
    FROM users
    ORDER BY id DESC
    LIMIT 200
  `);
  res.json({ok:true, users:q.rows});
});

app.get("/api/admin/recent-rounds", auth, soloAdminOSuper, async (req,res)=>{
  const q = await pool.query(`
    SELECT gr.id,u.email,gr.bet_amount,gr.prize_amount,gr.prize_tier,gr.balance_before,gr.balance_after,gr.created_at
    FROM game_rounds gr
    JOIN users u ON u.id=gr.user_id
    ORDER BY gr.id DESC
    LIMIT 50
  `);
  res.json({ok:true, rounds:q.rows});
});

// ================= FIN PASO 13 =================



// ================= PASO 14: RETIROS =================

app.post("/api/play/request-withdrawal", auth, async (req,res)=>{
  const amount = Number(req.body.amount || 0);
  if(amount <= 0) return res.status(400).json({error:"Monto inválido"});

  const client = await pool.connect();

  try{
    await client.query("BEGIN");

    const u = await client.query("SELECT * FROM users WHERE id=$1 FOR UPDATE",[req.user.id]);
    if(u.rowCount === 0) throw new Error("Usuario no encontrado");

    const before = Number(u.rows[0].balance);
    if(before < amount) throw new Error("Saldo insuficiente");

    const after = Number((before - amount).toFixed(2));

    await client.query("UPDATE users SET balance=$1 WHERE id=$2",[after,req.user.id]);

    const w = await client.query(`
      INSERT INTO withdrawals (user_id, amount, status, note)
      VALUES ($1,$2,'pending','Solicitud de retiro del jugador')
      RETURNING *
    `,[req.user.id,amount]);

    await client.query(`
      INSERT INTO wallet_movements (user_id,type,amount,balance_before,balance_after,note)
      VALUES ($1,'withdrawal_pending',$2,$3,$4,'Saldo bloqueado por solicitud de retiro')
    `,[req.user.id,amount,before,after]);

    await client.query("COMMIT");
    res.json({ok:true, withdrawal:w.rows[0], balance_after:after});

  }catch(e){
    await client.query("ROLLBACK");
    res.status(400).json({error:e.message});
  }finally{
    client.release();
  }
});

app.get("/api/admin/withdrawals", auth, soloAdminOSuper, async (req,res)=>{
  const q = await pool.query(`
    SELECT w.*, u.email
    FROM withdrawals w
    JOIN users u ON u.id=w.user_id
    ORDER BY w.id DESC
    LIMIT 100
  `);
  res.json({ok:true, withdrawals:q.rows});
});

app.post("/api/admin/withdrawals/:id/approve", auth, soloAdminOSuper, async (req,res)=>{
  const id = Number(req.params.id);

  const q = await pool.query(`
    UPDATE withdrawals
    SET status='approved', reviewed_by=$1, reviewed_at=NOW(), note='Retiro aprobado'
    WHERE id=$2 AND status='pending'
    RETURNING *
  `,[req.user.id,id]);

  if(q.rowCount === 0) return res.status(400).json({error:"Retiro no encontrado o ya revisado"});

  await pool.query(`
    INSERT INTO audit_logs (actor_user_id, action, detail)
    VALUES ($1,'APPROVE_WITHDRAWAL',$2)
  `,[req.user.id,{withdrawal_id:id}]);

  res.json({ok:true, withdrawal:q.rows[0]});
});

app.post("/api/admin/withdrawals/:id/reject", auth, soloAdminOSuper, async (req,res)=>{
  const id = Number(req.params.id);
  const client = await pool.connect();

  try{
    await client.query("BEGIN");

    const w = await client.query(`
      SELECT * FROM withdrawals
      WHERE id=$1 AND status='pending'
      FOR UPDATE
    `,[id]);

    if(w.rowCount === 0) throw new Error("Retiro no encontrado o ya revisado");

    const withdrawal = w.rows[0];

    const u = await client.query("SELECT * FROM users WHERE id=$1 FOR UPDATE",[withdrawal.user_id]);
    const before = Number(u.rows[0].balance);
    const amount = Number(withdrawal.amount);
    const after = Number((before + amount).toFixed(2));

    await client.query("UPDATE users SET balance=$1 WHERE id=$2",[after,withdrawal.user_id]);

    await client.query(`
      UPDATE withdrawals
      SET status='rejected', reviewed_by=$1, reviewed_at=NOW(), note='Retiro rechazado y saldo devuelto'
      WHERE id=$2
    `,[req.user.id,id]);

    await client.query(`
      INSERT INTO wallet_movements (user_id,type,amount,balance_before,balance_after,note)
      VALUES ($1,'withdrawal_rejected',$2,$3,$4,'Retiro rechazado: saldo devuelto')
    `,[withdrawal.user_id,amount,before,after]);

    await client.query(`
      INSERT INTO audit_logs (actor_user_id, action, detail)
      VALUES ($1,'REJECT_WITHDRAWAL',$2)
    `,[req.user.id,{withdrawal_id:id, amount}]);

    await client.query("COMMIT");
    res.json({ok:true, withdrawal_id:id, balance_after:after});

  }catch(e){
    await client.query("ROLLBACK");
    res.status(400).json({error:e.message});
  }finally{
    client.release();
  }
});

// ================= FIN PASO 14 =================



// ================= PASO 36: SOLICITUDES DE CRÉDITO =================

async function ensureCreditRequestsTable(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS credit_requests (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      amount NUMERIC(14,2) NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      note TEXT,
      reviewed_by INTEGER REFERENCES users(id),
      reviewed_at TIMESTAMP,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);
}

ensureCreditRequestsTable().catch(e=>console.error("credit_requests error",e));

app.post("/api/play/request-credit", auth, async (req,res)=>{
  const amount = Number(req.body.amount || 0);
  if(amount <= 0) return res.status(400).json({error:"Monto inválido"});

  const q = await pool.query(`
    INSERT INTO credit_requests (user_id, amount, status, note)
    VALUES ($1,$2,'pending','Solicitud de crédito del jugador')
    RETURNING *
  `,[req.user.id,amount]);

  res.json({ok:true, request:q.rows[0]});
});

app.get("/api/play/my-requests", auth, async (req,res)=>{
  const credits = await pool.query(`
    SELECT id,amount,status,note,created_at,reviewed_at
    FROM credit_requests
    WHERE user_id=$1
    ORDER BY id DESC
    LIMIT 30
  `,[req.user.id]);

  const withdrawals = await pool.query(`
    SELECT id,amount,status,note,created_at,reviewed_at
    FROM withdrawals
    WHERE user_id=$1
    ORDER BY id DESC
    LIMIT 30
  `,[req.user.id]);

  res.json({ok:true, credits:credits.rows, withdrawals:withdrawals.rows});
});

app.get("/api/admin/credit-requests", auth, soloAdminOSuper, async (req,res)=>{
  const q = await pool.query(`
    SELECT cr.*, u.email
    FROM credit_requests cr
    JOIN users u ON u.id=cr.user_id
    ORDER BY cr.id DESC
    LIMIT 100
  `);
  res.json({ok:true, requests:q.rows});
});

app.post("/api/admin/credit-requests/:id/approve", auth, soloAdminOSuper, async (req,res)=>{
  const id = Number(req.params.id);
  const client = await pool.connect();

  try{
    await client.query("BEGIN");

    const rq = await client.query(`
      SELECT * FROM credit_requests
      WHERE id=$1 AND status='pending'
      FOR UPDATE
    `,[id]);

    if(rq.rowCount===0) throw new Error("Solicitud no encontrada o ya revisada");

    const request = rq.rows[0];

    const u = await client.query("SELECT * FROM users WHERE id=$1 FOR UPDATE",[request.user_id]);
    const before = Number(u.rows[0].balance);
    const amount = Number(request.amount);
    const after = Number((before + amount).toFixed(2));

    await client.query("UPDATE users SET balance=$1 WHERE id=$2",[after,request.user_id]);

    await client.query(`
      UPDATE credit_requests
      SET status='approved', reviewed_by=$1, reviewed_at=NOW(), note='Crédito aprobado'
      WHERE id=$2
    `,[req.user.id,id]);

    await client.query(`
      INSERT INTO wallet_movements (user_id,type,amount,balance_before,balance_after,note)
      VALUES ($1,'credit_approved',$2,$3,$4,'Crédito aprobado por admin')
    `,[request.user_id,amount,before,after]);

    await client.query(`
      INSERT INTO audit_logs (actor_user_id, action, detail)
      VALUES ($1,'APPROVE_CREDIT_REQUEST',$2)
    `,[req.user.id,{credit_request_id:id, amount}]);

    await client.query("COMMIT");

    res.json({ok:true, request_id:id, balance_after:after});

  }catch(e){
    await client.query("ROLLBACK");
    res.status(400).json({error:e.message});
  }finally{
    client.release();
  }
});

app.post("/api/admin/credit-requests/:id/reject", auth, soloAdminOSuper, async (req,res)=>{
  const id = Number(req.params.id);

  const q = await pool.query(`
    UPDATE credit_requests
    SET status='rejected', reviewed_by=$1, reviewed_at=NOW(), note='Crédito rechazado'
    WHERE id=$2 AND status='pending'
    RETURNING *
  `,[req.user.id,id]);

  if(q.rowCount===0) return res.status(400).json({error:"Solicitud no encontrada o ya revisada"});

  await pool.query(`
    INSERT INTO audit_logs (actor_user_id, action, detail)
    VALUES ($1,'REJECT_CREDIT_REQUEST',$2)
  `,[req.user.id,{credit_request_id:id}]);

  res.json({ok:true, request:q.rows[0]});
});

// ================= FIN PASO 36 =================



app.post("/api/play/activate-multiplier", auth, async (req,res)=>{
  await pool.query(
    "UPDATE users SET multiplier_ready=TRUE WHERE id=$1",
    [req.user.id]
  );
  res.json({ok:true});
});


// ================= PASO 56: BONUS COFRE - 10 TIROS GRATIS =================

app.post("/api/play/bonus-spin", auth, async (req,res)=>{
  const betPerLine = Math.max(1, Number(req.body.bet_per_line || 1));
  const selectedLines = Math.max(1, Math.min(20, Number(req.body.lines || 20)));

  const PAYLINES = [
    {id:1,name:"Línea central",cells:[[1,0],[1,1],[1,2],[1,3],[1,4]],path:"M10 50 L30 50 L50 50 L70 50 L90 50"},
    {id:2,name:"Línea superior",cells:[[0,0],[0,1],[0,2],[0,3],[0,4]],path:"M10 16 L30 16 L50 16 L70 16 L90 16"},
    {id:3,name:"Línea inferior",cells:[[2,0],[2,1],[2,2],[2,3],[2,4]],path:"M10 84 L30 84 L50 84 L70 84 L90 84"},
    {id:4,name:"Diagonal V",cells:[[0,0],[1,1],[2,2],[1,3],[0,4]],path:"M10 16 L30 50 L50 84 L70 50 L90 16"},
    {id:5,name:"Diagonal A",cells:[[2,0],[1,1],[0,2],[1,3],[2,4]],path:"M10 84 L30 50 L50 16 L70 50 L90 84"}
  ];

  const activeLines = PAYLINES.slice(0, Math.min(5, selectedLines));

  const PAY = {
    F:{tier:"bonus",3:1.2,4:3,5:8},
    M:{tier:"bonus",3:1.5,4:4,5:10},
    C:{tier:"bonus",3:2,4:6,5:15},
    G:{tier:"bonus",3:3,4:8,5:20},
    T:{tier:"bonus",3:4,4:10,5:30},
    A:{tier:"bonus",3:5,4:15,5:50}
  };

  const SYMBOLS=["F","M","C","G","T","A","C","F","M"];

  function pick(){return SYMBOLS[Math.floor(Math.random()*SYMBOLS.length)]}

  function grid(){
    return [
      [pick(),pick(),pick(),pick(),pick()],
      [pick(),pick(),pick(),pick(),pick()],
      [pick(),pick(),pick(),pick(),pick()]
    ];
  }

  function detectWins(g){
    const wins=[];
    for(const line of activeLines){
      const arr=line.cells.map(([r,c])=>g[r][c]);
      const base=arr[0];
      let count=0;
      const cells=[];
      for(let i=0;i<arr.length;i++){
        if(arr[i]===base){
          count++;
          cells.push(line.cells[i]);
        }else break;
      }
      if(count>=3 && PAY[base] && PAY[base][count]){
        const prize=Number((betPerLine*PAY[base][count]).toFixed(2));
        wins.push({line_id:line.id,name:line.name,path:line.path,symbol:base,count,cells,prize,tier:"bonus"});
      }
    }
    return wins;
  }

  const client = await pool.connect();

  try{
    await client.query("BEGIN");

    const userQ = await client.query("SELECT * FROM users WHERE id=$1 FOR UPDATE",[req.user.id]);
    if(userQ.rowCount===0) throw new Error("Usuario no encontrado");

    const before = Number(userQ.rows[0].balance);
    const stage = await getActiveStage(client);
    await ensureStageFunds(client,stage.id);
    const funds = await getFunds(client,stage.id);
    const availableBonus = Number(funds.bonus || 0);

    let g = grid();
    let wins = detectWins(g);
    let prize = Number(wins.reduce((a,w)=>a+Number(w.prize),0).toFixed(2));

    if(prize > availableBonus){
      prize = availableBonus;
      if(prize <= 0){
        wins = [];
        prize = 0;
      }
    }

    if(prize > 0){
      await removeFund(client,stage.id,"bonus",prize);
    }

    const after = Number((before + prize).toFixed(2));

    await client.query("UPDATE users SET balance=$1 WHERE id=$2",[after,req.user.id]);

    if(prize > 0){
      await client.query(`
        INSERT INTO wallet_movements (user_id,type,amount,balance_before,balance_after,note)
        VALUES ($1,'bonus_prize',$2,$3,$4,'Premio de bonus cofre')
      `,[req.user.id,prize,before,after]);
    }

    const result = {
      grid:g,
      prize,
      tier: prize>0 ? "bonus" : "none",
      win_lines:wins,
      message: prize>0 ? "Bonus ganó $" + prize.toFixed(2) : "Bonus sin premio",
      free_spin:true
    };

    await client.query(`
      INSERT INTO game_rounds
      (user_id,bet_amount,house_amount,playable_amount,prize_amount,prize_tier,result_json,balance_before,balance_after)
      VALUES ($1,0,0,0,$2,$3,$4,$5,$6)
    `,[req.user.id,prize,prize>0?"bonus":"none",result,before,after]);

    await client.query("COMMIT");

    res.json({ok:true, prize_amount:prize, balance_before:before, balance_after:after, result});

  }catch(e){
    await client.query("ROLLBACK");
    res.status(400).json({error:e.message});
  }finally{
    client.release();
  }
});

// ================= FIN PASO 56 =================


const PORT = Number(process.env.PORT || 3050);

initDB().then(() => {
  app.listen(PORT, "127.0.0.1", () => {
    console.log("Slot Engine Backend activo en puerto " + PORT);
  });
}).catch(err => {
  console.error("Error iniciando backend:", err);
  process.exit(1);
});
