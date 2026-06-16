CREATE TABLE IF NOT EXISTS deposits (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  amount NUMERIC(14,2) NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  note TEXT,
  created_by INTEGER REFERENCES users(id),
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  approved_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS withdrawals (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  amount NUMERIC(14,2) NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  note TEXT,
  reviewed_by INTEGER REFERENCES users(id),
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  reviewed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS house_ledger (
  id SERIAL PRIMARY KEY,
  source TEXT NOT NULL,
  amount NUMERIC(14,2) NOT NULL,
  note TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS pool_ledger (
  id SERIAL PRIMARY KEY,
  pool_stage_id INTEGER REFERENCES pool_stages(id),
  source TEXT NOT NULL,
  amount NUMERIC(14,2) NOT NULL,
  note TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS game_symbols (
  id SERIAL PRIMARY KEY,
  code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  symbol_type TEXT NOT NULL DEFAULT 'normal',
  weight INTEGER NOT NULL DEFAULT 10,
  is_active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS paytables (
  id SERIAL PRIMARY KEY,
  symbol_code TEXT NOT NULL,
  match_count INTEGER NOT NULL,
  multiplier NUMERIC(10,2) NOT NULL,
  prize_tier TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS system_events (
  id SERIAL PRIMARY KEY,
  level TEXT NOT NULL DEFAULT 'info',
  message TEXT NOT NULL,
  detail JSONB,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

INSERT INTO game_symbols (code, name, symbol_type, weight)
VALUES
('A', 'Anaconda', 'premium', 3),
('T', 'Templo', 'high', 5),
('G', 'Gema', 'medium', 8),
('C', 'Corona', 'medium', 10),
('M', 'Moneda', 'low', 18),
('F', 'Fruta', 'low', 25),
('B', 'Bonus', 'bonus', 4),
('W', 'Wild', 'wild', 2)
ON CONFLICT (code) DO NOTHING;

INSERT INTO paytables (symbol_code, match_count, multiplier, prize_tier)
VALUES
('A', 5, 50, 'big'),
('A', 4, 15, 'medium'),
('A', 3, 5, 'small'),
('T', 5, 30, 'big'),
('T', 4, 10, 'medium'),
('T', 3, 4, 'small'),
('G', 5, 20, 'medium'),
('G', 4, 8, 'small'),
('G', 3, 3, 'small'),
('C', 5, 15, 'medium'),
('C', 4, 6, 'small'),
('C', 3, 2, 'small'),
('M', 5, 10, 'small'),
('M', 4, 4, 'small'),
('M', 3, 1.5, 'small'),
('F', 5, 8, 'small'),
('F', 4, 3, 'small'),
('F', 3, 1.2, 'small')
ON CONFLICT DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_spins_user_created ON spins(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_wallet_user_created ON wallet_movements(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_deposits_status ON deposits(status);
CREATE INDEX IF NOT EXISTS idx_withdrawals_status ON withdrawals(status);
