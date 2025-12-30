CREATE TABLE IF NOT EXISTS results (
  url_hash VARCHAR(64) PRIMARY KEY,
  url TEXT NOT NULL,
  domain_age FLOAT NOT NULL,
  diff_exipry_time FLOAT NOT NULL,
  diff_update_time FLOAT NOT NULL,
  registrar VARCHAR(255) NOT NULL,
  is_entry_locked BOOLEAN NOT NULL
);


