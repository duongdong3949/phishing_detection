CREATE TABLE IF NOT EXISTS results (
  url_hash VARCHAR(64) PRIMARY KEY,
  url TEXT NOT NULL,
  len_redirection_chain INT NOT NULL,
  different_domains_crossed INT NOT NULL
);


