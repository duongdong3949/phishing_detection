CREATE TABLE IF NOT EXISTS results (
  url_hash VARCHAR(64) PRIMARY KEY,
  url TEXT NOT NULL,
  http_header_count INT NOT NULL,
  exist_cache_control BOOLEAN NOT NULL,
  len_header_server INT NOT NULL
);


