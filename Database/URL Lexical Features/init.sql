CREATE TABLE IF NOT EXISTS results (
  url_hash VARCHAR(64) PRIMARY KEY,
  url TEXT NOT NULL,
  IP_address_in_domain BOOLEAN NOT NULL,
  len_domain INT NOT NULL,
  num_of_dot INT NOT NULL,
  num_of_dash INT NOT NULL
);


