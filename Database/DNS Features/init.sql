CREATE TABLE IF NOT EXISTS results (
  url_hash VARCHAR(64) PRIMARY KEY,
  url TEXT NOT NULL,
  num_unique_A_record INT NOT NULL,
  max_dns_a_ttl FLOAT NOT NULL,
  num_unique_NS_record INT NOT NULL,
  max_dns_ns_ttl FLOAT NOT NULL,
  average_num_A_records_for_name_servers FLOAT NOT NULL,
  max_dns_nsa_ttl FLOAT NOT NULL,
  exist_PTR_record BOOLEAN NOT NULL,
  reverse_dns_look_up_matching FLOAT NOT NULL,
  whether_AAAA_record_exist_for_domain BOOLEAN NOT NULL,
  whether_AAAA_record_exist_for_name_servers BOOLEAN NOT NULL
);


