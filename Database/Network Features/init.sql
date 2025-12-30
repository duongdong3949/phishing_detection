CREATE TABLE IF NOT EXISTS results (
  url_hash VARCHAR(64) PRIMARY KEY,
  url TEXT NOT NULL,
  ttl INT NOT NULL,
  advertised_window_size INT NOT NULL,
  handshake_time FLOAT NOT NULL,
  variance_rtt FLOAT NOT NULL,
  fins_local INT NOT NULL,
  fins_remote INT NOT NULL,
  max_idle_time FLOAT NOT NULL,
  variance_packet_arrival_time FLOAT NOT NULL,
  packets_received_to_packets_sent FLOAT NOT NULL,
  rsts_local INT NOT NULL,
  rsts_remote INT NOT NULL,
  retransmission_local INT NOT NULL,
  retransmission_remote INT NOT NULL,
  packet_counts INT NOT NULL,
  packet_rate FLOAT NOT NULL
);


