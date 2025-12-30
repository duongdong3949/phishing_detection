import os
import pymongo
import hashlib
import psycopg2
from psycopg2.extras import execute_values
from concurrent.futures import ThreadPoolExecutor

# MongoDB configurations for all crawlers
MONGO_URI = 'mongodb+srv://dong075:Password%40666@zevuqxrbyni.global.mongocluster.cosmos.azure.com/?tls=true&authMechanism=SCRAM-SHA-256&retrywrites=false&maxIdleTimeMS=120000&serverSelectionTimeoutMS=60000&connectTimeoutMS=60000&socketTimeoutMS=60000'
MONGO_CONFIGS = {
    "certificate": {
        "db_name": "certificate_db",
        "collection": "raw_certificate_data"
    },
    "http_header": {
        "db_name": "http_header_db",
        "collection": "raw_http_header_data"
    },
    "http_redirection": {
        "db_name": "http_redirection_db",
        "collection": "raw_redirection_data"
    },
    "network": {
        "db_name": "network_db",
        "collection": "raw_network_data"
    },
    "server_status": {
        "db_name": "server_status_db",
        "collection": "raw_server_status_data"
    },
    "url_lexical": {
        "db_name": "url_lexical_db",
        "collection": "raw_url_lexical_data"
    },
    "whois": {
        "db_name": "whois_db",
        "collection": "raw_whois_data"
    },
}

# Distributed MongoDB configs (4 locations)
DISTRIBUTED_CONFIGS = [
    {
        "db_name": "distributed_db_1",
        "collection": "raw_distributed_data_1"
    },
    {
        "db_name": "distributed_db_2",
        "collection": "raw_distributed_data_2"
    },
    {
        "db_name": "distributed_db_3",
        "collection": "raw_distributed_data_3"
    },
    {
        "db_name": "distributed_db_4",
        "collection": "raw_distributed_data_4"
    },
]

# PostgreSQL configurations
PG_CONFIGS = {
    "certificate": "postgresql://postgres:postgres@certificate_postgres:5432/certificate_db",
    "dns": "postgresql://postgres:postgres@dns_postgres:5432/dns_db",
    "http_header": "postgresql://postgres:postgres@http_header_postgres:5432/http_header_db",
    "http_redirection": "postgresql://postgres:postgres@http_redirection_postgres:5432/http_redirection_db",
    "network": "postgresql://postgres:postgres@network_postgres:5432/network_db",
    "server_status": "postgresql://postgres:postgres@server_status_postgres:5432/server_status_db",
    "url_lexical": "postgresql://postgres:postgres@url_lexical_postgres:5432/url_lexical_db",
    "whois": "postgresql://postgres:postgres@whois_postgres:5432/whois_db",
}

# PostgreSQL column definitions for each service
PG_COLUMNS = {
    "certificate": [
        "url_hash", "url", "extension_count", "authority_info_access", "authority_key_identifier",
        "subject_key_identifier", "basic_constraints", "certificate_policies", "extended_key_usage",
        "CRL_distribution_points", "freshest_CRL", "key_usage", "issuer_alt_name",
        "subject_alt_name", "subject_directory_attributes", "is_trusted_issuer", "is_prohibited_issuer",
        "is_prohibited_subject", "match_issuer_o_cn", "match_issuer_o_ou", "match_subject_o_cn",
        "match_subject_o_ou", "match_issuer_subject_cn", "match_website_issuer_cn", "match_website_altname",
        "match_website_subject_cn", "len_issuer_st", "len_issuer_city", "len_issuer_cn",
        "len_issuer_o", "len_issuer_ou", "len_issuer_email", "len_subject_st",
        "len_subject_city", "len_subject_cn", "len_subject_o", "len_subject_ou",
        "len_subject_email", "cert_issuer_c", "cert_subject_c", "diff_notbefore_timestamp",
        "diff_notafter_timestamp", "diff_notbefore_notafter", "has_expired", "len_serialnum",
        "signature_algorithm", "cert_version", "cert_count", "has_certificate"
    ],
    "dns": [
        "url_hash", "url", "num_unique_A_record", "max_dns_a_ttl", "num_unique_NS_record",
        "max_dns_ns_ttl", "average_num_A_records_for_name_servers", "max_dns_nsa_ttl",
        "exist_PTR_record", "reverse_dns_look_up_matching", "whether_AAAA_record_exist_for_domain",
        "whether_AAAA_record_exist_for_name_servers"
    ],
    "http_header": [
        "url_hash", "url", "http_header_count", "exist_cache_control", "len_header_server"
    ],
    "http_redirection": [
        "url_hash", "url", "len_redirection_chain", "different_domains_crossed"
    ],
    "network": [
        "url_hash", "url", "ttl", "advertised_window_size", "handshake_time", "variance_rtt",
        "fins_local", "fins_remote", "max_idle_time", "variance_packet_arrival_time",
        "packets_received_to_packets_sent", "rsts_local", "rsts_remote",
        "retransmission_local", "retransmission_remote", "packet_counts", "packet_rate"
    ],
    "server_status": [
        "url_hash", "url", "port_21", "port_22", "port_25", "port_53", "port_67", "port_68", "port_69",
        "port_80", "port_110", "port_111", "port_123", "port_135", "port_136", "port_137",
        "port_138", "port_139", "port_143", "port_161", "port_162", "port_443", "port_445",
        "port_514", "port_518", "port_520", "port_593", "port_631", "port_993", "port_995",
        "port_999", "port_1025", "port_1026", "port_1433", "port_1434", "port_1645", "port_1646",
        "port_1723", "port_1812", "port_1900", "port_2049", "port_2222", "port_3283", "port_3389",
        "port_3456", "port_4500", "port_5060", "port_5353", "port_5900", "port_8080", "port_20031",
        "port_32768", "open_ports_count", "server_os", "average_geo_distance", "average_rtt",
        "average_hop_distance", "target_location_count"
    ],
    "url_lexical": [
        "url_hash", "url", "IP_address_in_domain", "len_domain", "num_of_dot", "num_of_dash"
    ],
    "whois": [
        "url_hash", "url", "domain_age", "diff_exipry_time", "diff_update_time", "registrar", "is_entry_locked"
    ],
}

STANDARD_SERVICES = ["certificate", "http_header", "http_redirection", "network", "server_status", "url_lexical", "whois"]

def helper(results):
    if not results: return {}

    def get_vals(key, default=-1.0):
        return [r.get(key, default) for r in results if r.get(key, default) != default]

    geo_dist = get_vals("geo_distance")
    hop_dist = get_vals("hop_distance")
    rtt = get_vals("rtt")
    
    all_A = set()
    all_NS = set()
    all_NS_A = set()
    for r in results:
        all_A.update(r.get("A_records", []))
        all_NS.update(r.get("NS_records", []))
        all_NS_A.update(r.get("NS_A_records", []))
        
    dns_a_ttls = get_vals("dns_a_ttl", -1.0)
    dns_ns_ttls = get_vals("dns_ns_ttl", -1)
    dns_nsa_ttls = get_vals("dns_nsa_ttl", -1.0)
    reverse_dns = get_vals("reverse_dns_look_up_matching", -1.0)

    return {
        "target_location_count": len(set([c for r in results for c in r.get("city_names", [])])),
        "average_geo_distance": sum(geo_dist) / len(geo_dist) if geo_dist else -1.0,
        "average_hop_distance": sum(hop_dist) / len(hop_dist) if hop_dist else -1.0,
        "average_rtt": sum(rtt) / len(rtt) if rtt else -1.0,
        "cert_count": len(set([r.get("der_cert") for r in results if r.get("der_cert") != "missing"])),
        "num_unique_A_record": len(all_A),
        "max_dns_a_ttl": max(dns_a_ttls) if dns_a_ttls else -1.0,
        "num_unique_NS_record": len(all_NS),
        "max_dns_ns_ttl": max(dns_ns_ttls) if dns_ns_ttls else -1.0,
        "average_num_A_records_for_name_servers": len(all_NS_A) / len(all_NS) if all_NS else -1.0,
        "max_dns_nsa_ttl": max(dns_nsa_ttls) if dns_nsa_ttls else -1.0,
        "exist_PTR_record": any(r.get("exist_PTR_record", False) for r in results),
        "reverse_dns_look_up_matching": max(reverse_dns) if reverse_dns else -1.0,
        "whether_AAAA_record_exist_for_domain": any(r.get("whether_AAAA_record_exist_for_domain", False) for r in results),
        "whether_AAAA_record_exist_for_name_servers": any(r.get("whether_AAAA_record_exist_for_name_servers", False) for r in results)
    }

def fetch_data_from_mongo_batch(mongo_client, db_name, collection_name, batch_size=1000):
    """Fetch data from MongoDB in batches using a shared client."""
    try:
        db = mongo_client[db_name]
        collection = db[collection_name]
        cursor = collection.find({}, {"_id": 0}).batch_size(batch_size)
        batch = []
        for doc in cursor:
            batch.append(doc)
            if len(batch) >= batch_size:
                yield batch
                batch = []
        if batch:
            yield batch
    except Exception as e:
        print(f"Error fetching from {db_name}.{collection_name}: {e}")
        return

def insert_to_postgres_batch(service_name, data_iter, dist_data_iter=None):
    """Insert processed data to PostgreSQL in batches"""
    pg_uri = PG_CONFIGS.get(service_name)
    columns = PG_COLUMNS.get(service_name)
    if not pg_uri or not columns:
        print(f"No PostgreSQL config for {service_name}")
        return
    try:
        conn = psycopg2.connect(pg_uri)
        cur = conn.cursor()
        # Determine which iterator to use
        source_iter = dist_data_iter if service_name == "dns" else data_iter
        for batch in source_iter:
            rows = []
            for item in batch:
                original_url = item.get("url")
                if not original_url:
                    print(f"Warning: Skipping a record in {service_name} due to missing URL.")
                    continue  # Skip records without a URL entirely

                # Calculate hash from the original, full URL
                item['url_hash'] = hashlib.sha256(original_url.encode('utf-8')).hexdigest()

                row = []
                for col in columns:
                    val = item.get(col)

                    # Truncate long URLs to prevent PostgreSQL index size error
                    # This now only affects the 'url' column, which is for display/reference.
                    if col == "url" and isinstance(val, str) and len(val) > 2048:
                        print(f"Warning: Truncating long URL (len: {len(val)}) for service {service_name}: {val[:100]}...")
                        val = val[:2048]

                    # Handle potential integer overflow for timestamp differences in 'certificate'
                    INT32_MIN, INT32_MAX = -2147483648, 2147483647
                    if service_name == "certificate" and col.startswith("diff_") and isinstance(val, (int, float)):
                        if not (INT32_MIN <= val <= INT32_MAX):
                            print(f"Warning: Capping out-of-range integer for {col} (value: {val})")
                            val = -1

                    # Handle default values
                    if val is None:
                        if col == "url_hash" or col == "url":
                            val = "missing" # Should not happen due to check above, but as a safeguard
                        elif col in ["registrar", "signature_algorithm", "cert_version", "server_os"]:
                            val = "missing"
                        elif col.startswith("port_"):
                            val = "Close"
                        elif col.endswith("_c"):  # cert_issuer_c, cert_subject_c
                            val = "XX"
                        elif isinstance(columns, list) and any(c in col for c in ["count", "len_", "num_", "ttl", "diff_"]):
                            val = -1
                        elif "distance" in col or "rtt" in col or "rate" in col or "time" in col or "matching" in col or "age" in col:
                            val = -1.0
                        elif any(c in col for c in ["exist", "whether", "is_", "has_", "IP_address"]):
                            val = False
                        else:
                            val = -1
                    row.append(val)
                rows.append(tuple(row))
            if rows:
                cols_str = ", ".join(columns)
                placeholders = ", ".join(["%s"] * len(columns))
                update_cols = ", ".join([f"{col} = EXCLUDED.{col}" for col in columns if col != "url_hash"])
                query = f"""
                    INSERT INTO results ({cols_str})
                    VALUES %s
                    ON CONFLICT (url_hash) DO UPDATE SET {update_cols}
                """
                execute_values(cur, query, rows, template=f"({placeholders})")
                conn.commit()
                print(f"Inserted {len(rows)} records to PostgreSQL {service_name}")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error inserting to PostgreSQL {service_name}: {e}")


def main():
    print("Starting ETL Pipeline (batch mode)...")
    batch_size = 1000

    # Initialize a single MongoDB client
    client = pymongo.MongoClient(MONGO_URI)
    print("MongoDB connection established.")

    try:
        # Fetch and insert standard services in batches
        for service in STANDARD_SERVICES:
            print(f"Processing service: {service}")
            config = MONGO_CONFIGS[service]
            data_iter = fetch_data_from_mongo_batch(
                client, config["db_name"], config["collection"], batch_size
            )
            insert_to_postgres_batch(service, data_iter)

        # Fetch and process distributed data in batches
        print("Processing distributed services (DNS, server_status)...")
        # For distributed, we need to aggregate by URL after each batch
        dist_iters = [
            fetch_data_from_mongo_batch(
                client, config["db_name"], config["collection"], batch_size
            )
            for config in DISTRIBUTED_CONFIGS
        ]
        # Merge batches from all distributed sources
        from itertools import chain
        def dist_batch_iter():
            for batches in zip(*dist_iters):
                merged = list(chain.from_iterable(batches))
                # Aggregate by URL
                dist_by_url = {}
                for item in merged:
                    url = item.get("url")
                    if url:
                        if url not in dist_by_url:
                            dist_by_url[url] = []
                        dist_by_url[url].append(item)
                # Prepare DNS batch
                dns_batch = []
                for url, items in dist_by_url.items():
                    aggregated = helper(items)
                    aggregated["url"] = url
                    dns_batch.append(aggregated)
                yield dns_batch
        # Insert DNS batches
        insert_to_postgres_batch("dns", None, dist_batch_iter())

        print("\nETL Pipeline (batch mode) completed!")
    finally:
        client.close()
        print("MongoDB connection closed.")

if __name__ == "__main__":
    main()
