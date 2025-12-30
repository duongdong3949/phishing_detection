import os
import asyncio
import time
import httpx
import pymongo
import hashlib
import joblib
import pandas as pd
import numpy as np
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from dotenv import load_dotenv

MODEL_PATH = "best_model_smote_tuned.pkl"
global_pipeline = None

CRAWLER_TIMEOUT = 60
POLLING_INTERVAL = 2

load_dotenv()

CRAWLER_SERVICES = [
    "https://distributed-crawler-southeastasia-duong3949.azurewebsites.net/extract",
    "https://distributed-crawler-centralindia-duong3949.azurewebsites.net/extract",
    "https://url-lexical-crawler-duong3949.azurewebsites.net/extract",
    "https://http-header-crawler-duong3949.azurewebsites.net/extract",
    "https://certificate-crawler-duong3949.azurewebsites.net/extract",
    "https://distributed-crawler-eastasia-duong3949.azurewebsites.net/extract",
    "https://whois-crawler-duong3949.azurewebsites.net/extract",
    "https://http-redirection-crawler-duong3949.azurewebsites.net/extract",
    "https://distributed-crawler-japaneast-duong3949.azurewebsites.net/extract",
    "http://4.193.239.97:8000/extract",
    "http://4.194.46.132:8000/extract"
]

MONGO_URI = os.getenv("MONGO_URI")

MONGO_CONFIGS = {
    "certificate": {"db_name": "certificate_db", "collection": "raw_certificate_data"},
    "http_header": {"db_name": "http_header_db", "collection": "raw_http_header_data"},
    "http_redirection": {"db_name": "http_redirection_db", "collection": "raw_redirection_data"},
    "network": {"db_name": "network_db", "collection": "raw_network_data"},
    "server_status": {"db_name": "server_status_db", "collection": "raw_server_status_data"},
    "url_lexical": {"db_name": "url_lexical_db", "collection": "raw_url_lexical_data"},
    "whois": {"db_name": "whois_db", "collection": "raw_whois_data"},
}

DISTRIBUTED_CONFIGS = [
    {"db_name": "distributed_db_1", "collection": "raw_distributed_data_1"},
    {"db_name": "distributed_db_2", "collection": "raw_distributed_data_2"},
    {"db_name": "distributed_db_3", "collection": "raw_distributed_data_3"},
    {"db_name": "distributed_db_4", "collection": "raw_distributed_data_4"},
]

STANDARD_SERVICES = ["certificate", "http_header", "http_redirection", "network", "url_lexical", "whois"]

FEATURE_COLUMNS = {
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
        "url_hash", "url", 
        "num_unique_a_record",
        "max_dns_a_ttl", 
        "num_unique_ns_record",
        "max_dns_ns_ttl", 
        "average_num_a_records_for_name_servers",
        "max_dns_nsa_ttl",
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

def helper_aggregate_distributed(results):
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
        
        "num_unique_a_record": len(all_A),
        "max_dns_a_ttl": max(dns_a_ttls) if dns_a_ttls else -1.0,
        
        "num_unique_ns_record": len(all_NS),
        "max_dns_ns_ttl": max(dns_ns_ttls) if dns_ns_ttls else -1.0,
        
        "average_num_a_records_for_name_servers": len(all_NS_A) / len(all_NS) if all_NS else -1.0,
        "max_dns_nsa_ttl": max(dns_nsa_ttls) if dns_nsa_ttls else -1.0,
        
        "exist_PTR_record": any(r.get("exist_PTR_record", False) for r in results),
        "reverse_dns_look_up_matching": max(reverse_dns) if reverse_dns else -1.0,
        "whether_AAAA_record_exist_for_domain": any(r.get("whether_AAAA_record_exist_for_domain", False) for r in results),
        "whether_AAAA_record_exist_for_name_servers": any(r.get("whether_AAAA_record_exist_for_name_servers", False) for r in results)
    }

def clean_and_normalize_data(service_name, item):
    processed_item = {}
    columns = FEATURE_COLUMNS.get(service_name, [])
    if not item: item = {}

    original_url = item.get("url", "")
    if original_url:
         processed_item['url_hash'] = hashlib.sha256(original_url.encode('utf-8')).hexdigest()
    else:
         processed_item['url_hash'] = "missing"

    for col in columns:
        if col == "url_hash": continue
        
        mongo_key = col
        if col == "num_unique_a_record": mongo_key = "num_unique_A_record"
        if col == "num_unique_ns_record": mongo_key = "num_unique_NS_record"
        if col == "average_num_a_records_for_name_servers": mongo_key = "average_num_A_records_for_name_servers"
        
        val = item.get(mongo_key)
        if val is None:
             val = item.get(col)
        
        if col == "url" and isinstance(val, str) and len(val) > 2048:
            val = val[:2048]

        INT32_MIN, INT32_MAX = -2147483648, 2147483647
        if service_name == "certificate" and col.startswith("diff_") and isinstance(val, (int, float)):
            if not (INT32_MIN <= val <= INT32_MAX): val = -1

        if val is None:
            if col == "url": val = "missing"
            elif col in ["registrar", "signature_algorithm", "cert_version", "server_os"]: val = "missing"
            elif col.startswith("port_"): val = "Close"
            elif col.endswith("_c"): val = "XX"
            elif any(c in col for c in ["count", "len_", "num_", "ttl", "diff_"]): val = -1
            elif "distance" in col or "rtt" in col or "rate" in col or "time" in col or "matching" in col or "age" in col: val = -1.0
            elif any(c in col for c in ["exist", "whether", "is_", "has_", "IP_address"]): val = False
            else: val = -1
        
        processed_item[col] = val
    return processed_item

def fetch_data_by_url(client, target_url):
    merged_data = {}
    
    for service in STANDARD_SERVICES:
        config = MONGO_CONFIGS[service]
        db = client[config["db_name"]]
        collection = db[config["collection"]]
        
        doc = collection.find_one({"url": target_url}, sort=[('_id', pymongo.DESCENDING)])
        clean_data = clean_and_normalize_data(service, doc)
        merged_data.update(clean_data)

    dist_results = []
    for config in DISTRIBUTED_CONFIGS:
        db = client[config["db_name"]]
        collection = db[config["collection"]]
        doc = collection.find_one({"url": target_url}, sort=[('_id', pymongo.DESCENDING)])
        if doc: dist_results.append(doc)
    
    if dist_results:
        aggregated_data = helper_aggregate_distributed(dist_results)
        if "url" not in aggregated_data: aggregated_data["url"] = target_url
        merged_data.update(clean_and_normalize_data("dns", aggregated_data))
        merged_data.update(clean_and_normalize_data("server_status", aggregated_data))
    else:
        merged_data.update(clean_and_normalize_data("dns", None))
        merged_data.update(clean_and_normalize_data("server_status", None))

    return merged_data

async def send_to_crawler(client: httpx.AsyncClient, service_url: str, payload: dict):
    try:
        response = await client.post(service_url, json=payload, timeout=60.0)
        return True
    except Exception:
        return False

@asynccontextmanager
async def lifespan(app: FastAPI):
    global global_pipeline
    if os.path.exists(MODEL_PATH):
        try:
            global_pipeline = joblib.load(MODEL_PATH)
            print("✅ Model loaded successfully.")
        except Exception as e:
            print(f"⚠️ Error loading model: {e}")
    else:
        print(f"⚠️ Model file '{MODEL_PATH}' not found!")
    yield

app = FastAPI(title="End-to-End URL Phishing Detector", lifespan=lifespan)

class UrlPayload(BaseModel):
    url: str

class PredictionResponse(BaseModel):
    url: str
    prediction: str
    probability: Optional[Dict[str, float]] = None
    status: str
    message: str

@app.post("/analyze", response_model=PredictionResponse)
async def analyze_url(payload: UrlPayload):
    target_url = payload.url
    if not target_url:
        raise HTTPException(status_code=400, detail="URL is required")

    if global_pipeline is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    print(f"🚀 Dispatching crawlers for: {target_url}")
    crawl_payload = {"urls": [target_url]}
    async with httpx.AsyncClient() as client:
        tasks = [send_to_crawler(client, s, crawl_payload) for s in CRAWLER_SERVICES]
        await asyncio.gather(*tasks)

    print(f"⏳ Waiting for data in MongoDB...")
    
    mongo_client = pymongo.MongoClient(MONGO_URI, tlsAllowInvalidCertificates=True)
    
    data_found = False
    start_time = time.time()
    
    try:
        while (time.time() - start_time) < CRAWLER_TIMEOUT:
            db = mongo_client[MONGO_CONFIGS["url_lexical"]["db_name"]]
            coll = db[MONGO_CONFIGS["url_lexical"]["collection"]]
            
            if coll.find_one({"url": target_url}):
                data_found = True
                print("✅ Data detected in MongoDB!")
                break
            
            await asyncio.sleep(POLLING_INTERVAL)
        
        if not data_found:
            print("⚠️ Timeout reached. Attempting prediction with partial/missing data.")

        full_sample_dict = fetch_data_by_url(mongo_client, target_url)
        
        if "url" not in full_sample_dict or full_sample_dict["url"] == "missing":
            full_sample_dict["url"] = target_url

        input_df = pd.DataFrame([full_sample_dict])
        
        prediction = global_pipeline.predict(input_df)[0]
        
        prob_dict = {}
        if hasattr(global_pipeline, "predict_proba"):
            probs = global_pipeline.predict_proba(input_df)[0]
            classes = global_pipeline.classes_
            prob_dict = {str(c): float(p) for c, p in zip(classes, probs)}

        return {
            "url": target_url,
            "prediction": str(prediction),
            "probability": prob_dict,
            "status": "success" if data_found else "partial_success",
            "message": "Prediction complete" if data_found else "Timeout waiting for complete data"
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        mongo_client.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)