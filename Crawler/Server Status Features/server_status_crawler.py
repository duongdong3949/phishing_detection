from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import List, Optional
import asyncio
import aiodns
import socket
import json
import nmap
import masscan
import os
from urllib.parse import urlparse
from motor.motor_asyncio import AsyncIOMotorClient
from contextlib import asynccontextmanager
from pymongo import UpdateOne
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")
COLLECTION_NAME = os.getenv("COLLECTION_NAME")

TOP_50_PORTS = [
    21, 22, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 136, 137, 138, 139, 143, 
    161, 162, 443, 445, 514, 518, 520, 593, 631, 993, 995, 999, 1025, 1026, 1433, 
    1434, 1645, 1646, 1723, 1812, 1900, 2049, 2222, 3283, 3389, 3456, 4500, 5060, 
    5353, 5900, 8080, 20031, 32768
]
PORTS_STR = ",".join(str(p) for p in TOP_50_PORTS)

MONGO_CLIENT: Optional[AsyncIOMotorClient] = None
DB_COLLECTION = None
DNS_RESOLVER: Optional[aiodns.DNSResolver] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global MONGO_CLIENT, DB_COLLECTION, DNS_RESOLVER
    MONGO_CLIENT = AsyncIOMotorClient(MONGO_URI)
    db = MONGO_CLIENT[DB_NAME]
    DB_COLLECTION = db[COLLECTION_NAME]
    DNS_RESOLVER = aiodns.DNSResolver(
        nameservers=['8.8.8.8', '8.8.4.4', '1.1.1.1'],
        timeout=2
    )

    try:
        await DB_COLLECTION.create_index("url", unique=True)
    except Exception as e:
        print(f"[WARNING] Could not create index: {e}")

    yield
    MONGO_CLIENT.close()

async def resolve_ip(url):
    try: 
        domain = urlparse(url).hostname
        if not domain: return None
        answer = await DNS_RESOLVER.query(domain, 'A')
        return answer[0].host
    except Exception as e:
        print(f"[ERROR] DNS resolution failed for {url}: {e}")
        return None

def fetch_raw_data(ip_list, url_list):
    data_map = {}
    final_results = []
    for ip, url in zip(ip_list, url_list):
        base_row = {f"port_{p}": 'Close' for p in TOP_50_PORTS}
        base_row.update({
            "server_os": "Missing",
            "open_ports_count": -1,
            "url": url
        })
        if not ip:
            final_results.append(base_row)
            continue
        data_map[ip] = base_row

    if not any(k for k in data_map):
        return final_results
    try :
        mas = masscan.PortScanner()
        mas.scan(
            " ".join([ip for ip in ip_list if ip]),
            ports=PORTS_STR,
            arguments="--rate 5000"
        )
        if isinstance(mas.scan_result, str):
            scan_data = json.loads(mas.scan_result)
        else:
            scan_data = mas.scan_result
        active_ips = []
        print(scan_data)
        for ip, res in scan_data.get("scan", {}).items():
            if ip in data_map:
                open_p = [item.get("port") for item in res if item.get("status") == "open"]
                if open_p:
                    data_map[ip]["open_ports_count"] = len(open_p)
                    for p in open_p: data_map[ip][f"port_{p}"] = "Open"
                    active_ips.append(ip)
        # if active_ips:
        #     nm = nmap.PortScanner()
        #     nm.scan(
        #         " ".join(active_ips),
        #         PORTS_STR,
        #         arguments="-O"
        #     )
        #     for ip in active_ips:
        #         if ip in nm.all_hosts() and "osmatch" in nm[ip] and nm[ip]["osmatch"]:
        #             data_map[ip]["server_os"] = nm[ip]["osmatch"][0]["name"]
    except Exception as e:
        print(f"[ERROR] {e}")
        pass
    if data_map:
        final_results.extend(data_map.values())
    return final_results

async def crawl_and_store_raw(url_list, batch_size=200):
    total_inserted = 0
    for i in range(0, len(url_list), batch_size):
        batch_urls = url_list[i:i+batch_size]
        ip_tasks = [resolve_ip(url) for url in batch_urls]
        ip_list = await asyncio.gather(*ip_tasks)
        
        loop = asyncio.get_running_loop()
        scan_results = await loop.run_in_executor(None, fetch_raw_data, ip_list, batch_urls)
        
        if scan_results:
            ops = [UpdateOne({"url": r["url"]}, {"$set": r}, upsert=True) for r in scan_results]
            await DB_COLLECTION.bulk_write(ops)
            total_inserted += len(scan_results)
            print(f"Processed {total_inserted} URLs")
    
    return total_inserted

class UrlListPayload(BaseModel):
    urls: List[str]

app = FastAPI(title="Raw Server Status Crawler", lifespan=lifespan)

@app.post("/extract")
async def extract(payload: UrlListPayload, background_tasks: BackgroundTasks):
    url_strings = [str(url) for url in payload.urls]
    existing = await DB_COLLECTION.find({"url": {"$in": url_strings}}, {"url": 1}).to_list(None)
    existing_urls = {doc["url"] for doc in existing}
    to_crawl = [u for u in url_strings if u not in existing_urls]
    if to_crawl:
        background_tasks.add_task(crawl_and_store_raw, to_crawl)
    return {"message": "Crawling started", "urls_received": len(url_strings), "urls_scheduled": len(to_crawl), "urls_skipped": len(existing_urls), "status": "processing"}