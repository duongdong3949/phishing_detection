from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional
import ipaddress
from urllib.parse import urlparse
from motor.motor_asyncio import AsyncIOMotorClient
from contextlib import asynccontextmanager
import pandas as pd
from pymongo import UpdateOne
import os

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")
COLLECTION_NAME = os.getenv("COLLECTION_NAME")

MONGO_CLIENT: Optional[AsyncIOMotorClient] = None
DB_COLLECTION = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global MONGO_CLIENT, DB_COLLECTION
    MONGO_CLIENT = AsyncIOMotorClient(MONGO_URI)
    db = MONGO_CLIENT[DB_NAME]
    DB_COLLECTION = db[COLLECTION_NAME]

    try:
        await DB_COLLECTION.create_index("url", unique=True)
    except Exception as e:
        print(f"[WARNING] Could not create index: {e}")

    yield
    MONGO_CLIENT.close()

def is_ip(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False

def extract_url_lexical_features(url_list):
    df = pd.DataFrame({'url': url_list})
    df['hostname'] = df['url'].apply(lambda x: urlparse(x).hostname)
    df['IP_address_in_domain'] = df['hostname'].apply(is_ip)
    mask_not_ip = ~df['IP_address_in_domain']
    df['len_domain'] = -1
    df['num_of_dot'] = -1
    df['num_of_dash'] = -1
    hostname_series = df.loc[mask_not_ip, 'hostname']
    df.loc[mask_not_ip, 'len_domain'] = hostname_series.str.len()
    df.loc[mask_not_ip, 'num_of_dot'] = hostname_series.str.count(r'\.')
    df.loc[mask_not_ip, 'num_of_dash'] = hostname_series.str.count(r'-')
    return df.drop(columns=['hostname']).to_dict('records')

async def crawl_and_store_raw(url_list, batch_size=200):
    total_inserted = 0
    
    for i in range(0, len(url_list), batch_size):
        batch = url_list[i:i + batch_size]
        results = extract_url_lexical_features(batch)
        if results:
            ops = [UpdateOne({"url": r["url"]}, {"$set": r}, upsert=True) for r in results]
            await DB_COLLECTION.bulk_write(ops)
            total_inserted += len(results)
            print(f"Processed {total_inserted} URLs")
            
    return total_inserted

class UrlListPayload(BaseModel):
    urls: List[str]

app = FastAPI(title="Raw URL Lexical Crawler", lifespan=lifespan)

@app.post("/extract")
async def extract(payload: UrlListPayload, background_tasks: BackgroundTasks):
    url_strings = [str(url) for url in payload.urls]
    existing = await DB_COLLECTION.find({"url": {"$in": url_strings}}, {"url": 1}).to_list(None)
    existing_urls = {doc["url"] for doc in existing}
    to_crawl = [u for u in url_strings if u not in existing_urls]
    if to_crawl:
        background_tasks.add_task(crawl_and_store_raw, to_crawl)
    return {"message": "Crawling started", "urls_received": len(url_strings), "urls_scheduled": len(to_crawl), "urls_skipped": len(existing_urls), "status": "processing"}