from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional
import asyncio
import asyncwhois
from urllib.parse import urlparse
from motor.motor_asyncio import AsyncIOMotorClient
from contextlib import asynccontextmanager
import re
from datetime import datetime, timezone
from pymongo import UpdateOne
import os
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")
COLLECTION_NAME = os.getenv("COLLECTION_NAME")

MONGO_CLIENT: Optional[AsyncIOMotorClient] = None
DB_COLLECTION = None

WHOIS_SEMAPHORE = asyncio.Semaphore(10) 

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

async def fetch_one_url(url, semaphore):
    result = {
        "url": url,
        "domain_age": -1.0,
        "diff_exipry_time": -1.0,
        "diff_update_time": -1.0,
        "registrar": "missing",
        "is_entry_locked": False
    }
    async with semaphore:
        try: 
            hostname = urlparse(url).hostname
            # Add timeout to prevent hanging indefinitely
            result_whois = await asyncio.wait_for(asyncwhois.aio_whois_domain(hostname), timeout=10.0)
            w = result_whois.parser_output

            if not w or (not w.get('created') and not w.get('registrar') and not w.get('status')):
                 return result
            
            raw_created = w.get('created')
            raw_expires = w.get('expires')
            raw_updated = w.get('updated')

            now = datetime.now(timezone.utc)
            creation_date = (raw_created[0] if raw_created else None) if isinstance(raw_created, list) else raw_created
            expiration_date = (raw_expires[0] if raw_expires else None) if isinstance(raw_expires, list) else raw_expires
            updated_date = (raw_updated[0] if raw_updated else None) if isinstance(raw_updated, list) else raw_updated

            domain_age = (now - creation_date).total_seconds() if creation_date else -1.0
            diff_exipry_time = (expiration_date - now).total_seconds() if expiration_date else -1.0
            diff_update_time = (now - updated_date).total_seconds() if updated_date else -1.0
            registrar = w.get('registrar') if w.get('registrar') else "missing"
            if isinstance(registrar, list): 
                registrar = registrar[0] if registrar else "missing"
            is_entry_locked = False

            status_raw = w.get('status')
            if isinstance(status_raw, list):
                status_list = [re.sub(r'[^a-zA-Z0-9]', '', str(s)).lower() for s in status_raw]
                for status in status_list:
                    if "clienttransferprohibited" in status or "registrarlock" in status:
                        is_entry_locked = True
            elif isinstance(status_raw, str):
                status_str = re.sub(r'[^a-zA-Z0-9]', '', status_raw).lower()
                if "clienttransferprohibited" in status_str or "registrarlock" in status_str:
                    is_entry_locked = True
            result["domain_age"] = domain_age
            result["diff_exipry_time"] = diff_exipry_time
            result["diff_update_time"] = diff_update_time
            result["registrar"] = registrar
            result["is_entry_locked"] = is_entry_locked
            return result
        except Exception as e:
            print(f"[ERROR] {url}: {e}")
            return result
        
async def _worker_pool(input_queue, output_queue):
    while True:
        try:
            url = input_queue.get_nowait()
        except asyncio.QueueEmpty:
            break 
        
        try:
            data = await fetch_one_url(url, WHOIS_SEMAPHORE)
            await output_queue.put(data)
        except Exception as e:
            # print(f"Error fetching {url}: {e}")
            pass
        finally:
            input_queue.task_done()

async def _db_saver(queue, collection, batch_size):
    buffer = []
    count = 0
    while True:
        doc = await queue.get()
        
        if doc is None:
            if buffer:
                await collection.bulk_write([UpdateOne({"url": d["url"]}, {"$set": d}, upsert=True) for d in buffer], ordered=False)
                count += len(buffer)
                print(f"Processed {count} URLs")
            queue.task_done()
            break
        
        buffer.append(doc)
        if len(buffer) >= batch_size:
            try:
                ops = [UpdateOne({"url": d["url"]}, {"$set": d}, upsert=True) for d in buffer]
                await collection.bulk_write(ops, ordered=False)
                count += len(buffer)
                print(f"Processed {count} URLs")
            except Exception:
                pass
            buffer.clear()
        
        queue.task_done()

async def crawl_and_store_raw(url_list, batch_size=500, concurrency_limit=200):
    input_queue = asyncio.Queue()
    output_queue = asyncio.Queue()
    
    for url in url_list:
        input_queue.put_nowait(url)
        
    saver_task = asyncio.create_task(_db_saver(output_queue, DB_COLLECTION, batch_size))
    
    workers = [
        asyncio.create_task(_worker_pool(input_queue, output_queue)) 
        for _ in range(concurrency_limit)
    ]
    
    await input_queue.join()
    
    await asyncio.gather(*workers)
    
    await output_queue.put(None)
    await saver_task
            
    return len(url_list)

class UrlListPayload(BaseModel):
    urls: List[str]

app = FastAPI(title="Raw WHOIS Crawler", lifespan=lifespan)

@app.post("/extract")
async def extract(payload: UrlListPayload, background_tasks: BackgroundTasks):
    url_strings = [str(url) for url in payload.urls]
    existing = await DB_COLLECTION.find({"url": {"$in": url_strings}}, {"url": 1}).to_list(None)
    existing_urls = {doc["url"] for doc in existing}
    to_crawl = [u for u in url_strings if u not in existing_urls]
    if to_crawl:
        background_tasks.add_task(crawl_and_store_raw, to_crawl)
    return {"message": "Crawling started", "urls_received": len(url_strings), "urls_scheduled": len(to_crawl), "urls_skipped": len(existing_urls), "status": "processing"}