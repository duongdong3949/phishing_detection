from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional
import asyncio
import os
import aiohttp
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
from motor.motor_asyncio import AsyncIOMotorClient
from contextlib import asynccontextmanager
from urllib.parse import urlparse
from pymongo import UpdateOne

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")
COLLECTION_NAME = os.getenv("COLLECTION_NAME")

MONGO_CLIENT: Optional[AsyncIOMotorClient] = None
DB_COLLECTION = None
CLIENT_SESSION: Optional[aiohttp.ClientSession] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global MONGO_CLIENT, DB_COLLECTION, CLIENT_SESSION
    
    MONGO_CLIENT = AsyncIOMotorClient(MONGO_URI)
    db = MONGO_CLIENT[DB_NAME]
    DB_COLLECTION = db[COLLECTION_NAME]

    try:
        await DB_COLLECTION.create_index("url", unique=True)
    except Exception as e:
        print(f"[WARNING] Could not create index: {e}")
    
    timeout = aiohttp.ClientTimeout(total=10, connect=3) 
    connector = aiohttp.TCPConnector(limit=300, ssl=False, resolver=aiohttp.AsyncResolver(), ttl_dns_cache=300) 
    
    CLIENT_SESSION = aiohttp.ClientSession(
        connector=connector, 
        timeout=timeout,
        cookie_jar=aiohttp.DummyCookieJar(),
        headers={'User-Agent': 'Mozilla/5.0 (compatible; PhishBot/1.0)'}
    )
    yield
    await CLIENT_SESSION.close()
    MONGO_CLIENT.close()

async def fetch_one_url(url):
    try:
        async with CLIENT_SESSION.head(url, allow_redirects=True) as response:
            chain = [str(r.url) for r in response.history] + [str(response.url)]
            return {
                "url": url,
                "len_redirection_chain": len(chain),
                "different_domains_crossed": len(set(urlparse(u).hostname for u in chain)),    
            }

    except Exception as e:
        # print(f"[ERROR] {url}: {e}")
        return {
            "url": url,
            "len_redirection_chain": -1,
            "different_domains_crossed": -1,    
        }

async def _worker_pool(input_queue, output_queue):
    while True:
        try:
            url = input_queue.get_nowait()
        except asyncio.QueueEmpty:
            break 
        
        try:
            data = await fetch_one_url(url)
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

app = FastAPI(title="Raw Redirection Crawler", lifespan=lifespan)

@app.post("/extract")
async def extract(payload: UrlListPayload, background_tasks: BackgroundTasks):
    url_strings = [str(url) for url in payload.urls]
    existing = await DB_COLLECTION.find({"url": {"$in": url_strings}}, {"url": 1}).to_list(None)
    existing_urls = {doc["url"] for doc in existing}
    to_crawl = [u for u in url_strings if u not in existing_urls]
    if to_crawl:
        background_tasks.add_task(crawl_and_store_raw, to_crawl)
    return {"message": "Crawling started", "urls_received": len(url_strings), "urls_scheduled": len(to_crawl), "urls_skipped": len(existing_urls), "status": "processing"}