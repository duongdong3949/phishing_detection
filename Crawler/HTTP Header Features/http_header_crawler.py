from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import List, Optional
import asyncio
import os
import aiohttp
from contextlib import asynccontextmanager
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import UpdateOne
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; Bot/1.0)'
}
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")
COLLECTION_NAME = os.getenv("COLLECTION_NAME")

CLIENT_SESSION: Optional[aiohttp.ClientSession] = None
MONGO_CLIENT: Optional[AsyncIOMotorClient] = None
DB_COLLECTION = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global CLIENT_SESSION, MONGO_CLIENT, DB_COLLECTION
    MONGO_CLIENT = AsyncIOMotorClient(MONGO_URI)
    db = MONGO_CLIENT[DB_NAME]
    DB_COLLECTION = db[COLLECTION_NAME]

    try:
        await DB_COLLECTION.create_index("url", unique=True)
    except Exception as e:
        print(f"[WARNING] Could not create index: {e}")

    connector = aiohttp.TCPConnector(
        limit=300, 
        ssl=False,
        resolver=aiohttp.AsyncResolver(), 
        ttl_dns_cache=300
    )
    timeout_client = aiohttp.ClientTimeout(total=3, connect=2)
    CLIENT_SESSION = aiohttp.ClientSession(
        connector=connector, 
        timeout=timeout_client, 
        cookie_jar=aiohttp.DummyCookieJar(),
        headers=DEFAULT_HEADERS
    )
    yield
    await CLIENT_SESSION.close()
    MONGO_CLIENT.close()

async def fetch_one_url(url):
    try: 
        async with CLIENT_SESSION.head(url, allow_redirects=False) as response:
            headers = response.headers
            return {
                "url": url,
                "http_header_count": len(headers), 
                "exist_cache_control": 'Cache-Control' in headers, 
                "len_header_server": len(headers.get('Server', ''))
            }
    except Exception as e:
        # print(f"[ERROR] {url}: {e}")
        return {
            "url": url,
            "http_header_count": -1,
            "exist_cache_control": False,
            "len_header_server": -1
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

app = FastAPI(title="Raw Header Crawler", lifespan=lifespan)

@app.post("/extract")
async def extract(payload: UrlListPayload, background_tasks: BackgroundTasks):
    url_strings = [str(url) for url in payload.urls]
    existing = await DB_COLLECTION.find({"url": {"$in": url_strings}}, {"url": 1}).to_list(None)
    existing_urls = {doc["url"] for doc in existing}
    to_crawl = [u for u in url_strings if u not in existing_urls]
    if to_crawl:
        background_tasks.add_task(crawl_and_store_raw, to_crawl)
    return {"message": "Crawling started", "urls_received": len(url_strings), "urls_scheduled": len(to_crawl), "urls_skipped": len(existing_urls), "status": "processing"}
