from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import List, Optional
import asyncio
import time
import os
import aiodns
import ssl
import base64
import aiohttp
import tldextract
from urllib.parse import urlparse
from motor.motor_asyncio import AsyncIOMotorClient
from contextlib import asynccontextmanager
import math
from rapidfuzz import fuzz
from pymongo import UpdateOne
import geoip2.database
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")
COLLECTION_NAME = os.getenv("COLLECTION_NAME")

MONGO_CLIENT: Optional[AsyncIOMotorClient] = None
DB_COLLECTION = None

SOURCE_IP = None 
DB_PATH = 'GeoLite2-City.mmdb'
GEO_READER = None
SOURCE_COORDS = (None, None)

GLOBAL_RESOLVER = None
GLOBAL_SSL_CONTEXT = None
TLD_EXTRACTOR = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global MONGO_CLIENT, DB_COLLECTION, SOURCE_IP, SOURCE_COORDS, GEO_READER, GLOBAL_RESOLVER, GLOBAL_SSL_CONTEXT, TLD_EXTRACTOR
    
    MONGO_CLIENT = AsyncIOMotorClient(MONGO_URI)
    db = MONGO_CLIENT[DB_NAME]
    DB_COLLECTION = db[COLLECTION_NAME]

    try:
        await DB_COLLECTION.create_index("url", unique=True)
    except Exception as e:
        print(f"[WARNING] Could not create index: {e}")
    
    GLOBAL_RESOLVER = aiodns.DNSResolver(
        nameservers=['8.8.8.8', '8.8.4.4', '1.1.1.1'],
        timeout=2
    )

    TLD_EXTRACTOR = tldextract.TLDExtract()

    try:
        GLOBAL_SSL_CONTEXT = ssl.create_default_context()
        GLOBAL_SSL_CONTEXT.check_hostname = False
        GLOBAL_SSL_CONTEXT.verify_mode = ssl.CERT_NONE
    except Exception as e:
        print(f"[WARNING] SSL context creation failed: {e}")

    try:
        GEO_READER = geoip2.database.Reader(DB_PATH)
    except Exception as e:
        print(f"[WARNING] GeoIP DB not found: {e}")

    async with aiohttp.ClientSession() as session:
        try:
            headers = {'Metadata': 'true'}
            azure_url = 'http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text'
            async with session.get(azure_url, headers=headers, timeout=1) as resp:
                if resp.status == 200:
                    SOURCE_IP = await resp.text()
        except:
            try:
                async with session.get('https://api.ipify.org', timeout=3) as resp:
                    if resp.status == 200:
                        SOURCE_IP = await resp.text()
            except:
                pass    
    if SOURCE_IP and GEO_READER:
        rec = GEO_READER.city(SOURCE_IP)
        SOURCE_COORDS = (rec.location.latitude, rec.location.longitude)
    yield
    if MONGO_CLIENT:
        MONGO_CLIENT.close()

async def get_geographical_features(hostname):
    result = {
        "geo_distance": -1.0,
        "hop_distance": -1.0,
        "rtt": -1.0,
        "city_names": []
    }
    all_ips = set()
    target_ip = None
    async def func_a():
        nonlocal target_ip
        try:
            res = await GLOBAL_RESOLVER.query(hostname, 'A')
            if res:
                target_ip = res[0].host
                for rdata in res:
                    all_ips.add(rdata.host)
        except Exception as e:
            print(f"Error in func_a for {hostname}: {e}")
            return result

    async def func_aaaa():
        try:
            aaaa_records = await GLOBAL_RESOLVER.query(hostname, 'AAAA')
            for rdata in aaaa_records:
                all_ips.add(rdata.host)
        except Exception as e:
            print(f"Error in func_aaaa for {hostname}: {e}")
            pass
    
    async def func_time():
        try:
            t0 = time.time()
            reader, writer = await asyncio.wait_for(asyncio.open_connection(target_ip, 80), timeout=1)
            result['rtt'] = (time.time() - t0) * 1000
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            print(f"Error in func_time for {hostname}: {e}")
            pass
            
    await asyncio.gather(func_a(), func_aaaa())
    if target_ip:
        await func_time()

    if GEO_READER and target_ip:
        loop = asyncio.get_running_loop()
        try:
            target_rec = await loop.run_in_executor(None, lambda: GEO_READER.city(target_ip))
            t_lat, t_lon = target_rec.location.latitude, target_rec.location.longitude
            s_lat, s_lon = SOURCE_COORDS
            if all(x is not None for x in [t_lat, t_lon, s_lat, s_lon]):
                lat1, lon1 = math.radians(s_lat), math.radians(s_lon)
                lat2, lon2 = math.radians(t_lat), math.radians(t_lon)
                
                d_sigma = math.acos(
                    math.sin(lat1)*math.sin(lat2) + 
                    math.cos(lat1)*math.cos(lat2)*math.cos(abs(lon1-lon2))
                )
                result['geo_distance'] = 6371.0 * d_sigma
        except Exception as e:
            print(f"Error in GeoIP calc for {hostname}: {e}")
            pass
        try:
            def get_cities(ips):
                cities = []
                for ip in ips:
                    try:
                        c_name = GEO_READER.city(ip).city.name
                        if c_name: cities.append(c_name)
                    except: continue
                return cities

            c_names = await loop.run_in_executor(None, get_cities, all_ips)
            result['city_names'].extend(c_names)
        except Exception as e:
            print(f"Error in get_cities for {hostname}: {e}")
            pass

    return result

async def extract_certificate_features(hostname):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, 443, ssl=GLOBAL_SSL_CONTEXT), 
            timeout=1
        )
        ssl_obj = writer.get_extra_info('ssl_object')
        der_cert_b64 = "missing"
        if ssl_obj:
            der_cert = ssl_obj.getpeercert(binary_form=True)
            if der_cert:
                der_cert_b64 = base64.b64encode(der_cert).decode('ascii')
        writer.close()
        await writer.wait_closed()
        return {
            "der_cert": der_cert_b64 
        }
    except Exception as e:
        print(f"[ERROR] {e}")
        return {
            "der_cert": "missing"
        }

async def get_dns_features(hostname):
    extracted = TLD_EXTRACTOR(hostname)
    root = f"{extracted.domain}.{extracted.suffix}"

    async def func_a(root):
        res = {
            "A_records": [],
            "dns_a_ttl": -1.0,
            "exist_PTR_record": False,
            "reverse_dns_look_up_matching": -1.0
        }
        try:
            A = await GLOBAL_RESOLVER.query(root, 'A')
            res["A_records"] = [r.host for r in A]
            res["dns_a_ttl"] = float(getattr(A[0], 'ttl', -1))

            sims = []
            async def cal_sims(r):
                try:
                    # Reverse lookup
                    rev = '.'.join(reversed(r.host.split('.'))) + '.in-addr.arpa'
                    ptr = await GLOBAL_RESOLVER.query(rev, 'PTR')
                    loop = asyncio.get_running_loop()
                    def calc_fuzz(target_root, ptr_records):
                        res = []
                        for p in ptr_records:
                            ptr_domain = getattr(p, 'name', '')
                            res.append(fuzz.ratio(target_root, ptr_domain.rstrip('.')) / 100.0)
                        return res
                    r_sims = await loop.run_in_executor(None, calc_fuzz, root, ptr)
                    sims.extend(r_sims)
                except Exception as e:
                    pass
            await asyncio.gather(*[cal_sims(r) for r in A])
            if sims:
                res["exist_PTR_record"] = True
                res["reverse_dns_look_up_matching"] = max(sims) 
        except: 
            pass
        return res
    async def func_aaaa(root):
        res = {
            "whether_AAAA_record_exist_for_domain": False
        }
        try:
            aaaa_records = await GLOBAL_RESOLVER.query(root, 'AAAA')
            if aaaa_records:
                res["whether_AAAA_record_exist_for_domain"] = True
        except: pass
        return res
    async def func_ns(root):
        res = {
            "NS_records": [],
            "dns_ns_ttl": -1,
            "NS_A_records": [],
            "dns_nsa_ttl": -1.0,
            "whether_AAAA_record_exist_for_name_servers": False
        }
        try:
            NS = await GLOBAL_RESOLVER.query(root, 'NS')
            res["NS_records"] = [r.host for r in NS]
            # TTL not available in aiodns
            res["dns_ns_ttl"] = float(getattr(NS[0], 'ttl', -1))
            max_ttl = 0
            async def cal_ns(r):
                nonlocal max_ttl
                ns_d = r.host.rstrip('.')
                try:
                    ns_a = await GLOBAL_RESOLVER.query(ns_d, 'A')
                    res["NS_A_records"].extend([x.host for x in ns_a])
                    if ns_a:
                        max_ttl = max(max_ttl, float(ns_a[0].ttl))
                except Exception:
                    pass
                if res["whether_AAAA_record_exist_for_name_servers"] == False:
                    try:
                        aaaa_records = await GLOBAL_RESOLVER.query(ns_d, 'AAAA')
                        if aaaa_records:
                            res["whether_AAAA_record_exist_for_name_servers"] = True
                    except Exception:
                        pass
            await asyncio.gather(*[cal_ns(r) for r in NS])
            res["dns_nsa_ttl"] = max_ttl
        except:
            pass
        return res
    results = await asyncio.gather(
        func_a(root),
        func_aaaa(root),
        func_ns(root)
    )
    final_result = {}
    for r in results:
        final_result.update(r)
    return final_result

async def fetch_one_url(url):
    final_result = {"url": url}
    hostname = urlparse(url).hostname
    results = await asyncio.gather(
        get_geographical_features(hostname),
        extract_certificate_features(hostname),
        get_dns_features(hostname)
    )
    for r in results:
        final_result.update(r)
    return final_result

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
            print(f"Error fetching {url}: {e}", flush=True)
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

app = FastAPI(title="Raw Distributed Crawler", lifespan=lifespan)

@app.post("/extract")
async def extract(payload: UrlListPayload, background_tasks: BackgroundTasks):
    url_strings = [str(url) for url in payload.urls]
    existing = await DB_COLLECTION.find({"url": {"$in": url_strings}}, {"url": 1}).to_list(None)
    existing_urls = {doc["url"] for doc in existing}
    to_crawl = [u for u in url_strings if u not in existing_urls]
    if to_crawl:
        background_tasks.add_task(crawl_and_store_raw, to_crawl)
    return {"message": "Crawling started", "urls_received": len(url_strings), "urls_scheduled": len(to_crawl), "urls_skipped": len(existing_urls), "status": "processing"}
