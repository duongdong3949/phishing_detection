from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict, Tuple
import asyncio
import socket
import struct
from scapy.all import conf, get_if_addr
from urllib.parse import urlparse
import aiodns
from motor.motor_asyncio import AsyncIOMotorClient
from contextlib import asynccontextmanager
from pymongo import UpdateOne
import time
import numpy as np
import os
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

import threading

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")
COLLECTION_NAME = os.getenv("COLLECTION_NAME")
INTERFACE = str(conf.iface)

MONGO_CLIENT: Optional[AsyncIOMotorClient] = None
DB_COLLECTION = None
RAW_SOCKET: Optional[socket.socket] = None
active_flows: Dict[Tuple[bytes, int], Dict] = {}
LOCAL_IP_BYTES = None

GLOBAL_RESOLVER = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global MONGO_CLIENT, DB_COLLECTION, RAW_SOCKET, GLOBAL_RESOLVER, LOCAL_IP_BYTES
    MONGO_CLIENT = AsyncIOMotorClient(MONGO_URI)
    db = MONGO_CLIENT[DB_NAME]
    DB_COLLECTION = db[COLLECTION_NAME]

    try:
        await DB_COLLECTION.create_index("url", unique=True)
    except Exception as e:
        print(f"[WARNING] Could not create index: {e}")
    
    try:
        local_ip_str = get_if_addr(INTERFACE)
        LOCAL_IP_BYTES = socket.inet_aton(local_ip_str)
        print(f"[*] Local IP: {local_ip_str} on {INTERFACE}")
    except Exception as e:
        print(f"[CRITICAL] Cannot get Local IP: {e}")
        exit(1)

    GLOBAL_RESOLVER = aiodns.DNSResolver(
        nameservers=['8.8.8.8', '8.8.4.4', '1.1.1.1'],
        timeout=2)

    try:
        RAW_SOCKET = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        RAW_SOCKET.bind((INTERFACE, 0))
        # RAW_SOCKET.setblocking(False) # Blocking mode is better for thread loop
        
        # loop = asyncio.get_running_loop()
        # loop.add_reader(RAW_SOCKET, raw_packet_handler)
        
        t = threading.Thread(target=packet_sniffer_thread, daemon=True)
        t.start()
        
        print(f"[*] Raw Socket Sniffer Started on {INTERFACE}")
    except PermissionError:
        print("[CRITICAL] API must run with SUDO/ROOT to use Raw Sockets!")
    yield
    if RAW_SOCKET:
        try:
            loop = asyncio.get_running_loop()
            loop.remove_reader(RAW_SOCKET)
            RAW_SOCKET.close()
        except: pass
    MONGO_CLIENT.close()

def packet_sniffer_thread():
    global RAW_SOCKET
    print(f"[*] Sniffer thread started loop")
    while True:
        try:
            raw_packet_handler()
        except Exception as e:
            print(f"[ERROR] Sniffer loop: {e}")
            time.sleep(0.1)

def raw_packet_handler():
    global RAW_SOCKET
    try:
        raw_data = RAW_SOCKET.recv(65535)
        capture_time = time.time()

        # Ethernet Header is 14 bytes
        if len(raw_data) < 34: return # Too short for Eth + IP (20)

        # IP Header
        ver_ihl = raw_data[14]
        iph_len = (ver_ihl & 0x0F) * 4
        protocol = raw_data[23]
        if protocol != 6: return
        tcp_start = 14 + iph_len
        if len(raw_data) < tcp_start + 20: return # Too short for TCP header

        src_port = struct.unpack('!H', raw_data[tcp_start:tcp_start+2])[0]
        dst_port = struct.unpack('!H', raw_data[tcp_start+2:tcp_start+4])[0]
        src_ip = raw_data[26:30]
        dst_ip = raw_data[30:34]
        
        target_flow = None
        direction = None

        # Logic fix: Check based on direction and construct the key tuple
        # Incoming: Server (src) -> Local (dst)
        if dst_ip == LOCAL_IP_BYTES:
            key = (src_ip, dst_port) # Key is (RemoteIP, LocalPort)
            if key in active_flows:
                target_flow = active_flows[key]
                direction = 'in'
        
        # Outgoing: Local (src) -> Server (dst)
        elif src_ip == LOCAL_IP_BYTES:
            key = (dst_ip, src_port) # Key is (RemoteIP, LocalPort)
            if key in active_flows:
                target_flow = active_flows[key]
                direction = 'out'

        if target_flow is None:
            return
        seq_no = struct.unpack('!L', raw_data[tcp_start+4 : tcp_start+8])[0]
        flags = raw_data[tcp_start + 13]
        data_offset = (raw_data[tcp_start + 12] >> 4) * 4
        total_len = struct.unpack('!H', raw_data[16:18])[0]
        payload_len = total_len - iph_len - data_offset
        d = target_flow # Alias cho ngắn gọn
        
        if direction == 'in':
            if d['first_packet_time'] == 0:
                d['first_packet_time'] = capture_time
            d['last_packet_time'] = capture_time
            d['packet_received'] += 1
            
            # Idle Time
            if d['last_time'] != 0:
                d['idle_list'].append(capture_time - d['last_time'])
            d['last_time'] = capture_time

            # Flags (Bitwise: FIN=0x01, RST=0x04)
            if flags & 0x01: d['fins_remote'] += 1
            if flags & 0x04: d['rsts_remote'] += 1
            
            # Retransmission Check
            if d['highest_seq_received'] == 0:
                d['highest_seq_received'] = seq_no + payload_len
            else:
                if seq_no < d['highest_seq_received']:
                    d['retransmission_remote'] += 1
                else:
                    d['highest_seq_received'] = seq_no + payload_len

        else: # direction == 'out'
            d['packet_sent'] += 1
            if flags & 0x01: d['fins_local'] += 1
            if flags & 0x04: d['rsts_local'] += 1
            
            if d['highest_seq_sent'] == 0:
                d['highest_seq_sent'] = seq_no + payload_len
            else:
                if seq_no < d['highest_seq_sent']:
                    d['retransmission_local'] += 1
                else:
                    d['highest_seq_sent'] = seq_no + payload_len
    except Exception as e:
        print(f"[ERROR] Raw packet handler: {e}")
        pass

async def fetch_one_url(url):
    domain = urlparse(url).hostname
    flow_key = None 
    ip_str = None
    try:
        answers = await GLOBAL_RESOLVER.query(domain, 'A')
        ip_str = answers[0].host
        ip_bytes = socket.inet_aton(ip_str)
    except Exception as e:
        print(f"[ERROR] DNS resolution failed for {url}: {e}")
        return {
            'url': url,
            'fins_local': -1, 'fins_remote': -1,
            'max_idle_time': -1,
            'variance_packet_arrival_time': -1,
            'packets_received_to_packets_sent': -1,
            'rsts_local': -1, 'rsts_remote': -1,
            'retransmission_local': -1, 'retransmission_remote': -1,
            'packet_counts': -1, 'packet_rate': -1
        }
    metrics = {
        'fins_local': 0, 'fins_remote': 0,
        'packet_received': 0, 'packet_sent': 0,
        'last_time': 0, 'idle_list': [],
        'rsts_local': 0, 'rsts_remote': 0,
        'retransmission_local': 0, 'retransmission_remote': 0,
        'highest_seq_sent': 0, 'highest_seq_received': 0,
        'first_packet_time': 0, 'last_packet_time': 0
    }
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip_str, 80), timeout=3.0
        )

        sock = writer.get_extra_info('socket')
        local_port = sock.getsockname()[1]
        flow_key = (ip_bytes, local_port)
        active_flows[flow_key] = metrics

        request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
        writer.write(request.encode())
        await writer.drain()
        _ = await reader.read(1024)
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(1.0)
    except Exception as e:
        print(f"[ERROR] Connection failed for {url}: {e}")
        pass
    finally:
        if flow_key and flow_key in active_flows:
            del active_flows[flow_key]

    d = metrics
    packet_rate = -1.0
    if d['last_packet_time'] > d['first_packet_time']:
        packet_rate = d['packet_received'] / (d['last_packet_time'] - d['first_packet_time'])

    return {
        'url': url,
        'fins_local': d['fins_local'],
        'fins_remote': d['fins_remote'],
        'max_idle_time': float(np.max(d['idle_list'])) if d['idle_list'] else -1,
        'variance_packet_arrival_time': np.var(d['idle_list']) if d['idle_list'] else -1.0,
        'packets_received_to_packets_sent': d['packet_received'] / d['packet_sent'] if d['packet_sent'] > 0 else -1.0,
        'rsts_local': d['rsts_local'],
        'rsts_remote': d['rsts_remote'],
        'retransmission_local': d['retransmission_local'],
        'retransmission_remote': d['retransmission_remote'],
        'packet_counts': d['packet_received'],
        'packet_rate': packet_rate
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

app = FastAPI(title="Raw Network Crawler", lifespan=lifespan)

@app.post("/extract")
async def extract(payload: UrlListPayload, background_tasks: BackgroundTasks):
    url_strings = [str(url) for url in payload.urls]
    existing = await DB_COLLECTION.find({"url": {"$in": url_strings}}, {"url": 1}).to_list(None)
    existing_urls = {doc["url"] for doc in existing}
    to_crawl = [u for u in url_strings if u not in existing_urls]
    if to_crawl:
        background_tasks.add_task(crawl_and_store_raw, to_crawl)
    return {"message": "Crawling started", "urls_received": len(url_strings), "urls_scheduled": len(to_crawl), "urls_skipped": len(existing_urls), "status": "processing"}