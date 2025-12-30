import asyncio
import ssl
import re
import base64
import os
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import List, Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from motor.motor_asyncio import AsyncIOMotorClient
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.x509.extensions import ExtensionNotFound
from rapidfuzz import fuzz
from pymongo import UpdateOne
import aiodns
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")
COLLECTION_NAME = os.getenv("COLLECTION_NAME")
MONGO_CLIENT: Optional[AsyncIOMotorClient] = None
DB_COLLECTION = None

GLOBAL_SSL_CONTEXT = None

TRUSTED_ISSUER_NAMES = set()

PROHIBITED_PATTERNS = None

RESOLVER = None
@asynccontextmanager
async def lifespan(app: FastAPI):
    global MONGO_CLIENT, DB_COLLECTION, GLOBAL_SSL_CONTEXT, TRUSTED_ISSUER_NAMES, PROHIBITED_PATTERNS, RESOLVER
    MONGO_CLIENT = AsyncIOMotorClient(MONGO_URI)
    db = MONGO_CLIENT[DB_NAME]
    DB_COLLECTION = db[COLLECTION_NAME]    

    try:
        await DB_COLLECTION.create_index("url", unique=True)
    except Exception as e:
        print(f"[WARNING] Could not create index: {e}")

    try:
        GLOBAL_SSL_CONTEXT = ssl.create_default_context()
        GLOBAL_SSL_CONTEXT.check_hostname = False
        GLOBAL_SSL_CONTEXT.verify_mode = ssl.CERT_NONE
    except Exception as e:
        print(f"[WARNING] SSL context creation failed: {e}")

    trusted_certs = GLOBAL_SSL_CONTEXT.get_ca_certs()
    for cert in trusted_certs:
        for attr in cert['subject']:
            if attr[0][0] == 'commonName':
                TRUSTED_ISSUER_NAMES.add(attr[0][1].lower())

    PROHIBITED_PATTERNS = [
        re.compile(p) for p in [
            r"^192\.168\.", r"^10\.", r"^127\.0\.0\.1$",
            r"localhost", r"^\*$", r"^(default|none)$"
        ]
    ]

    RESOLVER = aiodns.DNSResolver()

    yield
    if MONGO_CLIENT:
        MONGO_CLIENT.close()

def is_cert_trusted_by_mozilla(issuer_cn):
    if not issuer_cn:
        return False
    return issuer_cn.lower() in TRUSTED_ISSUER_NAMES

def extract_certificate_extensions(cert):
    extensions = cert.extensions
    oids = {ext.oid for ext in extensions}
    return {
        "extension_count": len(extensions),
        "authority_info_access": ExtensionOID.AUTHORITY_INFORMATION_ACCESS in oids,
        "authority_key_identifier": ExtensionOID.AUTHORITY_KEY_IDENTIFIER in oids,
        "subject_key_identifier": ExtensionOID.SUBJECT_KEY_IDENTIFIER in oids,
        "basic_constraints": ExtensionOID.BASIC_CONSTRAINTS in oids,
        "certificate_policies": ExtensionOID.CERTIFICATE_POLICIES in oids,
        "extended_key_usage": ExtensionOID.EXTENDED_KEY_USAGE in oids,
        "CRL_distribution_points": ExtensionOID.CRL_DISTRIBUTION_POINTS in oids,
        "freshest_CRL": ExtensionOID.FRESHEST_CRL in oids,
        "key_usage": ExtensionOID.KEY_USAGE in oids,
        "issuer_alt_name": ExtensionOID.ISSUER_ALTERNATIVE_NAME in oids,
        "subject_alt_name": ExtensionOID.SUBJECT_ALTERNATIVE_NAME in oids,
        "subject_directory_attributes": ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES in oids
    }

def get_safe_alt_names(extensions):
    try:
        ext = extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return ext.value.get_values_for_type(x509.DNSName)
    except ExtensionNotFound:
        return []
    except Exception:
        return []

def get_safe_subfield(name_obj, oid):
    try:
        attributes = name_obj.get_attributes_for_oid(oid)
        if attributes:
            return attributes[0].value
    except Exception:
        pass
    return ""

def extract_certificate_issuer_subject(cert, domain):
    issuer = cert.issuer
    subject = cert.subject
    extensions = cert.extensions

    # Issuer information
    issuer_cn = get_safe_subfield(issuer, NameOID.COMMON_NAME)
    issuer_o = get_safe_subfield(issuer, NameOID.ORGANIZATION_NAME)
    issuer_ou = get_safe_subfield(issuer, NameOID.ORGANIZATIONAL_UNIT_NAME)
    issuer_st = get_safe_subfield(issuer, NameOID.STATE_OR_PROVINCE_NAME)
    issuer_city = get_safe_subfield(issuer, NameOID.LOCALITY_NAME)
    issuer_email = get_safe_subfield(issuer, NameOID.EMAIL_ADDRESS)
    issuer_c = get_safe_subfield(issuer, NameOID.COUNTRY_NAME)

    # Subject information
    subject_cn = get_safe_subfield(subject, NameOID.COMMON_NAME)
    subject_o = get_safe_subfield(subject, NameOID.ORGANIZATION_NAME)
    subject_ou = get_safe_subfield(subject, NameOID.ORGANIZATIONAL_UNIT_NAME)
    subject_st = get_safe_subfield(subject, NameOID.STATE_OR_PROVINCE_NAME)
    subject_city = get_safe_subfield(subject, NameOID.LOCALITY_NAME)
    subject_email = get_safe_subfield(subject, NameOID.EMAIL_ADDRESS)
    subject_c = get_safe_subfield(subject, NameOID.COUNTRY_NAME)

    alt_names = get_safe_alt_names(extensions)

    issuer_fields_to_check = [issuer_cn, issuer_o, issuer_ou]
    subject_fields_to_check = [subject_cn, subject_o, subject_ou]

    is_trusted_issuer = is_cert_trusted_by_mozilla(issuer_cn)
    is_prohibited_issuer = any(pattern.match(field) for pattern in PROHIBITED_PATTERNS for field in issuer_fields_to_check)
    is_prohibited_subject = any(pattern.match(field) for pattern in PROHIBITED_PATTERNS for field in subject_fields_to_check)
        
    match_issuer_o_cn = fuzz.ratio(issuer_cn, issuer_o) / 100.0 if issuer_o and issuer_cn else -1
    match_issuer_o_ou = fuzz.ratio(issuer_ou, issuer_o) / 100.0 if issuer_o and issuer_ou else -1
    match_subject_o_cn = fuzz.ratio(subject_cn, subject_o) / 100.0 if subject_o and subject_cn else -1
    match_subject_o_ou = fuzz.ratio(subject_ou, subject_o) / 100.0 if subject_o and subject_ou else -1
    match_issuer_subject_cn = fuzz.ratio(issuer_cn, subject_cn) / 100.0 if issuer_cn and subject_cn else -1
    match_website_issuer_cn = fuzz.ratio(issuer_cn, domain) / 100.0 if issuer_cn else -1
    match_website_subject_cn = fuzz.ratio(subject_cn, domain) / 100.0 if subject_cn else -1

    diff_alt_list = [fuzz.ratio(alt_name, domain) / 100.0 if alt_name else -1 for alt_name in alt_names]
    match_website_altname = max(diff_alt_list) if len(diff_alt_list) > 0 else -1

    len_issuer_st = len(issuer_st) if issuer_st else -1
    len_issuer_city = len(issuer_city) if issuer_city else -1
    len_issuer_cn = len(issuer_cn) if issuer_cn else -1
    len_issuer_o = len(issuer_o) if issuer_o else -1
    len_issuer_ou = len(issuer_ou) if issuer_ou else -1
    len_issuer_email = len(issuer_email) if issuer_email else -1

    len_subject_st = len(subject_st) if subject_st else -1
    len_subject_city = len(subject_city) if subject_city else -1
    len_subject_cn = len(subject_cn) if subject_cn else -1
    len_subject_o = len(subject_o) if subject_o else -1
    len_subject_ou = len(subject_ou) if subject_ou else -1
    len_subject_email = len(subject_email) if subject_email else -1

    cert_issuer_c = issuer_c if issuer_c else "missing"
    cert_subject_c = subject_c if subject_c else "missing"

    return {
        'is_trusted_issuer': is_trusted_issuer,
        'is_prohibited_issuer': is_prohibited_issuer,
        'is_prohibited_subject': is_prohibited_subject,
            
        'match_issuer_o_cn': match_issuer_o_cn,
        'match_issuer_o_ou': match_issuer_o_ou,
        'match_subject_o_cn': match_subject_o_cn,
        'match_subject_o_ou': match_subject_o_ou,
        'match_issuer_subject_cn': match_issuer_subject_cn,
        'match_website_issuer_cn': match_website_issuer_cn,
        'match_website_altname': match_website_altname,
        'match_website_subject_cn': match_website_subject_cn,
            
        'len_issuer_st': len_issuer_st,
        'len_issuer_city': len_issuer_city,
        'len_issuer_cn': len_issuer_cn,
        'len_issuer_o': len_issuer_o,
        'len_issuer_ou': len_issuer_ou,
        'len_issuer_email': len_issuer_email,
        'len_subject_st': len_subject_st,
        'len_subject_city': len_subject_city,
        'len_subject_cn': len_subject_cn,
        'len_subject_o': len_subject_o,
        'len_subject_ou': len_subject_ou,
        'len_subject_email': len_subject_email,
        'cert_issuer_c': cert_issuer_c,
        'cert_subject_c': cert_subject_c,
    }

def extract_certificate_chronological(cert):
    not_before = cert.not_valid_before_utc  
    not_after = cert.not_valid_after_utc  
    now = datetime.now(timezone.utc)
    return {
        "diff_notbefore_timestamp": (now - not_before).total_seconds(),
        "diff_notafter_timestamp": (not_after - now).total_seconds(),
        "diff_notbefore_notafter": (not_after - not_before).total_seconds(),
        "has_expired": now > not_after
    }

def extract_other_certificate(cert):
    return {
        "len_serialnum": len(hex(cert.serial_number)),
        "signature_algorithm": cert.signature_algorithm_oid.dotted_string,
        "cert_version": cert.version.name
    }

def process_certificate_data(cert, hostname, url):
    certificate_feature = {"url": url}
    certificate_feature.update(extract_certificate_extensions(cert))
    certificate_feature.update(extract_certificate_issuer_subject(cert, hostname))
    certificate_feature.update(extract_certificate_chronological(cert))
    certificate_feature.update(extract_other_certificate(cert))
    certificate_feature["has_certificate"] = True
    return certificate_feature

def get_certificate_missing_value(url):
    return {
        "url": url,
        "extension_count": -1,
        "authority_info_access": False,
        "authority_key_identifier": False,
        "subject_key_identifier": False,
        "basic_constraints": False,
        "certificate_policies": False,
        "extended_key_usage": False,
        "CRL_distribution_points": False,
        "freshest_CRL": False,
        # "is_extended_validation": False, 
        "key_usage": False,
        "issuer_alt_name": False,
        "subject_alt_name": False,
        "subject_directory_attributes": False,

        'is_trusted_issuer': False,
        'is_prohibited_issuer': False, 
        'is_prohibited_subject': False,
        'match_issuer_o_cn': -1.0,
        'match_issuer_o_ou': -1.0,
        'match_subject_o_cn': -1.0,
        'match_subject_o_ou': -1.0,
        'match_issuer_subject_cn': -1.0,
        'match_website_issuer_cn': -1.0,
        'match_website_altname': -1.0,
        'match_website_subject_cn': -1.0,
        'len_issuer_st': -1,
        'len_issuer_city': -1,
        'len_issuer_cn': -1,
        'len_issuer_o': -1,
        'len_issuer_ou': -1,
        'len_issuer_email': -1,
        'len_subject_st': -1,
        'len_subject_city': -1,
        'len_subject_cn': -1,
        'len_subject_o': -1,
        'len_subject_ou': -1,
        'len_subject_email': -1,
        'cert_issuer_c': "missing",
        'cert_subject_c': "missing",

        "diff_notbefore_timestamp": -1,
        "diff_notafter_timestamp": -1,
        "diff_notbefore_notafter": -1,
        "has_expired": False,

        "len_serialnum": -1,
        "signature_algorithm": "missing",
        "cert_version": "missing",
        "has_certificate": False
    }

async def fetch_one_url(url):
    target_url = url
    if not url.startswith(("http://", "https://")):
        target_url = f"https://{url}"
        
    hostname = urlparse(target_url).hostname
    if not hostname:
        return get_certificate_missing_value(url)

    try:
        result = await RESOLVER.query(hostname, 'A')
        ip_address = result[0].host
    except Exception as e:
        print(f"[ERROR] DNS resolution failed for {hostname}: {e}")
        return get_certificate_missing_value(url)
    port = 443
    try:
        conn_coro = asyncio.open_connection(host=ip_address, port=port, ssl=GLOBAL_SSL_CONTEXT, server_hostname=hostname)
        reader, writer = await asyncio.wait_for(conn_coro, timeout=3)
        try:
            ssl_object = writer.get_extra_info('ssl_object')
            if ssl_object:
                der_cert = ssl_object.getpeercert(binary_form=True)
                if der_cert:
                    cert = x509.load_der_x509_certificate(der_cert)
                    loop = asyncio.get_running_loop()
                    return await loop.run_in_executor(None, process_certificate_data, cert, hostname, url)
            else:
                print(f"[ERROR] No SSL object found for {url}. GLOBAL_SSL_CONTEXT might be None.")
        except Exception as e:
            print(f"[ERROR] SSL extraction error for {url}: {e}")
            return get_certificate_missing_value(url)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
    except Exception as e:
        print(f"[ERROR] Connection error for {url}: {e}") 
        pass
    return get_certificate_missing_value(url)

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

app = FastAPI(title="Raw Certificate Crawler", lifespan=lifespan)

@app.post("/extract")
async def extract(payload: UrlListPayload, background_tasks: BackgroundTasks):
    url_strings = [str(url) for url in payload.urls]
    existing = await DB_COLLECTION.find({"url": {"$in": url_strings}}, {"url": 1}).to_list(None)
    existing_urls = {doc["url"] for doc in existing}
    to_crawl = [u for u in url_strings if u not in existing_urls]
    if to_crawl:
        background_tasks.add_task(crawl_and_store_raw, to_crawl)
    return {"message": "Crawling started", "urls_received": len(url_strings), "urls_scheduled": len(to_crawl), "urls_skipped": len(existing_urls), "status": "processing"}


