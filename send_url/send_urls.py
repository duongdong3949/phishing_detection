import asyncio
import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List

app = FastAPI(title="URL Dispatcher Service")

class UrlListPayload(BaseModel):
    urls: List[str]

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

async def send_to_crawler(client: httpx.AsyncClient, service_url: str, payload: dict):
    try:
        response = await client.post(service_url, json=payload, timeout=60.0)
        response.raise_for_status()
        return {
            "service": service_url,
            "status": "success",
            "response": response.json()
        }
    except Exception as e:
        return {
            "service": service_url,
            "status": "error",
            "error": str(e)
        }

@app.post("/dispatch")
async def dispatch_urls(payload: UrlListPayload):
    if not payload.urls:
        raise HTTPException(status_code=400, detail="URL list cannot be empty")

    results = []
    async with httpx.AsyncClient() as client:
        tasks = [
            send_to_crawler(client, service_url, payload.dict())
            for service_url in CRAWLER_SERVICES
        ]
        results = await asyncio.gather(*tasks)

    return {
        "message": "Dispatch completed",
        "results": results
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
