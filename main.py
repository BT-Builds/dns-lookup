import os
import time
import socket
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import uvicorn
try:
    from mangum import Mangum
    mangum_available = True
except ImportError:
    mangum_available = False

app = FastAPI(title="DNS Lookup API", version="1.0.0")

# === BT Builds Standard Middleware ===
from fastapi.middleware.cors import CORSMiddleware as _BTCors
app.add_middleware(_BTCors, allow_origins=["*"], allow_methods=["*"],
    allow_headers=["*"], expose_headers=["X-RateLimit-Limit","X-RateLimit-Remaining","X-RateLimit-Reset"])

@app.middleware("http")
async def _bt_add_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Powered-By"] = "btbuilds"
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response

if mangum_available:
    handler = Mangum(app)

rate_limit_storage = {}
API_KEY = os.environ.get("API_KEY", "dev-key-change-me")

security = HTTPBearer(auto_error=False)

def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials or credentials.credentials != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return True

def check_rate_limit(client_id: str = "default"):
    current_hour = int(time.time() / 3600)
    key = f"{client_id}:{current_hour}"
    if key not in rate_limit_storage:
        rate_limit_storage[key] = 0
    if rate_limit_storage[key] >= 100:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    rate_limit_storage[key] += 1
    return True

class RecordResult(BaseModel):
    type: str
    value: str

class LookupResponse(BaseModel):
    domain: str
    records: list
    error: str = None

class BulkRequest(BaseModel):
    items: list

class BulkResponse(BaseModel):
    results: list
    total: int
    successful: int

def lookup_dns_sync(domain: str, record_types: list = None) -> dict:
    if record_types is None:
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

    results = {"domain": domain, "records": [], "error": None}

    try:
        for rtype in record_types:
            try:
                if rtype == "A":
                    answers = socket.getaddrinfo(domain, None, family=socket.AF_INET)
                    seen = set()
                    for family, type_, proto, canonname, sockaddr in answers:
                        ip = sockaddr[0]
                        if ip not in seen:
                            results["records"].append({"type": "A", "value": ip})
                            seen.add(ip)
                elif rtype == "AAAA":
                    answers = socket.getaddrinfo(domain, None, family=socket.AF_INET6)
                    seen = set()
                    for family, type_, proto, canonname, sockaddr in answers:
                        ip = sockaddr[0]
                        if ip not in seen:
                            results["records"].append({"type": "AAAA", "value": ip})
                            seen.add(ip)
            except socket.gaierror:
                pass
            except socket.error:
                pass
    except Exception as e:
        results["error"] = str(e)

    return results

def lookup_dns(domain: str, record_types: list = None) -> dict:
    """Async-capable DNS lookup using aiodns if available, falls back to sync socket"""
    try:
        import asyncio
        import aiodns
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(async_lookup_dns(domain, record_types))
        finally:
            loop.close()
    except ImportError:
        return lookup_dns_sync(domain, record_types)

async def async_lookup_dns(domain: str, record_types: list = None) -> dict:
    if record_types is None:
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

    results = {"domain": domain, "records": [], "error": None}

    try:
        import aiodns
        resolver = aiodns.DNSResolver()
        for rtype in record_types:
            try:
                if rtype == "A":
                    resp = await resolver.query(domain, "A")
                    for rdata in resp:
                        results["records"].append({"type": "A", "value": rdata.host})
                elif rtype == "AAAA":
                    resp = await resolver.query(domain, "AAAA")
                    for rdata in resp:
                        results["records"].append({"type": "AAAA", "value": rdata.host})
                elif rtype == "MX":\                    resp = await resolver.query(domain, "MX")
                    for rdata in resp:
                        results["records"].append({"type": "MX", "value": f"{rdata.host}. (priority: {rdata.priority})"})
                elif rtype == "TXT":
                    resp = await resolver.query(domain, "TXT")
                    for rdata in resp:
                        txt = "".join(rdata.strings) if hasattr(rdata, 'strings') else str(rdata)
                        results["records"].append({"type": "TXT", "value": txt})
                elif rtype == "NS":
                    resp = await resolver.query(domain, "NS")
                    for rdata in resp:
                        results["records"].append({"type": "NS", "value": str(rdata.host)})
                elif rtype == "CNAME":
                    resp = await resolver.query(domain, "CNAME")
                    for rdata in resp:
                        results["records"].append({"type": "CNAME", "value": str(rdata.host)})
            except Exception:
                pass
    except ImportError:
        # Fallback to sync socket-based lookup
        results = lookup_dns_sync(domain, record_types)

    return results

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/api/v1/lookup", response_model=LookupResponse)
async def lookup_dns_endpoint(domain: str, record_types: list = None, _: bool = Depends(check_rate_limit)):
    result = await async_lookup_dns(domain, record_types)
    return result

@app.post("/bulk/lookup", response_model=BulkResponse)
async def bulk_lookup(request: BulkRequest, _: bool = Depends(check_rate_limit)):
    items = request.items
    if not isinstance(items, list):
        raise HTTPException(status_code=400, detail="items must be a list")
    if len(items) > 1000:
        raise HTTPException(status_code=400, detail="Maximum 1000 items per request")

    results = []
    successful = 0

    for item in items:
        try:
            if isinstance(item, dict):
                domain = item.get("domain")
                record_types = item.get("record_types")
            else:
                domain = str(item)
                record_types = None

            if not domain:
                raise ValueError("domain is required")

            result = await async_lookup_dns(domain, record_types)
            results.append({"input": domain, "output": result, "error": None})
            successful += 1
        except Exception as e:
            domain = item.get("domain", str(item)) if isinstance(item, dict) else str(item)
            results.append({"input": domain, "output": None, "error": str(e)})

    return {"results": results, "total": len(items), "successful": successful}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)