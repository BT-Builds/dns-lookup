import os
import time
import dns.resolver
from collections import defaultdict
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from typing import List, Optional

# ── API Key Auth (Upstash Redis) ───────────────────────────────────────────────
import os, time, json as _json
from urllib.request import Request as _Req, urlopen as _urlopen

_UPSTASH_URL = os.environ.get('UPSTASH_REDIS_REST_URL', '')
_UPSTASH_TOKEN=os.environ.get('UPSTASH_REDIS_REST_TOKEN', '')
_TIERS = {'free': 1000, 'starter': 25000, 'pro': 200000, 'demo': 50}

def _redis(cmd):
    url = f'{_UPSTASH_URL}/{cmd[0]}/' + '/'.join(str(x) for x in cmd[1:])
    req = _Req(url, headers={'Authorization': f'Bearer {_UPSTASH_TOKEN}'})
    try:
        return _json.loads(_urlopen(req, timeout=3).read()).get('result')
    except: return None

def verify_api_key(x_api_key: str = Header(default='free-demo-key')):
    if not _UPSTASH_URL:  # no Upstash configured, allow all (dev mode)
        return {'key': x_api_key, 'tier': 'free'}
    tier = 'demo'
    if x_api_key != 'free-demo-key':
        raw = _redis(['GET', f'key:{x_api_key}'])
        if not raw:
            raise HTTPException(401, 'Invalid API key. Get one at btbuilds.lemonsqueezy.com')
        data = _json.loads(raw)
        if not data.get('active', True):
            raise HTTPException(401, 'API key revoked')
        tier = data.get('tier', 'free')
    month = time.strftime('%Y-%m')
    used = int(_redis(['INCR', f'usage:{x_api_key}:{month}']) or 1)
    if used == 1: _redis(['EXPIRE', f'usage:{x_api_key}:{month}', 2678400])
    limit = _TIERS.get(tier, 1000)
    if used > limit:
        raise HTTPException(429, f'Monthly limit reached ({limit:,}/mo). Upgrade at btbuilds.lemonsqueezy.com')
    return {'key': x_api_key, 'tier': tier, 'used': used}


app = FastAPI(
    title="DNS Lookup API",
    description="Query DNS records for any domain without installing CLI tools",
    version="1.0.0"
)

API_KEYS = set(filter(None, os.environ.get("API_KEYS", "free-demo-key").split(",")))
RATE_LIMIT = int(os.environ.get("RATE_LIMIT_PER_MIN", "60"))
_req_counts: dict = defaultdict(list)


def auth(x_api_key: str = Header(default="free-demo-key")):
    if x_api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    now = time.time()
    window = [t for t in _req_counts[x_api_key] if now - t < 60]
    window.append(now)
    _req_counts[x_api_key] = window
    if len(window) > RATE_LIMIT:
        raise HTTPException(status_code=429, detail=f"Rate limit: {RATE_LIMIT} req/min")


class DNSRecord(BaseModel):
    type: str
    value: str


class DNSResponse(BaseModel):
    domain: str
    records: List[DNSRecord]
    error: Optional[str] = None


class BulkRequest(BaseModel):
    items: list


class BulkResponse(BaseModel):
    results: list
    total: int
    successful: int


def lookup_dns_sync(domain: str, record_types: list = None) -> dict:
    """Core DNS lookup logic reused by both single and bulk endpoints"""
    if record_types is None:
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

    records = []
    for rtype in record_types:
        try:
            if rtype == "MX":
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                for rdata in answers:
                    records.append(DNSRecord(type=rtype, value=f"{rdata.exchange} (priority: {rdata.preference})"))
            elif rtype == "CNAME":
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                for rdata in answers:
                    records.append(DNSRecord(type=rtype, value=str(rdata.target)))
            else:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                for rdata in answers:
                    records.append(DNSRecord(type=rtype, value=str(rdata)))
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NoNameservers:
            pass
        except dns.exception.Timeout:
            pass
        except Exception:
            pass

    return DNSResponse(domain=domain, records=records)


@app.get("/health")
def health():
    return {"status": "ok", "service": "dns-lookup"}


@app.post("/api/v1/lookup", dependencies=[Depends(auth)])
def lookup_dns(
    domain: str,
    record_types: Optional[List[str]] = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]
):
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter required")
    return lookup_dns_sync(domain, record_types)


@app.post("/bulk/lookup", dependencies=[Depends(auth)])
def bulk_lookup(request: BulkRequest):
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

            output = lookup_dns_sync(domain, record_types)
            output_dict = {"domain": output.domain, "records": [{"type": r.type, "value": r.value} for r in output.records]}
            if output.error:
                output_dict["error"] = output.error
            results.append({"input": domain, "output": output_dict, "error": None})
            successful += 1
        except Exception as e:
            domain = item.get("domain", str(item)) if isinstance(item, dict) else str(item)
            results.append({"input": domain, "output": None, "error": str(e)})

    return {"results": results, "total": len(items), "successful": successful}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5051)

try:
    from mangum import Mangum
    handler = Mangum(app, lifespan="off")
except ImportError:
    pass