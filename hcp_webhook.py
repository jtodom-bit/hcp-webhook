from fastapi import FastAPI, Request
import hmac, hashlib, os, json

app = FastAPI()
SIGNING_SECRET = os.getenv("HCP_SIGNING_SECRET", "").encode()

def verify_signature(raw, sig):
    if not sig:
        return False
    digest = hmac.new(SIGNING_SECRET, raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, sig)

@app.post("/hcphook")
async def hcphook(request: Request):
    raw = await request.body()
    sig = request.headers.get("x-hcp-signature")
    if not verify_signature(raw, sig):
        return {"error": "Bad signature"}
    payload = json.loads(raw)
    print("✅ Got webhook:", payload)
    return {"ok": True}
