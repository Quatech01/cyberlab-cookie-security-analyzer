from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn
import threading
import time
import urllib.request

app = FastAPI()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/targets")
def targets():
    return {
        "endpoints": [
            {"path": "/set-cookie/bare", "description": "No flags at all — bare session cookie"},
            {"path": "/set-cookie/httponly-only", "description": "HttpOnly only — missing Secure and SameSite"},
            {"path": "/set-cookie/httponly-secure", "description": "HttpOnly + Secure — missing SameSite"},
            {"path": "/set-cookie/full-secure", "description": "Fully hardened: HttpOnly, Secure, SameSite=Strict"},
            {"path": "/set-cookie/samesite-lax", "description": "HttpOnly, Secure, SameSite=Lax — valid relaxed policy"},
            {"path": "/set-cookie/none-no-secure", "description": "SameSite=None without Secure — RFC 6265bis violation"},
        ]
    }


@app.get("/set-cookie/bare")
def cookie_bare():
    """VULNERABLE: session cookie with no security flags."""
    resp = JSONResponse({"endpoint": "bare", "status": "logged in"})
    resp.set_cookie(
        key="session",
        value="bare-insecure-token-abc123",
        httponly=False,
        secure=False,
        samesite=None,
        path="/",
    )
    return resp


@app.get("/set-cookie/httponly-only")
def cookie_httponly_only():
    """PARTIAL: HttpOnly prevents JS access but cookie still travels over HTTP and lacks CSRF protection."""
    resp = JSONResponse({"endpoint": "httponly-only", "status": "logged in"})
    resp.set_cookie(
        key="session",
        value="httponly-only-token-def456",
        httponly=True,
        secure=False,
        samesite=None,
        path="/",
    )
    return resp


@app.get("/set-cookie/httponly-secure")
def cookie_httponly_secure():
    """PARTIAL: HttpOnly + Secure protect the channel but missing SameSite leaves CSRF exposure."""
    resp = JSONResponse({"endpoint": "httponly-secure", "status": "logged in"})
    resp.set_cookie(
        key="session",
        value="httponly-secure-token-ghi789",
        httponly=True,
        secure=True,
        samesite=None,
        path="/",
    )
    return resp


@app.get("/set-cookie/full-secure")
def cookie_full_secure():
    """SAFE: All three flags present. SameSite=Strict provides the strongest CSRF protection."""
    resp = JSONResponse({"endpoint": "full-secure", "status": "logged in"})
    resp.set_cookie(
        key="session",
        value="fully-secure-token-jkl012",
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=3600,
        path="/",
    )
    return resp


@app.get("/set-cookie/samesite-lax")
def cookie_samesite_lax():
    """SAFE: SameSite=Lax is the browser default since Chrome 80 and is an acceptable policy."""
    resp = JSONResponse({"endpoint": "samesite-lax", "status": "logged in"})
    resp.set_cookie(
        key="session",
        value="lax-token-mno345",
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=3600,
        path="/",
    )
    return resp


@app.get("/set-cookie/none-no-secure")
def cookie_none_no_secure():
    """INVALID: SameSite=None without Secure violates RFC 6265bis. Modern browsers reject this cookie."""
    resp = JSONResponse({"endpoint": "none-no-secure", "status": "logged in"})
    # Use raw_headers to bypass any framework enforcement of the Secure requirement.
    # This accurately represents what a misconfigured server would emit.
    resp.raw_headers.append(
        (b"set-cookie", b"session=none-nosecure-token-pqr678; Path=/; SameSite=None")
    )
    return resp


def start(port: int = 3000):
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(20):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health")
            break
        except Exception:
            time.sleep(0.2)
    return server


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=3000)
