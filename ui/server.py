"""
FastAPI Server hosting loopback web dashboard on http://127.0.0.1:8000
"""

import os
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from blindagent.pipeline import BlindPipeline
from blindagent.sss import ShamirSecretSharing
from blindagent.crypto_bridge import engine_version

app = FastAPI(title="BlindAgent Loopback Dashboard")

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

pipeline = BlindPipeline(sss_threshold=3, sss_total=5)


class ExecuteRequest(BaseModel):
    prompt: str
    system_prompt: Optional[str] = None
    threshold: Optional[int] = 3
    total_shares: Optional[int] = 5


class SSSSplitRequest(BaseModel):
    secret: str
    k: int = 3
    n: int = 5


class SSSCombineRequest(BaseModel):
    shares: List[str]
    k: int = 3


@app.get("/api/status")
def get_status():
    current_pipeline = BlindPipeline(sss_threshold=3, sss_total=5)
    return {
        "status": "online",
        "engine": engine_version(),
        "default_k": 3,
        "default_n": 5,
        "provider": current_pipeline.llm.provider,
        "active_model": current_pipeline.llm.active_model,
        "has_gemini_key": bool(current_pipeline.llm.api_key)
    }


@app.post("/api/execute")
def execute_pipeline(req: ExecuteRequest):
    if not req.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")
    
    # Configure custom threshold if provided
    local_pipeline = BlindPipeline(
        sss_threshold=req.threshold or 3,
        sss_total=req.total_shares or 5
    )
    result = local_pipeline.execute(req.prompt, req.system_prompt)
    
    vault_dump = []
    for token, entity in local_pipeline.blinder.vault.items():
        vault_dump.append({
            "token": token,
            "entity_type": entity.entity_type,
            "original_value": entity.reconstruct_secret(local_pipeline.blinder.sss),
            "ciphertext_hex": entity.ciphertext_hex,
            "alpha": entity.blind_alpha,
            "beta": entity.blind_beta,
            "shares": entity.shares
        })

    return {
        "user_input": result.user_input,
        "wire_payload": result.wire_payload,
        "host_raw_response": result.host_raw_response,
        "final_output": result.final_output,
        "execution_time_ms": result.execution_time_ms,
        "metrics": result.metrics,
        "provider": result.provider_used,
        "active_model": local_pipeline.llm.active_model,
        "last_error": local_pipeline.llm.last_error,
        "vault": vault_dump
    }


@app.post("/api/sss/split")
def sss_split_endpoint(req: SSSSplitRequest):
    try:
        sss = ShamirSecretSharing(threshold=req.k, total_shares=req.n)
        shares = sss.split_text(req.secret)
        return {"k": req.k, "n": req.n, "shares": shares}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/sss/combine")
def sss_combine_endpoint(req: SSSCombineRequest):
    try:
        sss = ShamirSecretSharing(threshold=req.k, total_shares=max(req.k, len(req.shares)))
        recovered = sss.combine_text(req.shares)
        return {"recovered": recovered}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/")
def serve_index():
    index_path = os.path.join(_STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Static frontend not found at " + index_path}


if os.path.exists(_STATIC_DIR):
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


def run_server(host: str = "127.0.0.1", port: int = 8000):
    test_p = BlindPipeline(sss_threshold=3, sss_total=5)
    print("\n=======================================================")
    print("       BlindAgent Web Dashboard Server Starting        ")
    print("=======================================================")
    print(f"✔ Cryptographic Engine: {engine_version()}")
    if test_p.llm.provider == "gemini":
        k_disp = test_p.llm.api_key[:6] + "..." + test_p.llm.api_key[-4:] if test_p.llm.api_key else ""
        print(f"✔ Cloud LLM Active: Google Gemini API (Live Mode | Key: {k_disp})")
    elif test_p.llm.provider == "openai":
        print("✔ Cloud LLM Active: OpenAI API (Live Mode)")
    else:
        print("ℹ Cloud LLM: Local Host Simulator (Offline)")
        print("  To use live Gemini: export GEMINI_API_KEY=\"...\" or create a .env file")
    print(f"🌐 Access Dashboard at: http://{host}:{port}")
    print("=======================================================\n")
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
