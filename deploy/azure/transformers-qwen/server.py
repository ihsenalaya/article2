#!/usr/bin/env python3
"""Minimal HTTP server for Qwen2.5-7B-Instruct via plain HuggingFace
Transformers/PyTorch -- the replacement H100 workload after the vLLM
investigation found HF Transformers produces correct output on this exact hardware while
vLLM 0.26.0 does not (root cause not vLLM-specific-model, not fully
resolved; vLLM was dropped from the primary workload rather than pursued
further).

No web framework dependency (stdlib http.server only) to keep the image
small and the dependency surface auditable. Endpoints intentionally mirror
the previous vLLM pod's shape (/health, service on port 8000) so the rest
of the security-experiment tooling (attacker-gpu's forbidden-connect probe,
readinessProbe, mint-test-decision target) does not need to change.
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

MODEL_DIR = os.environ.get("MODEL_DIR", "/models/Qwen2.5-7B-Instruct")
PORT = int(os.environ.get("PORT", "8000"))

_state = {"ready": False, "tokenizer": None, "model": None, "lock": threading.Lock()}


def load_model():
    print(f"loading tokenizer/model from {MODEL_DIR} ...", flush=True)
    tok = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForCausalLM.from_pretrained(MODEL_DIR, dtype=torch.bfloat16, device_map="cuda")
    model.eval()
    _state["tokenizer"] = tok
    _state["model"] = model
    _state["ready"] = True
    print("model ready", flush=True)


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            if _state["ready"]:
                self._send_json(200, {"status": "ready"})
            else:
                self._send_json(503, {"status": "loading"})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/generate":
            self._send_json(404, {"error": "not found"})
            return
        if not _state["ready"]:
            self._send_json(503, {"error": "model not ready"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            req = json.loads(raw)
            prompt = req["prompt"]
            max_new_tokens = int(req.get("max_tokens", 40))
            temperature = float(req.get("temperature", 0.0))
        except Exception as e:
            self._send_json(400, {"error": f"bad request: {e}"})
            return

        tok = _state["tokenizer"]
        model = _state["model"]
        with _state["lock"]:
            inputs = tok(prompt, return_tensors="pt").to("cuda")
            with torch.no_grad():
                gen = model.generate(
                    **inputs,
                    max_new_tokens=max_new_tokens,
                    do_sample=temperature > 0.0,
                    temperature=temperature if temperature > 0.0 else None,
                )
            text = tok.decode(gen[0, inputs.input_ids.shape[1]:], skip_special_tokens=True)
        self._send_json(200, {"text": text})

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}", flush=True)


if __name__ == "__main__":
    threading.Thread(target=load_model, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"listening on :{PORT}", flush=True)
    server.serve_forever()
