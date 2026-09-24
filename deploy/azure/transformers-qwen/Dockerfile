# UNVERIFIED DRAFT -- written 2026-08-09, not yet built or run. Pins the
# exact torch/CUDA build already empirically proven to work on this exact
# H100 confidential VM (torch 2.11.0+cu130, driver 595.71.05, driver
# CUDA 13.2) instead of trusting an arbitrary base image tag, since the
# whole point of dropping vLLM is to stop debugging the inference stack --
# this must work on the first real try (TASK-16/17), not become its own
# investigation.
FROM python:3.12-slim

RUN pip install --no-cache-dir \
    torch==2.11.0+cu130 --index-url https://download.pytorch.org/whl/cu130 \
    && pip install --no-cache-dir transformers accelerate

COPY server.py /server.py

EXPOSE 8000
CMD ["python3", "/server.py"]
