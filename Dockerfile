# Web app image for the hosted demo. The sandbox step needs a Docker host, so it is off here
# (SLOPPROOF_SANDBOX=0); recorded sandbox runs are served from bench/results_sandbox.jsonl.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 user
COPY --from=ghcr.io/astral-sh/uv:0.12.15 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev
COPY web ./web
COPY bench ./bench
COPY examples ./examples
# Hosts such as Hugging Face Spaces run the container as uid 1000; it needs to write .cache (git clones).
RUN mkdir -p /app/.cache && chown -R user /app
USER user
ENV SLOPPROOF_SANDBOX=0 SLOPPROOF_DAILY_RUNS=40 HOST=0.0.0.0 PORT=7860
EXPOSE 7860
CMD ["/app/.venv/bin/slopproof-web"]
