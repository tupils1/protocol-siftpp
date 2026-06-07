FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy

COPY pyproject.toml uv.lock README.md LICENSE .python-version ./
COPY src ./src

RUN uv sync --frozen --no-dev

CMD ["sh", "-lc", ".venv/bin/siftpp-demo --out analysis/demo && .venv/bin/siftpp-spoliation-test --out analysis/spoliation && .venv/bin/siftpp-tamper-test --audit analysis/demo/audit.jsonl --out analysis/tamper"]
