FROM ghcr.io/astral-sh/uv:0.12.1 AS uv
FROM python:3.12-slim
COPY --from=uv /uv /uvx /bin/
WORKDIR /app
ENV UV_NO_DEV=1
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project
COPY src ./src
COPY config ./config
RUN uv sync --locked --no-editable
ENV PATH="/app/.venv/bin:${PATH}"
EXPOSE 8000
CMD ["security-engine", "serve", "--host", "0.0.0.0", "--port", "8000"]
