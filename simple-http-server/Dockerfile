FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /app
COPY . .

CMD ["uv", "run", "--script", "simple-http-server.py", "-i", "1"]
