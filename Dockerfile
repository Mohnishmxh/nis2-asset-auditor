# Stage 1: Build the Smart Frontend SPA
FROM node:22-alpine AS frontend-builder
WORKDIR /build
COPY frontend/package*.json ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY frontend/ ./
RUN npm run build

# Stage 2: Slim Debian/Python runtime with Nmap
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY main.py .
COPY --from=frontend-builder /build/dist ./frontend/dist
RUN mkdir -p /app/reports /app/data

EXPOSE 8000

ENTRYPOINT ["python", "main.py"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
