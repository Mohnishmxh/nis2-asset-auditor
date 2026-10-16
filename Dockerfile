# Use an official, deterministic slim Python base image to minimize attack surface
FROM python:3.12-slim-bookworm

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install the Nmap binary in a single layer and clean apt caches
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first to leverage Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and create reports directory
COPY src/ ./src/
COPY main.py .
RUN mkdir -p /app/reports

# Define the CLI entrypoint and default arguments
ENTRYPOINT ["python", "main.py"]
CMD ["-t", "127.0.0.1", "-p", "22,80,443,8000"]