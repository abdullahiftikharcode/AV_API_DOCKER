FROM python:3.11-slim

# Install Docker CLI and other system dependencies
RUN apt-get update && apt-get install -y \
    dos2unix \
    libmagic1 \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y docker-ce-cli \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set up Python environment
WORKDIR /app

# Copy API requirements (lightweight - no ML dependencies)
COPY docker/requirements-api.txt .

# Install API dependencies (fast, lightweight)
RUN pip install -r requirements-api.txt --timeout 120 --index-url https://pypi.org/simple

# Copy application code (API container doesn't need ML models or rules)
COPY app app/

# Create startup script for API container
RUN echo '#!/bin/bash\n\
# Start FastAPI application with optimized async configuration for concurrent requests\n\
exec uvicorn app.main:app --host 0.0.0.0 --port 8080 --loop asyncio --limit-concurrency 100\n\
' > /start.sh && chmod +x /start.sh

# Set the default command
CMD ["/start.sh"]