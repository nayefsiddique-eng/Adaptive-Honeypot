# Build stage for Python runtime
FROM python:3.12-slim

# Set system environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

# Set work directory
WORKDIR /app

# Install system dependencies and build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python requirements
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Remove build-essential after installation to keep the runtime clean
RUN apt-get purge -y --auto-remove build-essential && rm -rf /var/lib/apt/lists/*

# Create a non-root system user and group to run the application
RUN groupadd -r praetor && useradd -r -g praetor -d /app -s /sbin/nologin praetor

# Copy codebase (ensure .env is excluded via .dockerignore or docker run)
COPY . /app/

# Generate heuristic fallback model structure
RUN python ml/train_classifier.py || true

# Pre-generate SSH host key for read-only filesystem support
RUN python -c 'import os, asyncssh; key = asyncssh.generate_private_key("ssh-rsa"); os.makedirs("backend/honeypot", exist_ok=True); key.write_private_key("backend/honeypot/ssh_host_key")' || true

# Change ownership of the runtime application directory to the non-root user
RUN chown -R praetor:praetor /app

# Run as non-root
USER praetor

# Expose port (default FastAPI management port)
EXPOSE 8000

# Start server using host from config/settings binding by default to localhost (127.0.0.1)
# Note: For production container deployments, this can be configured via environment settings.
CMD ["uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8000"]

