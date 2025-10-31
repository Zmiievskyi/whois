FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    dnsutils \
    whois \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and source files
COPY app.py .
COPY setup.py .
COPY src/ src/
COPY env.example .env

# Create necessary directories
RUN mkdir -p results logs cache

# Set environment variables for better DNS resolution
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Expose Streamlit default port
EXPOSE 8501

# Add healthcheck for the intelligent DNS system
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Run Streamlit app with optimized settings
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true", "--server.fileWatcherType=none", "--server.maxUploadSize=50"]
