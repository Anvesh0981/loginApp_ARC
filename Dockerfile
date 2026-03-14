FROM python:3.11-bookworm

# Install system dependencies for Chromium
RUN apt-get update && apt-get install -y \
    chromium \
    chromium-driver \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python packages including playwright
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install playwright browsers AFTER pip install
RUN python -m playwright install chromium
RUN python -m playwright install-deps chromium

# Set chromium path for playwright
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

COPY . .

CMD ["python", "server.py"]