FROM python:3.11-bookworm

# System deps for Chromium + virtual display + VNC
RUN apt-get update && apt-get install -y \
    chromium chromium-driver \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libgbm1 libasound2 \
    xvfb x11vnc novnc websockify \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN python -m playwright install chromium
RUN python -m playwright install-deps chromium

ENV DISPLAY=:99
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

COPY . .

CMD ["python", "server.py"]