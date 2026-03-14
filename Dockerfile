FROM python:3.11-bookworm

RUN apt-get update && apt-get install -y \
    chromium \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

COPY . .

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["gunicorn app:app --bind 0.0.0.0:${PORT:-8080} --workers 2 --timeout 300"]