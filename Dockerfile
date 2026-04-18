FROM python:3.11-slim

# Hata veren paket yerine 'libgl1' ve 'libglx-mesa0' ekledik
RUN apt-get update && apt-get install -y \
    libgl1 \
    libglx-mesa0 \
    libgles2 \
    libegl1-mesa \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000", "--workers", "1"]