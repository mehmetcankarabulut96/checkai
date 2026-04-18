FROM python:3.11-slim

# Paket isimlerini Debian 12 uyumlu hale getirdik
RUN apt-get update && apt-get install -y \
    libgl1 \
    libglx-mesa0 \
    libgles2 \
    libegl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

# Render'da 10000 portu standarttır
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000", "--workers", "1"]