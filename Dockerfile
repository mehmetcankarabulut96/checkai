FROM ubuntu:22.04

# Etkileşimli soruları engelle ve Python yolunu sabitle
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# 1. Gerekli tüm sistem ve derleme kütüphanelerini kur
RUN apt-get update && apt-get install -y \
    python3.11 \
    python3-pip \
    python3.11-dev \
    build-essential \
    libgl1-mesa-glx \
    libgles2 \
    libegl1-mesa \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 2. Pip ve temel araçları güncelle
RUN python3 -m pip install --upgrade pip setuptools wheel

# 3. Bağımlılıkları tek tek veya dosyadan kur
COPY requirements.txt .
# Hata veren paketi bulmak için --no-cache-dir ekliyoruz
RUN python3 -m pip install --no-cache-dir -r requirements.txt

COPY . .

# Render portu ve başlatma
CMD ["python3", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]