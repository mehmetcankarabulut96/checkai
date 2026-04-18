# Debian yerine Ubuntu kullanıyoruz
FROM ubuntu:22.04

# Etkileşimli soruları kapat
ENV DEBIAN_FRONTEND=noninteractive

# Python ve gerekli sistem kütüphanelerini kur
RUN apt-get update && apt-get install -y \
    python3.11 \
    python3-pip \
    libgl1-mesa-glx \
    libgles2 \
    libegl1-mesa \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Bağımlılıkları kur
RUN pip3 install --upgrade pip setuptools wheel
RUN pip3 install -r requirements.txt

# Çalıştırma komutu (python3 ve uvicorn yolu önemli)
CMD ["python3", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]