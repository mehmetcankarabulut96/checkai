# Kararlı ve hafif Python 3.11 imajı
FROM python:3.11-slim

# MediaPipe ve OpenCV'nin ihtiyaç duyduğu sistem kütüphanelerini kur
# libGLESv2, libEGL ve libGL hatalarını bu katman çözer
RUN apt-get update && apt-get install -y \
    libgl1-mesa-glx \
    libgles2 \
    libegl1-mesa \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Uygulama dizinini oluştur
WORKDIR /app

# Önce sadece bağımlılıkları kopyalayıp kurmak (Docker Cache avantajı sağlar)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Proje kodlarını kopyala
COPY . .

# Render genellikle 10000 portunu kullanır
# Workers sayısını 1 tutmak MediaPipe bellek kullanımı için daha güvenlidir
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000", "--workers", "1"]