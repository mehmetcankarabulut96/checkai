# Kararlı Python 3.11 tabanı
FROM python:3.11-slim

# MediaPipe ve OpenCV için hayati önem taşıyan sistem kütüphaneleri
# Bu katman, "libGLESv2.so.2 not found" hatasını kalıcı olarak çözer
RUN apt-get update && apt-get install -y \
    libgl1-mesa-glx \
    libgles2 \
    libegl1-mesa \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Çalışma dizini
WORKDIR /app

# Önce bağımlılıkları kopyalayıp kuruyoruz (Docker önbelleği için)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Kaynak kodun tamamını kopyala
COPY . .

# Render varsayılan portu 10000'dir. Uygulamayı uvicorn ile başlatıyoruz.
# Workers sayısını 1 tutmak MediaPipe'ın bellek kullanımı için daha güvenlidir.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000", "--workers", "1"]