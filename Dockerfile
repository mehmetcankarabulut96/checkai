FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Gerekli sistem araçlarını ve derleyicileri kur
RUN apt-get update && apt-get install -y \
    python3.11 \
    python3-pip \
    python3.11-dev \
    build-essential \
    pkg-config \
    libgl1-mesa-glx \
    libgles2 \
    libegl1-mesa \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Pip güncelleme
RUN python3 -m pip install --upgrade pip setuptools wheel

COPY requirements.txt .

# Önemli: Eğer requirements'da takılırsa zorlamayı bırakıp kurması için
RUN python3 -m pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python3", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]