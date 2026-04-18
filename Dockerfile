FROM python:3.11-slim

# Paket yükleme komutunu şu şekilde güncelle:
RUN apt-get update --fix-missing && apt-get install -y --fix-missing \
    libgl1-mesa-glx \
    libgles2 \
    libegl1-mesa \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Diğer adımlara devam et...
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]