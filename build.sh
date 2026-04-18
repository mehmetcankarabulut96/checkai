#!/usr/bin/env bash
# Herhangi bir hata oluşursa betiği durdurur
set -o errexit

# 1. Sistem paketlerini güncelle ve MediaPipe/OpenCV için gereken bağımlılıkları yükle
# Bu kısım libGLESv2, libGL ve libglib hatalarını çözer
apt-get update && apt-get install -y \
    libgl1-mesa-glx \
    libgles2 \
    libglib2.0-0

# 2. Pip ve temel kurulum araçlarını güncelle
python -m pip install --upgrade pip setuptools wheel

# 3. Bağımlılıkları kur
pip install -r requirements.txt