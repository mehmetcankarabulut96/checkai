#!/usr/bin/env bash
# Hata durumunda dur
set -o errexit

# Sistem kütüphanelerini güncelle ve eksik olanları yükle
# Bu satır libGLESv2 ve libGL hatalarını çözer
apt-get update && apt-get install -y libgl1-mesa-glx libgles2 libglib2.0-0

# Bağımlılıkları kur
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt