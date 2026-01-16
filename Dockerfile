FROM python:3.9-slim

# Установка системных зависимостей
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    net-tools \
    nmap \
    arp-scan \
    tcpdump \
    libpcap-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Установка рабочей директории
WORKDIR /app

# Копирование файлов зависимостей
COPY requirements.txt .

# Установка Python зависимостей
RUN pip install --no-cache-dir -r requirements.txt

# Копирование исходного кода
COPY . .

# Создание необходимых директорий
RUN mkdir -p models data logs

# Экспорт портов
EXPOSE 5000

# Установка прав на выполнение для скриптов
RUN chmod +x /app/scripts/run_app.py

# Команда по умолчанию
CMD ["python", "main.py", "--mode", "web", "--port", "5000"]