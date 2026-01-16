# Запуск системы обнаружения аномалий IoT с помощью Docker

## Обзор

Этот документ описывает, как запустить систему обнаружения аномалий IoT с помощью Docker и Docker Compose.

## Предварительные требования

- Docker (версия 18.09 или выше)
- Docker Compose (версия 1.21 или выше)
- Git

## Сборка и запуск с помощью Docker Compose (рекомендуется)

### 1. Клонирование репозиттория

```bash
git clone https://github.com/yourusername/iot-anomaly-detection.git
cd iot-anomaly-detection
```

### 2. Запуск с помощью Docker Compose

```bash
# Сборка и запуск всех сервисов (в фоновом режиме)
docker-compose up --build -d

# Проверка состояния контейнеров
docker-compose ps

# Просмотр логов
docker-compose logs -f
```

После запуска приложение будет доступно по адресу `http://localhost:5000`.

### 3. Остановка сервисов

```bash
# Остановка и удаление контейнеров
docker-compose down

# Остановка с сохранением данных
docker-compose stop
```

## Запуск с помощью Docker (вручную)

### 1. Сборка образа

```bash
# Сборка Docker образа
docker build -t iot-anomaly-detection .
```

### 2. Запуск контейнера

```bash
# Запуск контейнера в фоновом режиме
docker run -d \
  --name iot-anomaly-detector \
  -p 5000:5000 \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  iot-anomaly-detection

# Проверка состояния контейнера
docker ps

# Просмотр логов
docker logs -f iot-anomaly-detector
```

### 3. Остановка контейнера

```bash
# Остановка контейнера
docker stop iot-anomaly-detector

# Удаление контейнера
docker rm iot-anomaly-detector
```

## Параметры запуска в Docker

### Переменные окружения

Вы можете передать переменные окружения в контейнер:

```bash
docker run -d \
  --name iot-anomaly-detector \
  -p 5000:5000 \
  -e MODE=web \
  -e PORT=5000 \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  iot-anomaly-detection
```

### Монтирование томов

Для сохранения данных между запусками рекомендуется использовать тома:

```bash
docker run -d \
  --name iot-anomaly-detector \
  -p 5000:5000 \
  -v $(pwd)/models:/app/models \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  iot-anomaly-detection
```

## Docker Compose детали

Файл `docker-compose.yml` содержит следующую конфигурацию:

```yaml
version: '3.8'

services:
  iot-anomaly-detection:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./models:/app/models
      - ./data:/app/data
      - ./logs:/app/logs
    privileged: true  # Требуется для доступа к сети
    cap_add:
      - NET_ADMIN
      - NET_RAW
    environment:
      - PYTHONPATH=/app/src
    command: python main.py --mode web --port 5000
```

### Запуск разных режимов

Вы можете изменить режим запуска, изменив команду в docker-compose.yml:

```yaml
# Для режима обучения
command: python main.py --mode train --data-path data/training_data.csv

# Для режима тестирования
command: python main.py --mode test

# Для режима оптимизации
command: python main.py --mode optimize
```

## Устранение неполадок

### Проблемы с сетевым доступом

Если вы сталкиваетесь с проблемами доступа к сети внутри контейнера:

1. Убедитесь, что добавлены права `NET_ADMIN` и `NET_RAW`
2. Попробуйте использовать `--privileged` флаг (менее безопасно)
3. Проверьте, что хост-система имеет соответствующие разрешения

### Проблемы с производительностью

Если контейнер использует слишком много ресурсов:

```bash
# Ограничение использования ресурсов
docker run -d \
  --name iot-anomaly-detector \
  -p 5000:5000 \
  --memory=2g \
  --cpus=1.0 \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  iot-anomaly-detection
```

### Проверка состояния контейнера

```bash
# Проверка использования ресурсов
docker stats iot-anomaly-detector

# Вход в работающий контейнер
docker exec -it iot-anomaly-detector /bin/bash
```

## Продвинутые примеры

### Запуск с пользовательской конфигурацией

```bash
# Создание пользовательского compose файла
cat > docker-compose.prod.yml << EOF
version: '3.8'

services:
  iot-anomaly-detection:
    build: .
    ports:
      - "80:5000"
    volumes:
      - ./models:/app/models
      - ./data:/app/data
      - ./logs:/app/logs
    environment:
      - MODE=web
      - PORT=5000
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
      - NET_RAW
    command: python main.py --mode web --port 5000
EOF

# Запуск с пользовательским файлом
docker-compose -f docker-compose.prod.yml up -d
```

### Масштабирование (если применимо)

```bash
# Запуск нескольких экземпляров (если приложение поддерживает)
docker-compose up --scale iot-anomaly-detection=3
```

## Безопасность

- Не запускайте контейнер с `--privileged` если это не обязательно
- Ограничьте права доступа к минимально необходимым (`NET_ADMIN`, `NET_RAW`)
- Регулярно обновляйте базовый образ и зависимости
- Используйте тома для хранения важных данных вне контейнера