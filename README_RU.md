# Система обнаружения аномалий IoT устройств

Комплексное решение для безопасности сетей IoT, использующее нейронные сети LSTM+RNN для обнаружения аномалий в сетевом трафике. Разработана для развертывания на Raspberry Pi с оптимизацией для ресурсоограниченных сред.

## Особенности

- Мониторинг сетевого трафика в реальном времени
- Нейронная сеть LSTM+RNN для обнаружения аномалий
- Веб-интерфейс для мониторинга и настройки
- Автоматическое обнаружение угроз и оповещение
- Оптимизация для Raspberry Pi
- Квантованные модели для эффективного вывода

## Структура проекта

```
iot-anomaly-detection/
├── src/                    # Исходный код
│   ├── lstm_rnn_anomaly_detection.py    # Основная реализация нейронной сети
│   ├── packet_capture.py               # Функциональность захвата сетевых пакетов
│   ├── anomaly_detection_integration.py # Интеграционный уровень
│   ├── model_trainer.py                # Обучение модели
│   ├── model_quantizer.py              # Квантование модели для устройств
│   ├── csv_data_processor.py           # Утилиты обработки данных
│   ├── device_specific_analyzer.py     # Анализ специфичный для устройства
│   ├── notification_system.py          # Система оповещений
│   ├── web_interface.py                # Веб-приложение Flask
│   └── raspberry_pi_optimizer.py       # Скрипты оптимизации Raspberry Pi
├── models/                 # Обученные файлы моделей
├── data/                   # Образцы и тренировочные данные
├── docs/                   # Документация
├── tests/                  # Модульные и интеграционные тесты
├── scripts/                # Служебные скрипты
├── Dockerfile             # Docker конфигурация
├── docker-compose.yml     # Docker Compose конфигурация
├── requirements.txt       # Зависимости Python
├── README.md              # Документация проекта
└── main.py                # Главная точка входа приложения
```

## Установка и запуск

### Локальная установка

1. Клонируйте репозиторий:
```bash
git clone https://github.com/yourusername/iot-anomaly-detection.git
cd iot-anomaly-detection
```

2. Создайте виртуальное окружение:
```bash
python3 -m venv venv
source venv/bin/activate  # На Windows: venv\Scripts\activate
```

3. Установите зависимости:
```bash
pip install -r requirements.txt
```

4. Установите дополнительные системные зависимости (для сканирования сети):
```bash
# На Ubuntu/Debian:
sudo apt-get install nmap arp-scan tcpdump libpcap-dev

# На CentOS/RHEL:
sudo yum install nmap arp-scan tcpdump libpcap-dev

# На macOS:
brew install nmap arp-scan tcpdump libpcap-dev
```

### Запуск с помощью Docker (рекомендуется)

1. Установите Docker и Docker Compose

2. Соберите и запустите контейнер:
```bash
docker-compose up --build
```

3. Приложение будет доступно по адресу `http://localhost:5000`

#### Альтернативный способ запуска Docker:

```bash
# Сборка образа
docker build -t iot-anomaly-detection .

# Запуск контейнера
docker run -p 5000:5000 --cap-add=NET_ADMIN --cap-add=NET_RAW -d iot-anomaly-detection
```

## Использование

### Запуск приложения

1. Запустите веб-интерфейс:
```bash
python main.py --mode web --port 5000
```

2. Откройте веб-интерфейс по адресу `http://localhost:5000`

### Обучение новой модели

```bash
python main.py --mode train --data-path data/training_data.csv --model-path models/my_model.h5
```

### Запуск тестов

```bash
python main.py --mode test
```

### Оптимизация для Raspberry Pi

```bash
python main.py --mode optimize
```

## Архитектура нейронной сети

Система использует гибридную архитектуру LSTM+RNN:

- **Слои LSTM**: Захватывают временные зависимости в сетевом трафике
- **Слой RNN**: Обрабатывает последовательные данные для распознавания паттернов
- **Полносвязные слои**: Окончательная классификация и оценка аномалий
- **Квантование**: Оптимизация модели для граничного развертывания

## Функции безопасности

- Постоянный мониторинг сетевого трафика
- Анализ поведения для обнаружения аномалий
- Автоматическая система оповещений
- Поддержка email и webhook уведомлений
- Пороговая оценка аномалий

## Развертывание на Raspberry Pi

Система оптимизирована для Raspberry Pi 5 с 8 ГБ ОЗУ:

1. Установите системные зависимости:
```bash
sudo apt update
sudo apt install -y python3-pip nmap arp-scan tcpdump libpcap-dev
```

2. Установите зависимости Python:
```bash
pip3 install -r requirements.txt
```

3. Запустите скрипт оптимизации:
```bash
python main.py --mode optimize
```

4. Запустите сервис:
```bash
python main.py --mode web --port 80
```

## Конфигурация

Приложение поддерживает несколько параметров конфигурации:

- `--mode`: Режим работы (web, train, test, optimize)
- `--model-path`: Путь к файлу обученной модели
- `--tflite-model-path`: Путь к квантованной модели TFLite
- `--data-path`: Путь к CSV файлу с тренировочными данными
- `--interface`: Интерфейс для мониторинга сети
- `--port`: Порт для веб-интерфейса

## Docker инструкции

### Сборка образа

```bash
docker build -t iot-anomaly-detection .
```

### Запуск контейнера

```bash
# Запуск в фоне
docker run -d -p 5000:5000 --cap-add=NET_ADMIN --cap-add=NET_RAW --name iot-anomaly-detector iot-anomaly-detection

# Запуск в интерактивном режиме
docker run -it -p 5000:5000 --cap-add=NET_ADMIN --cap-add=NET_RAW iot-anomaly-detection
```

### Использование Docker Compose

```bash
# Запуск всех сервисов
docker-compose up

# Запуск в фоне
docker-compose up -d

# Остановка сервисов
docker-compose down
```

### Просмотр логов

```bash
docker logs iot-anomaly-detector
docker-compose logs
```

## Вклад в развитие

1. Форкните репозиторий
2. Создайте ветку фичи (`git checkout -b feature/awesome-feature`)
3. Зафиксируйте изменения (`git commit -m 'Add awesome feature'`)
4. Запушьте в ветку (`git push origin feature/awesome-feature`)
5. Откройте Pull Request

## Лицензия

Этот проект лицензирован по лицензии MIT - см. файл LICENSE для подробностей.

## Благодарности

- Создано с использованием TensorFlow для возможностей нейронной сети
- Использует Flask для веб-интерфейса
- Сканирование сети работает на nmap и arp-scan