# IoT Anomaly Detection System

A comprehensive IoT network security solution that uses LSTM+RNN neural networks to detect anomalies in network traffic. Designed for deployment on Raspberry Pi with optimization for resource-constrained environments.

## Features

- Real-time network traffic monitoring
- LSTM+RNN neural network for anomaly detection
- Web-based dashboard for monitoring and configuration
- Automated threat detection and alerting
- Raspberry Pi optimized deployment
- Quantized models for efficient inference

## Project Structure

```
iot-anomaly-detection/
├── src/                    # Source code files
│   ├── lstm_rnn_anomaly_detection.py    # Core neural network implementation
│   ├── packet_capture.py               # Network packet capture functionality
│   ├── anomaly_detection_integration.py # Integration layer
│   ├── model_trainer.py                # Model training functionality
│   ├── model_quantizer.py              # Model quantization for edge devices
│   ├── csv_data_processor.py           # Data processing utilities
│   ├── device_specific_analyzer.py     # Device-specific analysis
│   ├── notification_system.py          # Alert and notification system
│   ├── web_interface.py                # Flask web application
│   └── raspberry_pi_optimizer.py       # Raspberry Pi optimization scripts
├── models/                 # Trained model files
├── data/                   # Sample and training data
├── docs/                   # Documentation
├── tests/                  # Unit and integration tests
├── scripts/                # Utility scripts
├── requirements.txt        # Python dependencies
├── README.md              # Project documentation
└── main.py                # Main application entry point
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/iot-anomaly-detection.git
cd iot-anomaly-detection
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install additional system dependencies (for network scanning):
```bash
# On Ubuntu/Debian:
sudo apt-get install nmap arp-scan

# On CentOS/RHEL:
sudo yum install nmap arp-scan

# On macOS:
brew install nmap arp-scan
```

## Usage

### Running the Application

1. Start the web interface:
```bash
python main.py --mode web --port 5000
```

2. Access the dashboard at `http://localhost:5000`

### Training a New Model

```bash
python main.py --mode train --data-path data/training_data.csv --model-path models/my_model.h5
```

### Running Tests

```bash
python main.py --mode test
```

### Raspberry Pi Optimization

```bash
python main.py --mode optimize
```

## Configuration

The application supports several configuration options:

- `--mode`: Operation mode (web, train, test, optimize)
- `--model-path`: Path to the trained model file
- `--tflite-model-path`: Path to the quantized TFLite model
- `--data-path`: Path to the training data CSV file
- `--interface`: Network interface to monitor
- `--port`: Port for the web interface

## Neural Network Architecture

The system uses a hybrid LSTM+RNN architecture:

- **LSTM Layers**: Capture temporal dependencies in network traffic
- **RNN Layer**: Processes sequential data for pattern recognition
- **Dense Layers**: Final classification and anomaly scoring
- **Quantization**: Model optimized for edge deployment

## Security Features

- Continuous network monitoring
- Behavioral analysis for anomaly detection
- Automated alerting system
- Support for email and webhook notifications
- Threshold-based anomaly scoring

## Deployment on Raspberry Pi

The system is optimized for Raspberry Pi 5 with 8GB RAM:

1. Install system dependencies:
```bash
sudo apt update
sudo apt install -y python3-pip nmap arp-scan tcpdump libpcap-dev
```

2. Install Python dependencies:
```bash
pip3 install -r requirements.txt
```

3. Run the optimization script:
```bash
python main.py --mode optimize
```

4. Start the service:
```bash
python main.py --mode web --port 80
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

