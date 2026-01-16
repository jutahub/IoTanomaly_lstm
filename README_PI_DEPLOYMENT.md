# IoT Anomaly Detection System - Raspberry Pi Deployment

## Overview
This system detects anomalies in IoT device network traffic using an LSTM+RNN neural network with quantization for efficient execution on Raspberry Pi 5 with 8GB RAM.

## Installation

1. Clone this repository to your Raspberry Pi:
   ```bash
   git clone <repository-url>
   cd iot-anomaly-detection
   ```

2. Install system dependencies:
   ```bash
   sudo apt update
   sudo apt install -y python3-pip nmap
   ```

3. Install Python packages:
   ```bash
   pip3 install -r requirements.txt
   ```

4. If scapy installation fails, install additional dependencies:
   ```bash
   sudo apt install -y tcpdump libpcap-dev
   pip3 install scapy
   ```

## Configuration

The system is pre-configured for Raspberry Pi 5 with 8GB RAM. Key settings:
- Uses quantized model for efficient inference
- Optimized for ARM architecture
- Memory usage limited to prevent issues

## Running the System

### Option 1: Direct execution
```bash
python3 web_interface.py
```

### Option 2: Using the startup script
```bash
chmod +x startup_raspberry_pi.sh
./startup_raspberry_pi.sh
```

### Option 3: As a systemd service (recommended for automatic startup)
```bash
sudo cp iot-anomaly-detection.service /etc/systemd/system/
sudo systemctl enable iot-anomaly-detection.service
sudo systemctl start iot-anomaly-detection.service
```

The web interface will be available at http://<your-pi-ip>:5000

## Training the Model

To train the model with your own normal traffic data:
1. Place your CSV file with network traffic data in the root directory
2. Run the training script:
   ```bash
   python3 model_trainer.py
   ```
3. The trained model will be saved as 'iot_anomaly_model.h5'

## Performance Notes

- The system is optimized for continuous monitoring of multiple IoT devices
- Quantized model reduces memory usage and increases inference speed
- Default configuration monitors 60 packets at a time for anomaly detection
- Web interface allows configuration of monitored IPs and notification settings