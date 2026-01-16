# IoT Anomaly Detection System - Documentation

## Overview

The IoT Anomaly Detection System is a comprehensive solution for monitoring and securing IoT networks using advanced neural network techniques. The system leverages LSTM+RNN architectures to detect unusual patterns in network traffic that may indicate security threats.

## Architecture

### Components

1. **Network Scanner**: Discovers and monitors devices on the network
2. **Packet Capture**: Captures and analyzes network packets in real-time
3. **Neural Network Model**: LSTM+RNN model for anomaly detection
4. **Web Interface**: Dashboard for monitoring and configuration
5. **Notification System**: Alerts for detected anomalies
6. **Model Quantizer**: Optimizes models for edge deployment

### Data Flow

1. Network scanner discovers devices
2. Packet capture monitors traffic to/from selected devices
3. Raw packets are converted to feature vectors
4. Feature vectors are fed to the neural network
5. Network predicts normal vs anomalous behavior
6. Anomalies trigger alerts in the notification system
7. Results are displayed in the web interface

## Neural Network Architecture

The system uses a hybrid LSTM+RNN architecture:

- **Input Layer**: Sequences of 60 packets with 10 features each
- **LSTM Layer 1**: 64 units with dropout (20%) for temporal pattern recognition
- **LSTM Layer 2**: 32 units with dropout (20%) for deeper temporal analysis
- **RNN Layer**: 32 units with dropout (20%) for sequential processing
- **Dense Layer 1**: 50 units with ReLU activation
- **Output Layer**: Linear activation with same dimensions as input

## Configuration

### Web Interface

The web interface provides:

- Network scanning and device discovery
- Real-time monitoring dashboard
- Alert visualization
- System configuration options

### Model Training

Models can be trained using historical network data:

- Normal traffic patterns are used for training
- Anomaly detection threshold is determined during training
- Models can be retrained as network patterns evolve

## Deployment

### Local Development

1. Install dependencies: `pip install -r requirements.txt`
2. Run the application: `python main.py --mode web`
3. Access the dashboard at `http://localhost:5000`

### Raspberry Pi Deployment

The system is optimized for Raspberry Pi 5 with 8GB RAM:

1. Install system dependencies
2. Run the optimization script: `python main.py --mode optimize`
3. Start the service with appropriate configuration

## Security Features

- Continuous monitoring of network traffic
- Behavioral analysis for anomaly detection
- Automated alerting system
- Support for email and webhook notifications
- Threshold-based anomaly scoring

## Troubleshooting

### Common Issues

- **Permission Errors**: Ensure the application has network access permissions
- **Model Loading Failures**: Verify TensorFlow installation and model file integrity
- **Network Scanning Failures**: Check that nmap and arp-scan are installed

### Performance Tuning

- Adjust packet capture buffer sizes for high-traffic networks
- Tune neural network batch sizes for optimal performance
- Configure appropriate alert thresholds to minimize false positives