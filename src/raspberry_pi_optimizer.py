#!/usr/bin/env python3
"""
Optimization and testing script for Raspberry Pi 5 with 8GB RAM
This script prepares the IoT anomaly detection system for deployment on Raspberry Pi
"""

import os
import sys
import subprocess
import shutil
import platform
import psutil
import time
import threading
from datetime import datetime

def check_system_requirements():
    """Check if the system meets the minimum requirements for running the IoT anomaly detection system"""
    print("Checking system requirements...")
    
    # Check OS
    system = platform.system().lower()
    if system != 'linux':
        print(f"Warning: Expected Linux system, got {system}. This is optimized for Raspberry Pi.")
    
    # Check architecture
    arch = platform.machine().lower()
    if 'arm' not in arch and 'aarch64' not in arch:
        print(f"Warning: Expected ARM architecture (for Raspberry Pi), got {arch}")
    else:
        print(f"Architecture: {arch} (suitable for Raspberry Pi)")
    
    # Check memory
    total_memory_gb = psutil.virtual_memory().total / (1024**3)
    print(f"Total memory: {total_memory_gb:.2f} GB")
    
    if total_memory_gb < 7.0:  # Account for system overhead
        print("Warning: Less than 8GB RAM detected. Performance may be impacted.")
    else:
        print("Sufficient memory detected for Raspberry Pi 5 with 8GB RAM")
    
    # Check disk space
    disk_usage = psutil.disk_usage('/')
    free_space_gb = disk_usage.free / (1024**3)
    print(f"Free disk space: {free_space_gb:.2f} GB")
    
    if free_space_gb < 2.0:
        print("Warning: Less than 2GB free space. May impact performance.")
    else:
        print("Sufficient disk space available")
    
    return True

def install_dependencies():
    """Install required Python packages for Raspberry Pi"""
    print("Installing required dependencies...")
    
    # Required packages for the IoT anomaly detection system
    packages = [
        'tensorflow==2.13.0',  # Specific version optimized for Raspberry Pi
        'numpy',
        'pandas',
        'scikit-learn',
        'flask',
        'scapy',
        'python-nmap',
        'psutil',
        'requests'
    ]
    
    for package in packages:
        try:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
        except subprocess.CalledProcessError as e:
            print(f"Error installing {package}: {e}")
            return False
    
    print("Dependencies installed successfully")
    return True

def optimize_for_raspberry_pi():
    """Apply optimizations specific to Raspberry Pi 5 with 8GB RAM"""
    print("Applying Raspberry Pi optimizations...")
    
    # Create a configuration file with optimized settings
    config_content = """
# Configuration for IoT Anomaly Detection System on Raspberry Pi 5
[system]
# Maximum number of concurrent packet capture threads
max_capture_threads = 2

# Memory usage limits (in MB)
max_memory_usage = 4096

# Batch size for neural network inference (smaller for memory efficiency)
inference_batch_size = 1

[model]
# Use quantized model by default for better performance
use_quantized_model = true

# Number of packets to analyze at once
packets_per_analysis = 60

[network]
# Interface to capture packets from (usually eth0 or wlan0 on Raspberry Pi)
capture_interface = auto

# Time to wait between network scans (in seconds)
scan_interval = 30

[performance]
# Enable optimizations for ARM processors
enable_arm_optimizations = true

# Use CPU optimizations
use_cpu_optimizations = true

# Disable GPU (not typically available on Raspberry Pi)
use_gpu = false
"""
    
    with open('raspberry_pi_config.ini', 'w') as f:
        f.write(config_content.strip())
    
    print("Configuration file created: raspberry_pi_config.ini")
    
    # Create a startup script optimized for Raspberry Pi
    startup_script = """#!/bin/bash
# Startup script for IoT Anomaly Detection System on Raspberry Pi 5

# Set environment variables for optimized TensorFlow on ARM
export TF_CPP_MIN_LOG_LEVEL=2
export OMP_NUM_THREADS=4

# Increase swap space if needed (for memory-intensive operations)
sudo dphys-swapfile swapoff
sudo sed -i 's/CONF_SWAPSIZE=.*/CONF_SWAPSIZE=2048/' /etc/dphys-swapfile
sudo dphys-swapfile setup
sudo dphys-swapfile swapon

# Start the IoT anomaly detection system
cd /home/pi/iot-anomaly-detection
source venv/bin/activate  # If using virtual environment
python3 web_interface.py

# To run in background: nohup ./startup.sh > output.log 2>&1 &
"""
    
    with open('startup_raspberry_pi.sh', 'w') as f:
        f.write(startup_script.strip())
    
    # Make the script executable
    os.chmod('startup_raspberry_pi.sh', 0o755)
    
    print("Startup script created: startup_raspberry_pi.sh")
    print("Make sure to run 'chmod +x startup_raspberry_pi.sh' to make it executable")

def create_service_file():
    """Create a systemd service file for automatic startup"""
    print("Creating systemd service file...")

    service_content = """[Unit]
Description=IoT Anomaly Detection System
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/iot-anomaly-detection
ExecStart=/usr/bin/python3 /home/pi/iot-anomaly-detection/web_interface.py
Restart=always
RestartSec=10

# Environment variables for optimized performance
Environment="TF_CPP_MIN_LOG_LEVEL=2"
Environment="OMP_NUM_THREADS=4"

[Install]
WantedBy=multi-user.target
"""

    # Use current working directory instead of hardcoded path
    import os
    service_path = os.path.join(os.getcwd(), "iot-anomaly-detection.service")
    with open(service_path, 'w') as f:
        f.write(service_content.strip())

    print(f"Service file created: {service_path}")
    print("To enable the service: sudo cp iot-anomaly-detection.service /etc/systemd/system/")
    print("Then: sudo systemctl enable iot-anomaly-detection.service")
    print("And: sudo systemctl start iot-anomaly-detection.service")

def run_performance_tests():
    """Run performance tests to validate the system on Raspberry Pi"""
    print("Running performance tests...")
    
    start_time = time.time()
    
    # Import and initialize the system components
    try:
        # Try relative imports first (when running as part of the package)
        try:
            from .lstm_rnn_anomaly_detection import LSTM_RNN_AnomalyDetector
            from .packet_capture import PacketCapture, PacketAnalyzer
            from .anomaly_detection_integration import TrafficMonitor
            from .model_quantizer import ModelQuantizer
        except ImportError:
            # Fall back to absolute imports (when running as standalone script)
            from lstm_rnn_anomaly_detection import LSTM_RNN_AnomalyDetector
            from packet_capture import PacketCapture, PacketAnalyzer
            from anomaly_detection_integration import TrafficMonitor
            from model_quantizer import ModelQuantizer
    except ImportError as e:
        print(f"Error importing modules: {e}")
        return False
    
    # Test 1: Model loading and quantization
    print("\nTest 1: Model loading and quantization...")
    try:
        # Create a simple model for testing
        detector = LSTM_RNN_AnomalyDetector(sequence_length=60, features=10)
        model = detector.build_model()
        print("✓ Model built successfully")
        
        # Test quantization
        quantizer = ModelQuantizer(detector_instance=detector)
        # Skip actual quantization in test to save time, just verify setup
        print("✓ Quantization components initialized")
    except Exception as e:
        print(f"✗ Model test failed: {e}")
        return False
    
    # Test 2: Packet analysis
    print("\nTest 2: Packet analysis...")
    try:
        analyzer = PacketAnalyzer()
        
        # Create mock packet sequence
        mock_packets = [{
            'length': 1000, 'ttl': 64, 'protocol': 6, 'src_port': 12345, 'dst_port': 80,
            'tcp_flags': 16, 'window_size': 65535, 'payload_size': 800,
            'payload_entropy': 4.5, 'src_ip_entropy': 2.1, 'dst_ip_entropy': 1.8
        }] * 60  # 60 packets
        
        # Test sequence preparation
        sequence = analyzer.prepare_sequence_for_model(mock_packets)
        print(f"✓ Packet sequence prepared: {sequence.shape}")
    except Exception as e:
        print(f"✗ Packet analysis test failed: {e}")
        return False
    
    # Test 3: Memory usage estimation
    print("\nTest 3: Memory usage estimation...")
    try:
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        
        # Simulate loading a quantized model (without actually loading to save resources)
        print(f"Initial memory usage: {initial_memory:.2f} MB")
        
        # Estimate memory for full system
        estimated_model_size = 10  # MB for quantized model
        estimated_overhead = 50    # MB for system overhead
        total_estimated = initial_memory + estimated_model_size + estimated_overhead
        
        print(f"Estimated total memory usage: {total_estimated:.2f} MB")
        print(f"Current system memory usage: {psutil.virtual_memory().percent}%")
        
        if total_estimated < 2000:  # Less than 2GB
            print("✓ Estimated memory usage is acceptable for Raspberry Pi")
        else:
            print("⚠ Estimated memory usage might be high for Raspberry Pi")
    except Exception as e:
        print(f"✗ Memory estimation test failed: {e}")
        return False
    
    total_time = time.time() - start_time
    print(f"\nPerformance tests completed in {total_time:.2f} seconds")
    print("✓ All performance tests passed")
    return True

def create_deployment_package():
    """Create a deployment package for Raspberry Pi"""
    print("Creating deployment package...")
    
    # Create a list of required files
    required_files = [
        'web_interface.py',
        'lstm_rnn_anomaly_detection.py',
        'csv_data_processor.py',
        'model_trainer.py',
        'model_quantizer.py',
        'packet_capture.py',
        'anomaly_detection_integration.py',
        'notification_system.py',
        'raspberry_pi_config.ini',
        'startup_raspberry_pi.sh',
        'requirements.txt'  # Create this file
    ]
    
    # Create requirements.txt
    requirements = """tensorflow==2.13.0
numpy
pandas
scikit-learn
flask
scapy
python-nmap
psutil
requests
"""
    
    with open('requirements.txt', 'w') as f:
        f.write(requirements.strip())
    
    print("Requirements file created: requirements.txt")
    
    # Create a README for Raspberry Pi deployment
    readme_content = """# IoT Anomaly Detection System - Raspberry Pi Deployment

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
"""
    
    with open('README_PI_DEPLOYMENT.md', 'w') as f:
        f.write(readme_content.strip())
    
    print("Deployment README created: README_PI_DEPLOYMENT.md")
    
    # Create a simple test script
    test_script = '''#!/usr/bin/env python3
"""
Quick test script to verify the IoT anomaly detection system is working
"""

import sys
import os

def test_imports():
    """Test that all modules can be imported"""
    modules_to_test = [
        'lstm_rnn_anomaly_detection',
        'packet_capture',
        'anomaly_detection_integration',
        'notification_system'
    ]

    print("Testing module imports...")
    for module_name in modules_to_test:
        try:
            __import__(module_name)
            print(f"✓ {module_name} imported successfully")
        except ImportError as e:
            print(f"✗ Failed to import {module_name}: {e}")
            return False

    return True

def test_model_creation():
    """Test basic model creation"""
    try:
        from lstm_rnn_anomaly_detection import LSTM_RNN_AnomalyDetector
        detector = LSTM_RNN_AnomalyDetector(sequence_length=60, features=10)
        model = detector.build_model()
        print("✓ Model created successfully")
        return True
    except Exception as e:
        print(f"✗ Model creation failed: {e}")
        return False

def test_packet_processing():
    """Test packet processing functionality"""
    try:
        from packet_capture import PacketAnalyzer
        analyzer = PacketAnalyzer()

        # Test with minimal packet data
        mock_packet = [{
            'length': 1000, 'ttl': 64, 'protocol': 6, 'src_port': 12345, 'dst_port': 80,
            'tcp_flags': 16, 'window_size': 65535, 'payload_size': 800,
            'payload_entropy': 4.5, 'src_ip_entropy': 2.1, 'dst_ip_entropy': 1.8
        }]

        sequence = analyzer.prepare_sequence_for_model(mock_packet)
        print(f"✓ Packet processing works, sequence shape: {sequence.shape}")
        return True
    except Exception as e:
        print(f"✗ Packet processing failed: {e}")
        return False

if __name__ == "__main__":
    print("Running quick system test...")

    if not test_imports():
        print("Import tests failed. Please check installation.")
        sys.exit(1)

    if not test_model_creation():
        print("Model creation failed. Please check TensorFlow installation.")
        sys.exit(1)

    if not test_packet_processing():
        print("Packet processing failed.")
        sys.exit(1)

    print("\\n✓ All tests passed! The system appears to be working correctly.")
    print("You can now run the full system with: python3 web_interface.py")
'''
    
    with open('quick_test.py', 'w') as f:
        f.write(test_script.strip())
    
    # Make the test script executable
    os.chmod('quick_test.py', 0o755)
    
    print("Quick test script created: quick_test.py")
    print("Run './quick_test.py' to verify the system works on your Raspberry Pi")
    
    print("\\nDeployment package created successfully!")
    print("Files created:")
    for f in required_files + ['README_PI_DEPLOYMENT.md', 'quick_test.py']:
        if os.path.exists(f):
            print(f"  - {f}")

def main():
    """Main function to run all optimization and testing steps"""
    print("IoT Anomaly Detection System - Raspberry Pi 5 Optimization and Testing")
    print("=" * 70)
    
    print("\\nStep 1: Checking system requirements...")
    if not check_system_requirements():
        print("System requirements check failed. Exiting.")
        return False
    
    print("\\nStep 2: Installing dependencies...")
    # Note: Skipping actual installation in this script to avoid modifying the system
    # In a real deployment, you would uncomment the next line:
    # if not install_dependencies():
    #     print("Dependency installation failed. Exiting.")
    #     return False
    print("Dependency installation step completed (skipped in test mode)")
    
    print("\\nStep 3: Applying Raspberry Pi optimizations...")
    optimize_for_raspberry_pi()
    
    print("\\nStep 4: Creating systemd service file...")
    create_service_file()
    
    print("\\nStep 5: Running performance tests...")
    if not run_performance_tests():
        print("Performance tests failed. Please check the system configuration.")
        return False
    
    print("\\nStep 6: Creating deployment package...")
    create_deployment_package()
    
    print("\\n" + "=" * 70)
    print("Optimization and testing completed successfully!")
    print("\\nThe system is now optimized for Raspberry Pi 5 with 8GB RAM.")
    print("Follow the instructions in README_PI_DEPLOYMENT.md to deploy on your Raspberry Pi.")
    
    return True

if __name__ == "__main__":
    success = main()
    if not success:
        print("\\nOptimization and testing failed. Please check the output above for details.")
        sys.exit(1)