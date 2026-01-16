#!/bin/bash
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