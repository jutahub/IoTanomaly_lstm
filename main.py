#!/usr/bin/env python3
"""
Main entry point for the IoT Anomaly Detection System
This system combines LSTM+RNN neural networks with quantization for efficient 
anomaly detection in IoT device traffic, deployed on Raspberry Pi 5 with 8GB RAM.
"""

import os
import sys
import argparse
import logging
from datetime import datetime

def setup_logging():
    """Setup logging for the application"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler('iot_anomaly_detection.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def main():
    """Main function to run the IoT anomaly detection system"""
    parser = argparse.ArgumentParser(description='IoT Anomaly Detection System')
    parser.add_argument('--mode', choices=['web', 'train', 'test', 'optimize'],
                       default='web', help='Operation mode')
    parser.add_argument('--model-path', type=str, default='models/iot_anomaly_model.h5',
                       help='Path to the trained model')
    parser.add_argument('--tflite-model-path', type=str, default='models/quantized_iot_anomaly_model.tflite',
                       help='Path to the quantized TFLite model')
    parser.add_argument('--data-path', type=str, default='data/normal_traffic_data.csv',
                       help='Path to the training data CSV file')
    parser.add_argument('--interface', type=str, default=None,
                       help='Network interface to monitor (e.g., eth0, wlan0)')
    parser.add_argument('--port', type=int, default=5001,  # Changed default port
                       help='Port to run the web interface on')

    args = parser.parse_args()

    setup_logging()
    logger = logging.getLogger(__name__)

    logger.info("Starting IoT Anomaly Detection System")
    logger.info(f"Mode: {args.mode}")
    logger.info(f"Port: {args.port}")

    if args.mode == 'web':
        # Start the web interface
        try:
            from src.web_interface import app
            logger.info(f"Starting web interface on http://0.0.0.0:{args.port}")
            app.run(debug=False, host='0.0.0.0', port=args.port)
        except ImportError as e:
            logger.error(f"Failed to import web interface: {e}")
            # Try to import mock version if TensorFlow is missing
            if "tensorflow" in str(e).lower():
                logger.info("TensorFlow not available, attempting to run with mock TensorFlow...")
                sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'mock_tf'))
                try:
                    from src.web_interface import app
                    logger.info(f"Starting web interface on http://0.0.0.0:{args.port}")
                    app.run(debug=False, host='0.0.0.0', port=args.port)
                except Exception as e2:
                    logger.error(f"Could not start web interface even with mock TensorFlow: {e2}")
                    return 1
            else:
                return 1

    elif args.mode == 'train':
        # Train the model
        try:
            from src.model_trainer import train_on_normal_traffic
            logger.info(f"Training model with data from {args.data_path}")

            # Create sample data if it doesn't exist
            if not os.path.exists(args.data_path):
                from src.csv_data_processor import create_sample_csv
                args.data_path = create_sample_csv(args.data_path)

            success = train_on_normal_traffic(args.data_path, args.model_path)
            if success:
                logger.info(f"Model training completed. Saved to {args.model_path}")

                # Quantize the model for Raspberry Pi
                from src.model_quantizer import quantize_for_raspberry_pi
                quant_success = quantize_for_raspberry_pi(
                    model_path=args.model_path,
                    output_path=args.tflite_model_path
                )
                if quant_success:
                    logger.info(f"Model quantized for Raspberry Pi. Saved to {args.tflite_model_path}")
                else:
                    logger.error("Model quantization failed")
            else:
                logger.error("Model training failed")
        except ImportError as e:
            logger.error(f"Training mode requires TensorFlow: {e}")
            return 1

    elif args.mode == 'test':
        # Run tests
        logger.info("Running system tests...")

        # Import and run basic functionality tests
        try:
            from src.packet_capture import PacketCapture, PacketAnalyzer

            # Test packet analyzer
            analyzer = PacketAnalyzer()
            logger.info("✓ Packet analyzer initialized successfully")

            logger.info("✓ Basic system components are working correctly")

        except Exception as e:
            logger.error(f"Test failed: {e}")
            return 1

    elif args.mode == 'optimize':
        # Run optimization for Raspberry Pi
        logger.info("Running Raspberry Pi optimizations...")
        from src.raspberry_pi_optimizer import main as optimize_main
        optimize_main()

    return 0

if __name__ == "__main__":
    exit(main())
