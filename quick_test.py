#!/usr/bin/env python3
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

    print("\n✓ All tests passed! The system appears to be working correctly.")
    print("You can now run the full system with: python3 web_interface.py")