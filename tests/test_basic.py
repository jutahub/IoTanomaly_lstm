"""
Basic tests for the IoT Anomaly Detection System
"""
import unittest
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

class TestImports(unittest.TestCase):
    """Test that all modules can be imported correctly"""
    
    def test_lstm_rnn_anomaly_detection_import(self):
        """Test LSTM RNN anomaly detection module import"""
        try:
            from src.lstm_rnn_anomaly_detection import LSTM_RNN_AnomalyDetector
            self.assertTrue(True)
        except ImportError:
            self.fail("Could not import LSTM_RNN_AnomalyDetector")
    
    def test_packet_capture_import(self):
        """Test packet capture module import"""
        try:
            from src.packet_capture import PacketCapture, PacketAnalyzer
            self.assertTrue(True)
        except ImportError:
            self.fail("Could not import PacketCapture or PacketAnalyzer")
    
    def test_anomaly_detection_integration_import(self):
        """Test anomaly detection integration module import"""
        try:
            from src.anomaly_detection_integration import AnomalyDetector
            self.assertTrue(True)
        except ImportError:
            self.fail("Could not import AnomalyDetector")

if __name__ == '__main__':
    unittest.main()