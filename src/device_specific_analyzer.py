"""
Custom Traffic Analyzer using Device-Specific Model
This module integrates the trained model with the traffic analysis system
"""
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib
import os
import sys
import logging

# Add the project directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    import tensorflow as tf
    from tensorflow.keras.models import load_model
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    print("TensorFlow not available, using mock implementation")

class DeviceSpecificAnalyzer:
    def __init__(self, model_path=None, scaler_path=None):
        """
        Initialize the device-specific traffic analyzer
        """
        self.model = None
        self.scaler = None
        self.model_path = model_path or "iot_device_model.h5"
        self.scaler_path = scaler_path or self.model_path.replace('.h5', '_scaler.pkl')
        self.is_loaded = False
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Load the model and scaler
        self.load_model()
    
    def load_model(self):
        """
        Load the trained model and scaler
        """
        if not TF_AVAILABLE:
            self.logger.warning("TensorFlow not available, using mock model")
            self.is_loaded = True
            return True
        
        try:
            # Check if model file exists
            if os.path.exists(self.model_path):
                self.model = load_model(self.model_path)
                self.logger.info(f"Model loaded from {self.model_path}")
            else:
                self.logger.warning(f"Model file not found: {self.model_path}")
                # Try to find any model file in the directory
                current_dir = os.getcwd()
                for file in os.listdir(current_dir):
                    if file.endswith('.h5') and 'model' in file.lower():
                        self.model_path = os.path.join(current_dir, file)
                        self.model = load_model(self.model_path)
                        self.logger.info(f"Found and loaded model: {self.model_path}")
                        break
                else:
                    self.logger.error("No model file found, using mock implementation")
                    self.is_loaded = False
                    return False
            
            # Load the scaler
            if os.path.exists(self.scaler_path):
                self.scaler = joblib.load(self.scaler_path)
                self.logger.info(f"Scaler loaded from {self.scaler_path}")
            else:
                self.logger.warning(f"Scaler file not found: {self.scanner_path}")
                # Try to find any scaler file in the directory
                for file in os.listdir(current_dir):
                    if file.endswith('_scaler.pkl'):
                        self.scanner_path = os.path.join(current_dir, file)
                        self.scaler = joblib.load(self.scaler_path)
                        self.logger.info(f"Found and loaded scaler: {self.scanner_path}")
                        break
                else:
                    self.logger.warning("No scaler file found, will create one later if needed")
            
            self.is_loaded = True
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            self.is_loaded = False
            return False
    
    def preprocess_packet_features(self, packet_info):
        """
        Preprocess packet information to match the model's expected input
        """
        # Define the expected feature order based on common network features
        expected_features = [
            'length', 'ttl', 'protocol', 'src_port', 'dst_port', 
            'tcp_flags', 'window_size', 'payload_size', 
            'payload_entropy', 'src_ip_entropy', 'dst_ip_entropy'
        ]
        
        # Create a feature vector based on the expected features
        features = []
        
        for feat in expected_features:
            if feat in packet_info:
                val = packet_info[feat]
                # Normalize values to be between 0 and 1 where possible
                if feat == 'length':
                    features.append(min(val / 1500.0, 1.0))  # Max typical packet size
                elif feat == 'ttl':
                    features.append(min(val / 255.0, 1.0))  # Max TTL
                elif feat == 'src_port' or feat == 'dst_port':
                    features.append(min(val / 65535.0, 1.0))  # Max port number
                elif feat == 'tcp_flags':
                    features.append(min(val / 255.0, 1.0))  # Max flags value
                elif feat == 'window_size':
                    features.append(min(val / 65535.0, 1.0))  # Max window size
                elif feat == 'payload_size':
                    features.append(min(val / 1500.0, 1.0))  # Max payload size
                elif feat in ['payload_entropy', 'src_ip_entropy', 'dst_ip_entropy']:
                    features.append(min(val / 8.0, 1.0))  # Max entropy value
                elif feat == 'protocol':
                    features.append(min(val / 255.0, 1.0))  # Max protocol number
                else:
                    features.append(float(val) if isinstance(val, (int, float)) else 0.0)
            else:
                # If feature is missing, append a default value
                features.append(0.0)
        
        return np.array(features).reshape(1, -1)  # Reshape for model input
    
    def prepare_sequence(self, packet_sequence, sequence_length=60):
        """
        Prepare a sequence of packets for model prediction
        """
        if len(packet_sequence) < sequence_length:
            # Pad with zeros if we don't have enough packets
            padded_sequence = [self._get_zero_packet_features()] * (sequence_length - len(packet_sequence))
            padded_sequence.extend(packet_sequence)
            packet_sequence = padded_sequence
        elif len(packet_sequence) > sequence_length:
            # Take the most recent packets
            packet_sequence = packet_sequence[-sequence_length:]
        
        # Extract features for each packet
        features_list = []
        for packet in packet_sequence:
            features = self.preprocess_packet_features(packet)
            features_list.append(features.flatten())
        
        # Convert to numpy array
        features_array = np.array(features_list)
        
        # Reshape for LSTM: (1, sequence_length, features)
        return features_array.reshape(1, sequence_length, features_array.shape[1])
    
    def _get_zero_packet_features(self):
        """
        Get a zero-filled packet feature vector
        """
        return np.zeros(11)  # Based on our expected features
    
    def detect_anomaly(self, packet_sequence, threshold_percentile=95):
        """
        Detect anomaly in a sequence of packets using the device-specific model
        """
        if not self.is_loaded:
            # Use mock implementation
            self.logger.warning("Model not loaded, using mock anomaly detection")
            # Return mock results
            import random
            is_anomaly = random.random() < 0.1  # 10% chance of anomaly
            confidence = random.random() * 0.2  # Low confidence in mock mode
            mse = random.random() * 0.01
            return is_anomaly, confidence, mse
        
        try:
            # Prepare the sequence for the model
            X = self.prepare_sequence(packet_sequence)
            
            # Make prediction
            predictions = self.model.predict(X, verbose=0)
            
            # Calculate reconstruction error (MSE)
            mse = np.mean(np.power(X - predictions, 2))
            
            # Determine threshold based on a reasonable assumption
            # In a real scenario, this would be calculated from training data
            threshold = 0.01  # This should be determined during training
            
            is_anomaly = mse > threshold
            confidence = min(mse / threshold, 1.0)  # Normalize confidence to 0-1
            
            return is_anomaly, confidence, mse
            
        except Exception as e:
            self.logger.error(f"Error during anomaly detection: {e}")
            # Return mock results in case of error
            import random
            is_anomaly = random.random() < 0.1
            confidence = random.random() * 0.2
            mse = random.random() * 0.01
            return is_anomaly, confidence, mse

# Update the anomaly detection integration to use the device-specific analyzer
def integrate_device_specific_analyzer():
    """
    Integrate the device-specific analyzer with the existing system
    """
    try:
        # Try to import the existing components
        from .anomaly_detection_integration import AnomalyDetector
        from .lstm_rnn_anomaly_detection import LSTM_RNN_AnomalyDetector

        # Create a wrapper class that uses the device-specific analyzer
        class DeviceSpecificAnomalyDetector(AnomalyDetector):
            def __init__(self, model_path=None, tflite_model_path=None):
                super().__init__(model_path, tflite_model_path)

                # Initialize the device-specific analyzer
                self.device_analyzer = DeviceSpecificAnalyzer(model_path)

                # Override the detect_anomaly method
                self.is_initialized = self.device_analyzer.is_loaded

            def detect_anomaly(self, packet_sequence, threshold_percentile=95):
                """
                Override the parent method to use device-specific model
                """
                return self.device_analyzer.detect_anomaly(packet_sequence, threshold_percentile)

        # Return the new class
        return DeviceSpecificAnomalyDetector

    except ImportError as e:
        print(f"Could not integrate with existing system: {e}")
        return None

if __name__ == "__main__":
    # Test the device-specific analyzer
    analyzer = DeviceSpecificAnalyzer()
    
    if analyzer.is_loaded:
        print("Device-specific analyzer loaded successfully!")
        
        # Create mock packet sequence for testing
        mock_packets = [
            {
                'length': 1000, 'ttl': 64, 'protocol': 6, 'src_port': 12345, 'dst_port': 80,
                'tcp_flags': 16, 'window_size': 65535, 'payload_size': 800,
                'payload_entropy': 4.5, 'src_ip_entropy': 2.1, 'dst_ip_entropy': 1.8
            },
            {
                'length': 1200, 'ttl': 128, 'protocol': 6, 'src_port': 12346, 'dst_port': 443,
                'tcp_flags': 18, 'window_size': 65535, 'payload_size': 1000,
                'payload_entropy': 5.2, 'src_ip_entropy': 2.3, 'dst_ip_entropy': 2.0
            }
        ]
        
        # Test anomaly detection
        is_anomaly, confidence, mse = analyzer.detect_anomaly(mock_packets)
        print(f"Anomaly detected: {is_anomaly}")
        print(f"Confidence: {confidence:.4f}")
        print(f"MSE: {mse:.6f}")
    else:
        print("Could not load the device-specific analyzer.")
        print("Make sure you have a trained model file (iot_device_model.h5) in the directory.")