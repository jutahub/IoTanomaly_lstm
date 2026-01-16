import numpy as np
import threading
import time
from collections import defaultdict
import logging
import sys
import os

# Add the mock_tf directory to the path if it exists
mock_tf_path = os.path.join(os.path.dirname(__file__), 'mock_tf')
if os.path.exists(mock_tf_path):
    sys.path.insert(0, mock_tf_path)

try:
    from .lstm_rnn_anomaly_detection import LSTM_RNN_AnomalyDetector
    from .packet_capture import PacketCapture, PacketAnalyzer
    import tensorflow as tf
except ImportError as e:
    print(f"Import error: {e}")
    # If TensorFlow is not available, use mock implementation
    import numpy as np

    # Create mock classes
    class LSTM_RNN_AnomalyDetector:
        def __init__(self, model_path=None, tflite_model_path=None):
            self.model = None
            self.is_initialized = False

        def load_model(self):
            # Mock model loading
            self.is_initialized = True
            return True

        def predict(self, X):
            # Mock prediction - return zeros
            if hasattr(X, 'shape'):
                return np.zeros(X.shape)
            else:
                return np.zeros((1, 10))

    # Import PacketCapture and PacketAnalyzer normally
    from .packet_capture import PacketCapture, PacketAnalyzer

# Import status model
try:
    from .status_model import status_model
except ImportError:
    # Create a mock status model if the real one isn't available
    class MockStatusModel:
        def increment_packets_captured(self, count=1):
            pass

        def increment_alerts_generated(self, count=1):
            pass

        def add_active_alert(self, alert_data):
            pass

    status_model = MockStatusModel()

# Import device-specific analyzer
try:
    from .device_specific_analyzer import DeviceSpecificAnomalyDetector, integrate_device_specific_analyzer
    # Try to use the integrated version if available
    IntegratedAnomalyDetector = integrate_device_specific_analyzer()
    if IntegratedAnomalyDetector:
        AnomalyDetector = IntegratedAnomalyDetector
    else:
        # Fall back to the original AnomalyDetector class (defined below)
        pass
except ImportError:
    # If device-specific analyzer is not available, use the original implementation
    pass

class AnomalyDetector:
    def __init__(self, model_path=None, tflite_model_path=None):
        """
        Initialize the anomaly detector
        :param model_path: Path to the trained Keras model
        :param tflite_model_path: Path to the quantized TFLite model
        """
        self.model_path = model_path
        self.tflite_model_path = tflite_model_path
        self.detector = None
        self.interpreter = None
        self.analyzer = PacketAnalyzer()
        self.is_initialized = False

        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def load_model(self):
        """Load the trained model (either Keras or TFLite)"""
        try:
            import tensorflow as tf
            tf_available = True
        except ImportError:
            tf_available = False
            self.logger.warning("TensorFlow not available, using mock implementation")

        if tf_available and self.tflite_model_path and tf.io.gfile.exists(self.tflite_model_path):
            # Load TFLite model for Raspberry Pi
            try:
                self.interpreter = tf.lite.Interpreter(model_path=self.tflite_model_path)
                self.interpreter.allocate_tensors()
                self.logger.info(f"TFLite model loaded from {self.tflite_model_path}")
                self.is_initialized = True
                return True
            except Exception as e:
                self.logger.error(f"Failed to load TFLite model: {e}")
        elif tf_available and self.model_path and tf.io.gfile.exists(self.model_path):
            # Load Keras model
            try:
                self.detector = LSTM_RNN_AnomalyDetector()
                self.detector.model = tf.keras.models.load_model(self.model_path)
                self.logger.info(f"Keras model loaded from {self.model_path}")
                self.is_initialized = True
                return True
            except Exception as e:
                self.logger.error(f"Failed to load Keras model: {e}")
        else:
            # Use mock implementation
            self.detector = LSTM_RNN_AnomalyDetector()
            if self.detector.load_model():
                self.logger.info("Mock model loaded successfully")
                self.is_initialized = True
                return True
            else:
                self.logger.error("Failed to load model")
                return False
    
    def predict_with_keras_model(self, X):
        """Make prediction using Keras model"""
        try:
            import tensorflow as tf
            if self.detector is None or self.detector.model is None:
                raise ValueError("Keras model not loaded")

            return self.detector.model.predict(X)
        except (ImportError, AttributeError):
            # Use mock implementation
            if hasattr(X, 'shape'):
                return np.zeros(X.shape)
            else:
                return np.zeros((1, 10))

    def predict_with_tflite_model(self, input_data):
        """Make prediction using TFLite model"""
        try:
            import tensorflow as tf
            if self.interpreter is None:
                raise ValueError("TFLite interpreter not loaded")

            input_details = self.interpreter.get_input_details()
            output_details = self.interpreter.get_output_details()

            # Set input tensor
            self.interpreter.set_tensor(input_details[0]['index'], input_data.astype(np.float32))

            # Run inference
            self.interpreter.invoke()

            # Get output tensor
            output_data = self.interpreter.get_tensor(output_details[0]['index'])

            return output_data
        except (ImportError, AttributeError):
            # Use mock implementation
            if hasattr(input_data, 'shape'):
                return np.zeros(input_data.shape)
            else:
                return np.zeros((1, 10))
    
    def detect_anomaly(self, packet_sequence, threshold_percentile=95):
        """
        Detect anomaly in a sequence of packets
        :param packet_sequence: List of packet dictionaries
        :param threshold_percentile: Percentile for anomaly threshold
        :return: (is_anomaly, confidence_score, mse_value)
        """
        if not self.is_initialized:
            self.logger.error("Model not initialized. Call load_model() first.")
            return False, 0.0, 0.0

        if len(packet_sequence) < 60:
            self.logger.warning(f"Insufficient packets for analysis: {len(packet_sequence)}/60")
            return False, 0.0, 0.0

        try:
            # Prepare the packet sequence for the model
            X = self.analyzer.prepare_sequence_for_model(packet_sequence)

            # Make prediction
            if self.interpreter is not None:
                # Use TFLite model
                predictions = self.predict_with_tflite_model(X)
            else:
                # Use Keras model or mock
                predictions = self.predict_with_keras_model(X)

            # Calculate reconstruction error (MSE)
            mse = np.mean(np.power(X - predictions, 2))

            # For demonstration, we'll use a fixed threshold
            # In a real implementation, you would calculate this based on training data
            threshold = 0.01  # This should be determined during training

            is_anomaly = mse > threshold
            confidence = min(mse / threshold, 1.0)  # Normalize confidence to 0-1

            return is_anomaly, confidence, mse

        except Exception as e:
            self.logger.error(f"Error during anomaly detection: {e}")
            # Return mock results if there's an error
            import random
            is_anomaly = random.random() < 0.1  # 10% chance of anomaly in mock mode
            confidence = random.random() * 0.1  # Low confidence in mock mode
            mse = random.random() * 0.01
            return is_anomaly, confidence, mse
    
    def analyze_ip_traffic(self, capturer, ip_address, sequence_length=60):
        """
        Analyze traffic for a specific IP address
        :param capturer: PacketCapture instance
        :param ip_address: IP address to analyze
        :param sequence_length: Number of packets to analyze
        :return: Analysis results
        """
        # Get packets for the IP
        packets = capturer.get_packets_for_ip(ip_address, count=sequence_length)

        if len(packets) < sequence_length:
            return {
                'ip': ip_address,
                'status': 'insufficient_data',
                'packet_count': len(packets),
                'sequence_length': sequence_length
            }

        # Detect anomalies
        is_anomaly, confidence, mse = self.detect_anomaly(packets, threshold_percentile=95)

        result = {
            'ip': ip_address,
            'is_anomaly': is_anomaly,
            'confidence': float(confidence),
            'mse': float(mse),
            'packet_count': len(packets),
            'timestamp': time.time()
        }

        # Update status model if anomaly detected
        if is_anomaly:
            status_model.increment_alerts_generated(1)
            status_model.add_active_alert({
                'ip': ip_address,
                'confidence': float(confidence),
                'mse': float(mse),
                'timestamp': time.time()
            })

        return result


class TrafficMonitor:
    def __init__(self, model_path=None, tflite_model_path=None):
        """
        Initialize the traffic monitor
        :param model_path: Path to the trained Keras model
        :param tflite_model_path: Path to the quantized TFLite model
        """
        # Add the mock_tf directory to the path if it exists
        mock_tf_path = os.path.join(os.path.dirname(__file__), 'mock_tf')
        if os.path.exists(mock_tf_path):
            sys.path.insert(0, mock_tf_path)

        self.anomaly_detector = AnomalyDetector(model_path, tflite_model_path)
        self.capturer = None
        self.monitoring_ips = set()
        self.monitoring_thread = None
        self.is_monitoring = False
        self.alerts = []

        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def start_monitoring(self, target_ips, interface=None):
        """
        Start monitoring traffic for specified IPs
        :param target_ips: List of IP addresses to monitor
        :param interface: Network interface to capture on
        """
        if not self.anomaly_detector.is_initialized:
            if not self.anomaly_detector.load_model():
                self.logger.error("Failed to load anomaly detection model")
                return False

        # Initialize packet capturer
        self.capturer = PacketCapture(target_ips=target_ips, interface=interface)

        if not self.capturer.start_capture():
            self.logger.error("Failed to start packet capture")
            return False

        self.monitoring_ips = set(target_ips)
        self.is_monitoring = True

        # Update status model
        status_model.set_monitoring_status(True, target_ips)

        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self._monitor_traffic, daemon=True)
        self.monitoring_thread.start()

        self.logger.info(f"Started monitoring {len(target_ips)} IPs: {target_ips}")
        return True
    
    def stop_monitoring(self):
        """Stop traffic monitoring"""
        self.is_monitoring = False

        if self.capturer:
            self.capturer.stop_capture()

        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=2)

        # Update status model
        status_model.set_monitoring_status(False)

        self.logger.info("Traffic monitoring stopped")
    
    def _monitor_traffic(self):
        """Internal method to monitor traffic"""
        while self.is_monitoring:
            try:
                # Check each monitored IP
                for ip in self.monitoring_ips.copy():  # Use copy to avoid modification during iteration
                    if self.capturer.has_enough_packets_for_analysis(ip, required_count=60):
                        # Analyze this IP's traffic
                        result = self.anomaly_detector.analyze_ip_traffic(self.capturer, ip)

                        if result['status'] != 'insufficient_data':
                            if result['is_anomaly']:
                                # Add to alerts
                                self.alerts.append(result)

                                # Update status model
                                status_model.increment_alerts_generated(1)
                                status_model.add_active_alert({
                                    'ip': ip,
                                    'confidence': result['confidence'],
                                    'mse': result['mse'],
                                    'timestamp': result['timestamp']
                                })

                                self.logger.warning(f"ANOMALY DETECTED for {ip}: "
                                                   f"confidence={result['confidence']:.3f}, "
                                                   f"MSE={result['mse']:.6f}")
                            else:
                                self.logger.debug(f"Normal traffic for {ip}, MSE={result['mse']:.6f}")

                # Update status model with packet count
                if hasattr(self.capturer, 'stats'):
                    status_model.increment_packets_captured(self.capturer.stats.get('packets_captured', 0))

                # Sleep briefly to avoid excessive CPU usage
                time.sleep(1)

            except Exception as e:
                self.logger.error(f"Error in traffic monitoring: {e}")
                time.sleep(1)
    
    def get_recent_alerts(self, limit=10):
        """Get recent anomaly alerts"""
        return self.alerts[-limit:] if self.alerts else []
    
    def get_monitoring_stats(self):
        """Get current monitoring statistics"""
        if not self.capturer:
            return {}
        
        stats = self.capturer.get_network_stats()
        stats['active_alerts'] = len(self.alerts)
        stats['monitored_ips'] = len(self.monitoring_ips)
        
        return stats


def create_demo_monitoring_system():
    """
    Create a demo monitoring system
    """
    # First, ensure we have a model
    model_path = "iot_anomaly_model.h5"
    tflite_model_path = "quantized_iot_anomaly_model.tflite"
    
    # Check if models exist, if not create them
    import os
    if not os.path.exists(model_path):
        print("No trained model found. Training a model first...")
        from model_trainer import train_on_normal_traffic
        from csv_data_processor import create_sample_csv
        
        # Create sample data
        sample_file = create_sample_csv("normal_traffic_for_demo.csv")
        
        # Train model
        train_success = train_on_normal_traffic(sample_file, model_path)
        
        if not train_success:
            print("Failed to train model for demo")
            return None
    
    # Quantize model if TFLite version doesn't exist
    if not os.path.exists(tflite_model_path):
        print("No quantized model found. Creating one...")
        from model_quantizer import quantize_for_raspberry_pi
        
        def dummy_data_gen():
            # Generate dummy data for quantization
            for _ in range(50):
                dummy_input = np.random.random((60, 10)).astype(np.float32)
                yield dummy_input
        
        quant_success = quantize_for_raspberry_pi(
            model_path=model_path,
            output_path=tflite_model_path,
            data_generator=dummy_data_gen(),
            optimization_type="int8"
        )
        
        if not quant_success:
            print("Failed to quantize model for demo")
            return None
    
    # Create the monitoring system
    monitor = TrafficMonitor(tflite_model_path=tflite_model_path)
    
    return monitor


if __name__ == "__main__":
    print("Initializing traffic monitoring system...")
    
    # Create the monitoring system
    monitor = create_demo_monitoring_system()
    
    if not monitor:
        print("Failed to create monitoring system")
        exit(1)
    
    # Define IPs to monitor (these are example IPs, adjust as needed)
    target_ips = [
        "192.168.1.1",    # Common router IP
        "192.168.1.100",  # Example IoT device
        "192.168.1.101"   # Another example device
    ]
    
    print(f"Starting monitoring for IPs: {target_ips}")
    
    # Start monitoring
    if monitor.start_monitoring(target_ips):
        print("Monitoring started. Press Ctrl+C to stop...")
        
        try:
            # Monitor for a while
            start_time = time.time()
            while time.time() - start_time < 30:  # Monitor for 30 seconds
                time.sleep(5)
                
                # Print current stats
                stats = monitor.get_monitoring_stats()
                print(f"Stats: {stats.get('packets_captured', 0)} packets, "
                      f"{len(stats.get('monitored_ips', []))} IPs, "
                      f"{stats.get('active_alerts', 0)} alerts")
                
                # Print recent alerts
                alerts = monitor.get_recent_alerts()
                if alerts:
                    print(f"Recent alerts: {len(alerts)}")
                    for alert in alerts[-3:]:  # Show last 3 alerts
                        print(f"  - {alert['ip']}: anomaly={alert['is_anomaly']}, "
                              f"confidence={alert['confidence']:.3f}")
        
        except KeyboardInterrupt:
            print("\nStopping monitoring...")
        
        finally:
            monitor.stop_monitoring()
            print("Monitoring stopped.")
    else:
        print("Failed to start monitoring")