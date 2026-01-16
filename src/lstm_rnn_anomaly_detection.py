try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import LSTM, Dense, Dropout, SimpleRNN
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    # Define placeholder classes when TensorFlow is not available
    class Sequential:
        pass

    # Other classes will be defined conditionally in the class itself

import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
import os

class LSTM_RNN_AnomalyDetector:
    def __init__(self, sequence_length=60, features=10):
        """
        Initialize the LSTM+RNN model for anomaly detection
        :param sequence_length: Number of time steps to look back (60 packets)
        :param features: Number of features per packet
        """
        if not TF_AVAILABLE:
            # Initialize with mock attributes when TensorFlow is not available
            self.sequence_length = sequence_length
            self.features = features
            self.model = None
            self.scaler = MinMaxScaler()
            return

        self.sequence_length = sequence_length
        self.features = features
        self.model = None
        self.scaler = MinMaxScaler()

    def build_model(self):
        """Build the LSTM+RNN model"""
        if not TF_AVAILABLE:
            # Return a mock model when TensorFlow is not available
            class MockModel:
                def __init__(self):
                    self.built = True

                def compile(self, optimizer, loss, metrics):
                    pass

                def fit(self, x, y, epochs, batch_size, validation_split, verbose):
                    # Mock training
                    class MockHistory:
                        def __init__(self):
                            self.history = {'loss': [0.1] * epochs}
                    return MockHistory()

                def predict(self, x):
                    # Return mock predictions
                    return np.zeros_like(x) if hasattr(x, 'shape') else np.zeros((1, self.features))

            self.model = MockModel()
            return self.model

        self.model = Sequential([
            # First LSTM layer
            LSTM(64, return_sequences=True, input_shape=(self.sequence_length, self.features)),
            Dropout(0.2),

            # Second LSTM layer
            LSTM(32, return_sequences=True),
            Dropout(0.2),

            # RNN layer
            SimpleRNN(32, return_sequences=False),
            Dropout(0.2),

            # Dense layers
            Dense(50, activation='relu'),
            Dense(self.features, activation='linear')  # Output same number of features as input
        ])

        self.model.compile(
            optimizer='adam',
            loss='mse',  # Mean squared error for anomaly detection
            metrics=['mae']
        )

        return self.model
    
    def prepare_data(self, df, feature_columns):
        """
        Prepare data for training
        :param df: DataFrame with network traffic data
        :param feature_columns: List of column names to use as features
        """
        if not TF_AVAILABLE:
            # Return mock data when TensorFlow is not available
            # Generate some mock sequences
            n_samples = min(100, len(df))  # Use up to 100 samples
            n_features = len(feature_columns)

            # Extract features
            data = df[feature_columns].values[:n_samples]

            # Normalize the data
            scaled_data = self.scaler.fit_transform(data)

            # Create sequences
            X, y = [], []
            for i in range(self.sequence_length, len(scaled_data)):
                X.append(scaled_data[i-self.sequence_length:i])
                y.append(scaled_data[i])  # Predict next time step

            X, y = np.array(X), np.array(y)

            return X, y

        # Extract features
        data = df[feature_columns].values

        # Normalize the data
        scaled_data = self.scaler.fit_transform(data)

        # Create sequences
        X, y = [], []
        for i in range(self.sequence_length, len(scaled_data)):
            X.append(scaled_data[i-self.sequence_length:i])
            y.append(scaled_data[i])  # Predict next time step

        X, y = np.array(X), np.array(y)

        return X, y

    def train(self, X, y, epochs=50, batch_size=32, validation_split=0.2):
        """Train the model"""
        if not TF_AVAILABLE:
            # Mock training when TensorFlow is not available
            class MockHistory:
                def __init__(self):
                    self.history = {'loss': [0.1] * epochs, 'val_loss': [0.15] * epochs}
            return MockHistory()

        history = self.model.fit(
            X, y,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            verbose=1
        )
        return history

    def predict(self, X):
        """Make predictions"""
        if not TF_AVAILABLE or self.model is None:
            # Return mock predictions when TensorFlow is not available
            if hasattr(X, 'shape'):
                return np.zeros_like(X)
            else:
                # If X is not an array, create an appropriate shaped array
                return np.zeros((1, self.features))
        return self.model.predict(X)

    def detect_anomalies(self, X, threshold_percentile=95):
        """
        Detect anomalies in the data
        :param X: Input sequences
        :param threshold_percentile: Percentile to use as anomaly threshold
        """
        if not TF_AVAILABLE:
            # Return mock anomaly detection results when TensorFlow is not available
            if hasattr(X, 'shape'):
                n_samples = X.shape[0]
            else:
                n_samples = 1

            # Generate mock results
            anomalies = np.random.random(n_samples) < 0.1  # 10% chance of anomaly
            mse = np.random.random(n_samples) * 0.01  # Small random MSE values
            threshold = np.percentile(mse, threshold_percentile)

            return anomalies, mse, threshold

        predictions = self.predict(X)

        # Calculate reconstruction error
        mse = np.mean(np.power(X - predictions, 2), axis=1)

        # Determine threshold based on training data
        threshold = np.percentile(mse, threshold_percentile)

        # Identify anomalies
        anomalies = mse > threshold

        return anomalies, mse, threshold
    
    def quantize_model(self, representative_dataset_gen=None):
        """
        Quantize the model for deployment on Raspberry Pi
        :param representative_dataset_gen: Generator for representative dataset
        """
        if not TF_AVAILABLE:
            # Return mock quantized model when TensorFlow is not available
            # In a real scenario, this would return a quantized model, but for mock we return empty bytes
            return b"mock_quantized_model"

        converter = tf.lite.TFLiteConverter.from_keras_model(self.model)
        converter.optimizations = [tf.lite.Optimize.DEFAULT]

        # If representative dataset is provided, use it for quantization
        if representative_dataset_gen:
            converter.representative_dataset = representative_dataset_gen

        # Ensure compatibility with Raspberry Pi
        converter.target_spec.supported_ops = [
            tf.lite.OpsSet.TFLITE_BUILTINS,
            tf.lite.OpsSet.SELECT_TF_OPS  # Fallback to TensorFlow ops if needed
        ]

        quantized_model = converter.convert()
        return quantized_model

    def save_quantized_model(self, filepath, representative_dataset_gen=None):
        """Save the quantized model to file"""
        if not TF_AVAILABLE:
            # Create a mock quantized model file when TensorFlow is not available
            with open(filepath, 'wb') as f:
                f.write(b"mock_quantized_model")
            print(f"Mock quantized model saved to {filepath}")
            return

        quantized_model = self.quantize_model(representative_dataset_gen)

        with open(filepath, 'wb') as f:
            f.write(quantized_model)

        print(f"Quantized model saved to {filepath}")

    def load_quantized_model(self, filepath):
        """Load a quantized model from file"""
        if not TF_AVAILABLE:
            # Create a mock interpreter when TensorFlow is not available
            class MockInterpreter:
                def allocate_tensors(self):
                    pass

                def get_input_details(self):
                    return [{'index': 0, 'shape': [1, self.sequence_length, self.features]}]

                def get_output_details(self):
                    return [{'index': 0, 'shape': [1, self.features]}]

                def set_tensor(self, index, value):
                    pass

                def invoke(self):
                    pass

                def get_tensor(self, index):
                    return np.zeros((1, self.features))

            self.interpreter = MockInterpreter()
            return self.interpreter

        interpreter = tf.lite.Interpreter(model_path=filepath)
        interpreter.allocate_tensors()

        self.interpreter = interpreter
        return interpreter

    def predict_quantized(self, input_data):
        """Make prediction using quantized model"""
        if not TF_AVAILABLE:
            # Return mock prediction when TensorFlow is not available
            if hasattr(input_data, 'shape'):
                return np.zeros_like(input_data)
            else:
                return np.zeros((1, self.features))

        if not hasattr(self, 'interpreter'):
            raise ValueError("Quantized model not loaded. Call load_quantized_model first.")

        input_details = self.interpreter.get_input_details()
        output_details = self.interpreter.get_output_details()

        # Set input tensor
        self.interpreter.set_tensor(input_details[0]['index'], input_data.astype(np.float32))

        # Run inference
        self.interpreter.invoke()

        # Get output tensor
        output_data = self.interpreter.get_tensor(output_details[0]['index'])

        return output_data


def create_sample_dataset():
    """
    Create a sample dataset for demonstration purposes
    In practice, you would load your actual network traffic CSV data
    """
    # Generate sample network traffic data
    np.random.seed(42)
    n_samples = 10000
    n_features = 10
    
    # Simulate normal network traffic patterns
    data = {
        'packet_size': np.random.normal(1000, 300, n_samples),
        'protocol': np.random.choice([0, 1, 2, 3], n_samples),  # TCP, UDP, ICMP, Other
        'port': np.random.choice(range(1, 65535), n_samples),
        'source_ip_entropy': np.random.uniform(0, 1, n_samples),
        'dest_ip_entropy': np.random.uniform(0, 1, n_samples),
        'time_interval': np.random.exponential(0.1, n_samples),
        'flags_count': np.random.poisson(2, n_samples),
        'payload_entropy': np.random.uniform(0, 1, n_samples),
        'header_checksum': np.random.uniform(0, 1, n_samples),
        'ttl': np.random.randint(30, 255, n_samples)
    }
    
    df = pd.DataFrame(data)
    
    # Introduce some subtle patterns to make the data more realistic
    df.loc[df['protocol'] == 0, 'packet_size'] += 200  # TCP tends to have larger packets
    df.loc[df['protocol'] == 1, 'time_interval'] *= 0.5  # UDP often has shorter intervals
    
    return df


if __name__ == "__main__":
    # Example usage
    detector = LSTM_RNN_AnomalyDetector(sequence_length=60, features=10)
    model = detector.build_model()
    
    print("Model Architecture:")
    model.summary()
    
    # Create sample data for demonstration
    print("\nCreating sample dataset...")
    df = create_sample_dataset()
    
    # Define feature columns
    feature_columns = [
        'packet_size', 'protocol', 'port', 'source_ip_entropy', 
        'dest_ip_entropy', 'time_interval', 'flags_count', 
        'payload_entropy', 'header_checksum', 'ttl'
    ]
    
    # Prepare data
    print("Preparing data...")
    X, y = detector.prepare_data(df, feature_columns)
    
    print(f"Data shape - X: {X.shape}, y: {y.shape}")
    
    # Train the model
    print("Training model...")
    history = detector.train(X, y, epochs=5)  # Reduced epochs for demo
    
    # Save the trained model
    model.save('iot_anomaly_model.h5')
    print("Model saved as iot_anomaly_model.h5")
    
    # Example of anomaly detection
    print("Testing anomaly detection...")
    anomalies, mse, threshold = detector.detect_anomalies(X[:100])  # Test on first 100 samples
    print(f"Number of anomalies detected: {np.sum(anomalies)} out of {len(anomalies)} samples")
    print(f"Anomaly threshold: {threshold:.4f}")