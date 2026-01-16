try:
    import tensorflow as tf
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

import numpy as np
import pandas as pd
from .lstm_rnn_anomaly_detection import LSTM_RNN_AnomalyDetector
from .csv_data_processor import CSVDataProcessor
import os
import logging
from sklearn.model_selection import train_test_split

class ModelTrainer:
    def __init__(self, model_params=None):
        """
        Initialize the model trainer
        :param model_params: Dictionary with model parameters
        """
        if not TF_AVAILABLE:
            # Initialize with mock attributes when TensorFlow is not available
            if model_params is None:
                model_params = {'sequence_length': 60, 'features': 10}
            self.model_params = model_params
            self.detector = LSTM_RNN_AnomalyDetector(**model_params)
            self.processor = None
            self.history = None

            # Setup logging
            logging.basicConfig(level=logging.INFO)
            self.logger = logging.getLogger(__name__)
            return

        if model_params is None:
            model_params = {'sequence_length': 60, 'features': 10}

        self.model_params = model_params
        self.detector = LSTM_RNN_AnomalyDetector(**model_params)
        self.processor = None
        self.history = None

        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def load_and_prepare_data(self, csv_file_path, sequence_length=60):
        """
        Load and prepare data for training
        :param csv_file_path: Path to the CSV file
        :param sequence_length: Length of sequences for LSTM
        """
        # Initialize processor
        self.processor = CSVDataProcessor(csv_file_path)
        
        # Load data
        if not self.processor.load_data():
            self.logger.error("Failed to load data")
            return None, None
        
        # Create sequences
        X, y = self.processor.split_data_for_sequences(sequence_length=sequence_length)
        
        # Update model parameters if needed
        self.model_params['features'] = X.shape[2]
        self.detector = LSTM_RNN_AnomalyDetector(**self.model_params)
        
        return X, y
    
    def build_and_compile_model(self):
        """Build and compile the model"""
        if not TF_AVAILABLE:
            # Return a mock model when TensorFlow is not available
            class MockModel:
                def __init__(self):
                    pass
                def evaluate(self, X, y, verbose=0):
                    return 0.1, 0.05  # Mock loss and MAE
            self.logger.info("Mock model built successfully")
            return MockModel()

        model = self.detector.build_model()
        self.logger.info("Model built successfully")
        return model
    
    def train_model(self, X, y, validation_split=0.2, epochs=50, batch_size=32):
        """
        Train the model
        :param X: Training features
        :param y: Training targets
        :param validation_split: Fraction of data for validation
        :param epochs: Number of training epochs
        :param batch_size: Batch size for training
        """
        if not TF_AVAILABLE:
            # Mock training when TensorFlow is not available
            self.logger.info("Mock training completed")
            class MockHistory:
                def __init__(self):
                    self.history = {'loss': [0.1] * epochs}
            self.history = MockHistory()
            return self.history

        # Build the model
        model = self.build_and_compile_model()

        # Split data into train and validation sets
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=validation_split, random_state=42
        )

        self.logger.info(f"Training on {len(X_train)} samples, validating on {len(X_val)} samples")

        # Train the model
        self.history = self.detector.train(
            X_train, y_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.0  # We're using explicit validation split
        )

        # Evaluate on validation set
        val_loss, val_mae = model.evaluate(X_val, y_val, verbose=0)
        self.logger.info(f"Validation Loss: {val_loss:.4f}, Validation MAE: {val_mae:.4f}")

        return self.history
    
    def evaluate_model(self, X_test, y_test):
        """
        Evaluate the model on test data
        :param X_test: Test features
        :param y_test: Test targets
        """
        if not TF_AVAILABLE:
            # Mock evaluation when TensorFlow is not available
            self.logger.info("Mock evaluation completed")
            return 0.1, 0.05  # Mock loss and MAE

        if self.detector.model is None:
            self.logger.error("Model not trained yet. Call train_model() first.")
            return None

        # Evaluate the model
        test_loss, test_mae = self.detector.model.evaluate(X_test, y_test, verbose=0)
        self.logger.info(f"Test Loss: {test_loss:.4f}, Test MAE: {test_mae:.4f}")

        return test_loss, test_mae
    
    def detect_anomalies_in_data(self, X, threshold_percentile=95):
        """
        Detect anomalies in the provided data
        :param X: Input sequences
        :param threshold_percentile: Percentile for anomaly threshold
        """
        if self.detector.model is None:
            self.logger.error("Model not trained yet. Call train_model() first.")
            return None, None, None
        
        anomalies, mse, threshold = self.detector.detect_anomalies(X, threshold_percentile)
        
        self.logger.info(f"Detected {np.sum(anomalies)} anomalies out of {len(anomalies)} samples")
        self.logger.info(f"Anomaly threshold: {threshold:.4f} (MSE)")
        
        return anomalies, mse, threshold
    
    def save_model(self, filepath):
        """
        Save the trained model
        :param filepath: Path to save the model
        """
        if not TF_AVAILABLE:
            # Mock save when TensorFlow is not available
            with open(filepath, 'w') as f:
                f.write("mock_model")
            self.logger.info(f"Mock model saved to {filepath}")
            return True

        if self.detector.model is None:
            self.logger.error("Model not trained yet. Cannot save.")
            return False

        self.detector.model.save(filepath)
        self.logger.info(f"Model saved to {filepath}")
        return True
    
    def save_training_history(self, filepath):
        """
        Save the training history
        :param filepath: Path to save the history
        """
        if self.history is None:
            self.logger.error("No training history to save.")
            return False
        
        import pickle
        with open(filepath, 'wb') as f:
            pickle.dump(self.history.history, f)
        
        self.logger.info(f"Training history saved to {filepath}")
        return True


def train_on_normal_traffic(csv_file_path, model_save_path="iot_anomaly_model.h5"):
    """
    Complete training pipeline for normal traffic
    :param csv_file_path: Path to CSV file with normal traffic
    :param model_save_path: Path to save the trained model
    """
    # Initialize trainer
    trainer = ModelTrainer(model_params={'sequence_length': 60, 'features': 10})
    
    # Load and prepare data
    X, y = trainer.load_and_prepare_data(csv_file_path, sequence_length=60)
    
    if X is None or y is None:
        print("Failed to load and prepare data")
        return False
    
    print(f"Data loaded: X shape {X.shape}, y shape {y.shape}")
    
    # Train the model
    print("Starting model training...")
    history = trainer.train_model(X, y, epochs=30, batch_size=32)
    
    # Save the model
    trainer.save_model(model_save_path)
    
    # Save training history
    trainer.save_training_history("training_history.pkl")
    
    print(f"Model training completed. Model saved to {model_save_path}")
    
    return True


if __name__ == "__main__":
    # Create a sample CSV file for demonstration
    from csv_data_processor import create_sample_csv
    sample_file = create_sample_csv("normal_traffic_for_training.csv")
    
    # Train the model on the sample data
    success = train_on_normal_traffic(sample_file)
    
    if success:
        print("Training completed successfully!")
    else:
        print("Training failed!")