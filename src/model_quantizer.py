try:
    import tensorflow as tf
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

import numpy as np
import os
import logging
from .lstm_rnn_anomaly_detection import LSTM_RNN_AnomalyDetector

class ModelQuantizer:
    def __init__(self, model_path=None, detector_instance=None):
        """
        Initialize the model quantizer
        :param model_path: Path to the saved Keras model
        :param detector_instance: Instance of LSTM_RNN_AnomalyDetector
        """
        self.model_path = model_path
        self.detector = detector_instance
        self.quantized_model = None
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def load_model(self):
        """Load the trained model"""
        if not TF_AVAILABLE:
            # Mock loading when TensorFlow is not available
            self.detector = LSTM_RNN_AnomalyDetector()
            # Initialize a mock model
            self.detector.model = None
            self.logger.info("Mock model loaded for quantization")
            return True

        if self.model_path and os.path.exists(self.model_path):
            # Load using TensorFlow/Keras
            model = tf.keras.models.load_model(self.model_path)
            self.detector = LSTM_RNN_AnomalyDetector()
            self.detector.model = model
            self.logger.info(f"Model loaded from {self.model_path}")
            return True
        elif self.detector and self.detector.model:
            self.logger.info("Using provided detector instance")
            return True
        else:
            self.logger.error("No model found to quantize")
            return False
    
    def create_representative_dataset(self, data_generator, num_samples=100):
        """
        Create a representative dataset for quantization
        :param data_generator: Generator that yields input data for the model
        :param num_samples: Number of samples to use for quantization
        """
        def representative_data_gen():
            count = 0
            for data in data_generator:
                # Ensure data is in the right shape for the model
                if len(data.shape) == 2:
                    # Add batch dimension if needed
                    data = np.expand_dims(data, axis=0)
                
                yield [data.astype(np.float32)]
                
                count += 1
                if count >= num_samples:
                    break
        
        return representative_data_gen
    
    def quantize_model(self, representative_dataset_gen=None, optimization_type="dynamic"):
        """
        Quantize the model for Raspberry Pi deployment
        :param representative_dataset_gen: Generator for representative dataset
        :param optimization_type: Type of quantization ('dynamic', 'static', 'float16', 'int8')
        """
        if not TF_AVAILABLE:
            # Mock quantization when TensorFlow is not available
            self.logger.info(f"Mock model quantized successfully using {optimization_type} optimization")
            self.quantized_model = b"mock_quantized_model"
            return self.quantized_model

        if not self.load_model():
            return None

        # Convert the model to TensorFlow Lite format
        converter = tf.lite.TFLiteConverter.from_keras_model(self.detector.model)

        # Apply optimizations based on the selected type
        if optimization_type == "dynamic":
            # Dynamic range quantization (default)
            converter.optimizations = [tf.lite.Optimize.DEFAULT]
        elif optimization_type == "static":
            # Full integer quantization with representative dataset
            converter.optimizations = [tf.lite.Optimize.DEFAULT]
            if representative_dataset_gen:
                converter.representative_dataset = representative_dataset_gen
            else:
                self.logger.warning("Static quantization requires a representative dataset. Using dynamic quantization instead.")
                converter.optimizations = [tf.lite.Optimize.DEFAULT]
        elif optimization_type == "float16":
            # Float16 quantization
            converter.optimizations = [tf.lite.Optimize.DEFAULT]
            converter.target_spec.supported_types = [tf.float16]
        elif optimization_type == "int8":
            # INT8 quantization
            converter.optimizations = [tf.lite.Optimize.DEFAULT]
            if representative_dataset_gen:
                converter.representative_dataset = representative_dataset_gen
                converter.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]
                converter.inference_input_type = tf.int8
                converter.inference_output_type = tf.int8
            else:
                self.logger.warning("INT8 quantization requires a representative dataset. Using dynamic quantization instead.")
                converter.optimizations = [tf.lite.Optimize.DEFAULT]
        else:
            self.logger.error(f"Unknown optimization type: {optimization_type}. Using dynamic quantization.")
            converter.optimizations = [tf.lite.Optimize.DEFAULT]

        # Ensure compatibility with Raspberry Pi
        converter.target_spec.supported_ops = [
            tf.lite.OpsSet.TFLITE_BUILTINS,
            tf.lite.OpsSet.SELECT_TF_OPS  # Fallback to TensorFlow ops if needed
        ]

        try:
            # Convert the model
            self.quantized_model = converter.convert()
            self.logger.info(f"Model quantized successfully using {optimization_type} optimization")
            return self.quantized_model
        except Exception as e:
            self.logger.error(f"Error during model quantization: {e}")
            return None
    
    def save_quantized_model(self, output_path):
        """
        Save the quantized model to a file
        :param output_path: Path to save the quantized model
        """
        if self.quantized_model is None:
            self.logger.error("No quantized model to save. Run quantize_model() first.")
            return False
        
        try:
            with open(output_path, 'wb') as f:
                f.write(self.quantized_model)
            self.logger.info(f"Quantized model saved to {output_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving quantized model: {e}")
            return False
    
    def get_model_size_info(self, original_model_path=None, quantized_model_path=None):
        """
        Get size information for original and quantized models
        :param original_model_path: Path to original model
        :param quantized_model_path: Path to quantized model
        """
        info = {}
        
        if original_model_path and os.path.exists(original_model_path):
            original_size = os.path.getsize(original_model_path)
            info['original_size_bytes'] = original_size
            info['original_size_mb'] = round(original_size / (1024 * 1024), 2)
        
        if quantized_model_path and os.path.exists(quantized_model_path):
            quantized_size = os.path.getsize(quantized_model_path)
            info['quantized_size_bytes'] = quantized_size
            info['quantized_size_mb'] = round(quantized_size / (1024 * 1024), 2)
        
        if 'original_size_bytes' in info and 'quantized_size_bytes' in info:
            reduction = (info['original_size_bytes'] - info['quantized_size_bytes']) / info['original_size_bytes'] * 100
            info['size_reduction_percent'] = round(reduction, 2)
        
        return info
    
    def benchmark_model(self, tflite_model_path, input_shape, num_runs=100):
        """
        Benchmark the quantized model performance
        :param tflite_model_path: Path to the TFLite model
        :param input_shape: Shape of input data
        :param num_runs: Number of inference runs for benchmarking
        """
        import time
        
        # Load the TFLite model and allocate tensors
        interpreter = tf.lite.Interpreter(model_path=tflite_model_path)
        interpreter.allocate_tensors()
        
        # Get input and output tensors
        input_details = interpreter.get_input_details()
        output_details = interpreter.get_output_details()
        
        # Generate random input data
        input_data = np.random.random_sample(input_shape).astype(np.float32)
        
        # Warmup runs
        for _ in range(10):
            interpreter.set_tensor(input_details[0]['index'], input_data)
            interpreter.invoke()
            output_data = interpreter.get_tensor(output_details[0]['index'])
        
        # Benchmark runs
        start_time = time.time()
        for _ in range(num_runs):
            interpreter.set_tensor(input_details[0]['index'], input_data)
            interpreter.invoke()
            output_data = interpreter.get_tensor(output_details[0]['index'])
        end_time = time.time()
        
        avg_time = (end_time - start_time) / num_runs
        self.logger.info(f"Average inference time: {avg_time*1000:.2f} ms")
        
        return avg_time


def quantize_for_raspberry_pi(model_path, output_path="quantized_iot_anomaly_model.tflite", 
                             data_generator=None, optimization_type="int8"):
    """
    Complete quantization pipeline for Raspberry Pi
    :param model_path: Path to the saved Keras model
    :param output_path: Path to save the quantized model
    :param data_generator: Generator for representative dataset (for static/INT8 quantization)
    :param optimization_type: Type of quantization to apply
    """
    # Initialize quantizer
    quantizer = ModelQuantizer(model_path=model_path)
    
    # Create representative dataset generator if not provided
    if data_generator is None:
        # Create a dummy generator for demonstration
        def dummy_data_gen():
            # Generate dummy data matching the expected input shape
            # Assuming sequence_length=60, features=10 based on our model
            for _ in range(100):  # 100 samples
                dummy_input = np.random.random((60, 10)).astype(np.float32)
                yield dummy_input
        
        data_generator = dummy_data_gen()
    
    # Create representative dataset
    representative_dataset = quantizer.create_representative_dataset(data_generator, num_samples=100)
    
    # Quantize the model
    quantized_model = quantizer.quantize_model(
        representative_dataset_gen=representative_dataset,
        optimization_type=optimization_type
    )
    
    if quantized_model is None:
        print("Model quantization failed!")
        return False
    
    # Save the quantized model
    success = quantizer.save_quantized_model(output_path)
    
    if not success:
        print("Failed to save quantized model!")
        return False
    
    # Print size comparison
    size_info = quantizer.get_model_size_info(
        original_model_path=model_path,
        quantized_model_path=output_path
    )
    
    print("Model Size Information:")
    for key, value in size_info.items():
        print(f"  {key}: {value}")
    
    # Benchmark the model (optional)
    try:
        avg_time = quantizer.benchmark_model(
            tflite_model_path=output_path,
            input_shape=(1, 60, 10),  # (batch_size, sequence_length, features)
            num_runs=50
        )
        print(f"Average inference time on this machine: {avg_time*1000:.2f} ms")
    except Exception as e:
        print(f"Benchmarking failed: {e}")
    
    print(f"Model successfully quantized and saved to {output_path}")
    return True


if __name__ == "__main__":
    # Example usage
    # Note: This requires a trained model to be available
    # For demonstration, we'll create a dummy model first
    
    # First, let's train a model if one doesn't exist
    import os
    model_path = "iot_anomaly_model.h5"
    
    if not os.path.exists(model_path):
        print("No trained model found. Training a model first...")
        from model_trainer import train_on_normal_traffic
        from csv_data_processor import create_sample_csv
        
        # Create sample data
        sample_file = create_sample_csv("normal_traffic_for_quantization.csv")
        
        # Train model
        train_success = train_on_normal_traffic(sample_file, model_path)
        
        if not train_success:
            print("Failed to train model for quantization demo")
            exit(1)
    
    # Now quantize the model
    print("Starting model quantization for Raspberry Pi...")
    
    def sample_data_generator():
        """Generator for sample data for quantization"""
        # Load some sample data to use for quantization
        from csv_data_processor import CSVDataProcessor
        
        # Create sample data if needed
        sample_file = "normal_traffic_for_quantization.csv"
        if not os.path.exists(sample_file):
            create_sample_csv(sample_file)
        
        processor = CSVDataProcessor(sample_file)
        processor.load_data()
        
        # Get sequences for quantization
        X, _ = processor.split_data_for_sequences(sequence_length=60)
        
        # Yield samples for quantization
        for i in range(min(100, len(X))):  # Use up to 100 samples
            yield X[i]
    
    # Perform quantization
    success = quantize_for_raspberry_pi(
        model_path=model_path,
        output_path="quantized_iot_anomaly_model.tflite",
        data_generator=sample_data_generator(),
        optimization_type="int8"
    )
    
    if success:
        print("Quantization completed successfully!")
    else:
        print("Quantization failed!")