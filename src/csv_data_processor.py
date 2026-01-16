import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
import logging

class CSVDataProcessor:
    def __init__(self, csv_file_path):
        """
        Initialize the CSV data processor
        :param csv_file_path: Path to the CSV file containing network traffic data
        """
        self.csv_file_path = csv_file_path
        self.data = None
        self.feature_columns = []
        self.label_encoder = LabelEncoder()
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def load_data(self):
        """Load the CSV data"""
        try:
            self.data = pd.read_csv(self.csv_file_path)
            self.logger.info(f"Loaded {len(self.data)} rows from {self.csv_file_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error loading CSV file: {e}")
            return False
    
    def preprocess_data(self, target_column=None):
        """
        Preprocess the data for neural network training
        :param target_column: Name of the target column (if any)
        """
        if self.data is None:
            self.logger.error("No data loaded. Call load_data() first.")
            return None
        
        # Make a copy to avoid modifying original data
        processed_data = self.data.copy()
        
        # Handle missing values
        processed_data = processed_data.fillna(processed_data.mean(numeric_only=True))
        
        # Identify numeric and categorical columns
        numeric_columns = processed_data.select_dtypes(include=[np.number]).columns.tolist()
        categorical_columns = processed_data.select_dtypes(include=['object']).columns.tolist()
        
        # Encode categorical variables
        for col in categorical_columns:
            if col != target_column:  # Don't encode target if specified
                processed_data[col] = self.label_encoder.fit_transform(processed_data[col].astype(str))
        
        # Select feature columns (all numeric columns after encoding)
        self.feature_columns = [col for col in processed_data.columns if col != target_column]
        
        # Log preprocessing info
        self.logger.info(f"Processed data shape: {processed_data.shape}")
        self.logger.info(f"Feature columns: {self.feature_columns}")
        
        return processed_data
    
    def extract_features(self, feature_config=None):
        """
        Extract relevant features for anomaly detection
        :param feature_config: Dictionary specifying which features to extract
        """
        if self.data is None:
            self.logger.error("No data loaded. Call load_data() first.")
            return None
        
        # Default feature extraction for network traffic
        default_features = {
            'packet_size': 'len',
            'protocol': 'proto',
            'source_port': 'sport',
            'destination_port': 'dport',
            'source_ip_entropy': 'src_ip_entropy',
            'destination_ip_entropy': 'dst_ip_entropy',
            'time_interval': 'time_delta',
            'tcp_flags': 'tcp_flags',
            'ttl': 'ttl',
            'payload_entropy': 'payload_entropy'
        }
        
        # If custom config provided, use it
        if feature_config:
            features_to_extract = feature_config
        else:
            features_to_extract = default_features
        
        extracted_data = pd.DataFrame()
        
        # Extract each feature
        for feature_name, column_name in features_to_extract.items():
            if column_name in self.data.columns:
                extracted_data[feature_name] = self.data[column_name]
            else:
                # If the column doesn't exist, create synthetic data for demo
                self.logger.warning(f"Column '{column_name}' not found. Creating synthetic data for '{feature_name}'.")
                
                if 'size' in feature_name or 'entropy' in feature_name:
                    # For size and entropy features, use random values in reasonable ranges
                    extracted_data[feature_name] = np.random.uniform(0, 1, len(self.data))
                elif 'port' in feature_name:
                    extracted_data[feature_name] = np.random.randint(1, 65535, len(self.data))
                elif 'protocol' in feature_name:
                    extracted_data[feature_name] = np.random.choice([0, 1, 2, 3], len(self.data))  # TCP, UDP, ICMP, Other
                elif 'interval' in feature_name:
                    extracted_data[feature_name] = np.random.exponential(0.1, len(self.data))
                elif 'flags' in feature_name:
                    extracted_data[feature_name] = np.random.poisson(2, len(self.data))
                elif 'ttl' in feature_name:
                    extracted_data[feature_name] = np.random.randint(30, 255, len(self.data))
                else:
                    extracted_data[feature_name] = np.random.normal(0, 1, len(self.data))
        
        # Normalize the features
        from sklearn.preprocessing import StandardScaler
        scaler = StandardScaler()
        normalized_data = pd.DataFrame(
            scaler.fit_transform(extracted_data),
            columns=extracted_data.columns
        )
        
        self.logger.info(f"Extracted {len(normalized_data.columns)} features from the dataset")
        return normalized_data
    
    def split_data_for_sequences(self, sequence_length=60):
        """
        Split the data into sequences for LSTM/RNN training
        :param sequence_length: Length of each sequence (number of packets)
        """
        if self.data is None:
            self.logger.error("No data loaded. Call load_data() first.")
            return None, None
        
        # Extract features
        features_df = self.extract_features()
        
        # Convert to numpy array
        data_array = features_df.values
        
        # Create sequences
        X, y = [], []
        for i in range(sequence_length, len(data_array)):
            X.append(data_array[i-sequence_length:i])
            y.append(data_array[i])  # Predict the next time step
        
        X, y = np.array(X), np.array(y)
        
        self.logger.info(f"Created {len(X)} sequences of length {sequence_length}")
        return X, y
    
    def get_statistics(self):
        """Get statistics about the loaded data"""
        if self.data is None:
            return None
        
        stats = {
            'total_rows': len(self.data),
            'total_columns': len(self.data.columns),
            'column_names': list(self.data.columns),
            'missing_values': self.data.isnull().sum().to_dict(),
            'data_types': self.data.dtypes.to_dict(),
            'numeric_summary': self.data.describe().to_dict() if len(self.data.select_dtypes(include=[np.number])) > 0 else {}
        }
        
        return stats


def create_sample_csv(filename="normal_traffic_sample.csv"):
    """
    Create a sample CSV file with normal network traffic data
    """
    import random
    from datetime import datetime, timedelta
    
    # Generate sample data
    n_samples = 10000
    
    # Create timestamps
    start_time = datetime.now() - timedelta(hours=24)
    timestamps = [start_time + timedelta(seconds=i*random.uniform(0.001, 0.1)) for i in range(n_samples)]
    
    # Generate network traffic features
    data = {
        'timestamp': timestamps,
        'src_ip': [f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(n_samples)],
        'dst_ip': [f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(n_samples)],
        'src_port': [random.choice([22, 80, 443, 8080, 3389, random.randint(1024, 65535)]) for _ in range(n_samples)],
        'dst_port': [random.choice([22, 80, 443, 8080, 3389, random.randint(1024, 65535)]) for _ in range(n_samples)],
        'protocol': [random.choice(['TCP', 'UDP', 'ICMP']) for _ in range(n_samples)],
        'length': [random.randint(40, 1500) for _ in range(n_samples)],  # Packet length
        'ttl': [random.randint(30, 64) for _ in range(n_samples)],
        'tcp_flags': [random.choice([0, 2, 18, 16, 1]) for _ in range(n_samples)],  # Common TCP flags
        'window_size': [random.randint(1000, 65535) for _ in range(n_samples)],
    }
    
    df = pd.DataFrame(data)
    
    # Save to CSV
    df.to_csv(filename, index=False)
    print(f"Sample CSV file created: {filename}")
    return filename


if __name__ == "__main__":
    # Create a sample CSV file for demonstration
    sample_file = create_sample_csv()
    
    # Initialize the processor
    processor = CSVDataProcessor(sample_file)
    
    # Load the data
    success = processor.load_data()
    
    if success:
        # Get statistics
        stats = processor.get_statistics()
        print("Dataset Statistics:")
        for key, value in stats.items():
            if key != 'numeric_summary':
                print(f"  {key}: {value}")
        
        # Extract features
        features = processor.extract_features()
        print(f"\nExtracted features shape: {features.shape}")
        print(f"Features: {list(features.columns)}")
        
        # Create sequences
        X, y = processor.split_data_for_sequences(sequence_length=60)
        print(f"Sequences shape - X: {X.shape}, y: {y.shape}")
    else:
        print("Failed to load data")