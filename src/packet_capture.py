import threading
import time
import queue
import numpy as np
from collections import defaultdict, deque
import socket
import struct
from datetime import datetime
import logging

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not available. Packet capture will be limited.")

# Import status model
try:
    from status_model import status_model
except ImportError:
    # Create a mock status model if the real one isn't available
    class MockStatusModel:
        def increment_packets_captured(self, count=1):
            pass

    status_model = MockStatusModel()

class PacketCapture:
    def __init__(self, target_ips=None, interface=None):
        """
        Initialize packet capture
        :param target_ips: List of target IPs to monitor
        :param interface: Network interface to capture on (None for default)
        """
        self.target_ips = target_ips or []
        self.interface = interface
        self.capture_thread = None
        self.is_capturing = False
        self.packet_queue = queue.Queue()
        self.packet_buffer = defaultdict(lambda: deque(maxlen=60))  # Buffer 60 packets per IP
        self.stats = {
            'packets_captured': 0,
            'bytes_captured': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def start_capture(self):
        """Start packet capture in a separate thread"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy is not available. Cannot start packet capture.")
            return False
        
        if self.is_capturing:
            self.logger.warning("Packet capture already running")
            return False
        
        self.is_capturing = True
        self.stats['start_time'] = datetime.now()
        
        # Start capture thread
        self.capture_thread = threading.Thread(target=self._capture_packets, daemon=True)
        self.capture_thread.start()
        
        self.logger.info("Packet capture started")
        return True
    
    def stop_capture(self):
        """Stop packet capture"""
        if not self.is_capturing:
            return
        
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)  # Wait up to 2 seconds for thread to finish
        
        self.stats['end_time'] = datetime.now()
        self.logger.info(f"Packet capture stopped. Captured {self.stats['packets_captured']} packets")
    
    def _capture_packets(self):
        """Internal method to capture packets"""
        try:
            # Define filter based on target IPs
            if self.target_ips:
                ip_filter = " or ".join([f"host {ip}" for ip in self.target_ips])
                capture_filter = f"({ip_filter}) and (ip or tcp or udp)"
            else:
                capture_filter = "ip and (tcp or udp)"
            
            # Start sniffing
            scapy.sniff(
                iface=self.interface,
                filter=capture_filter,
                prn=self._process_packet,
                stop_filter=lambda x: not self.is_capturing
            )
        except Exception as e:
            self.logger.error(f"Error during packet capture: {e}")
    
    def _process_packet(self, packet):
        """Process each captured packet"""
        if not self.is_capturing:
            return

        # Extract packet information
        try:
            packet_info = self._extract_packet_features(packet)

            if packet_info:
                # Add to buffer for the source IP
                src_ip = packet_info['src_ip']
                self.packet_buffer[src_ip].append(packet_info)

                # Add to queue for processing
                self.packet_queue.put(packet_info)

                # Update stats
                self.stats['packets_captured'] += 1
                if 'length' in packet_info:
                    self.stats['bytes_captured'] += packet_info['length']

                # Update status model
                status_model.increment_packets_captured(1)

        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def _extract_packet_features(self, packet):
        """Extract features from a packet for anomaly detection"""
        if IP not in packet:
            return None
        
        ip_layer = packet[IP]
        
        # Basic IP information
        packet_features = {
            'timestamp': float(packet.time),
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'length': len(packet),
            'ttl': ip_layer.ttl if ip_layer.ttl is not None else 64,
            'protocol': ip_layer.proto,
            'version': ip_layer.version
        }
        
        # Protocol-specific information
        if TCP in packet:
            tcp_layer = packet[TCP]
            packet_features.update({
                'protocol_type': 'TCP',
                'src_port': tcp_layer.sport,
                'dst_port': tcp_layer.dport,
                'tcp_flags': tcp_layer.flags,
                'window_size': tcp_layer.window,
                'seq_num': tcp_layer.seq,
                'ack_num': tcp_layer.ack
            })
        elif UDP in packet:
            udp_layer = packet[UDP]
            packet_features.update({
                'protocol_type': 'UDP',
                'src_port': udp_layer.sport,
                'dst_port': udp_layer.dport,
                'udp_len': udp_layer.len
            })
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            packet_features.update({
                'protocol_type': 'ICMP',
                'icmp_type': icmp_layer.type,
                'icmp_code': icmp_layer.code
            })
        else:
            packet_features['protocol_type'] = 'OTHER'
        
        # Calculate additional features
        payload = bytes(packet[IP].payload)
        packet_features['payload_size'] = len(payload)
        packet_features['payload_entropy'] = self._calculate_entropy(payload)
        
        # Calculate IP address entropy (as a measure of randomness)
        packet_features['src_ip_entropy'] = self._calculate_ip_entropy(ip_layer.src)
        packet_features['dst_ip_entropy'] = self._calculate_ip_entropy(ip_layer.dst)
        
        return packet_features
    
    def _calculate_entropy(self, data):
        """Calculate entropy of byte data"""
        if not data:
            return 0.0
        
        # Count frequency of each byte
        freq_map = {}
        for byte in data:
            freq_map[byte] = freq_map.get(byte, 0) + 1
        
        # Calculate entropy
        ent = 0.0
        data_len = len(data)
        for freq in freq_map.values():
            probability = freq / data_len
            ent -= probability * np.log2(probability)
        
        return ent
    
    def _calculate_ip_entropy(self, ip_str):
        """Calculate entropy of IP address string"""
        return self._calculate_entropy(ip_str.encode('utf-8'))
    
    def get_packets_for_ip(self, ip, count=60):
        """Get the last N packets for a specific IP"""
        if ip in self.packet_buffer:
            packets = list(self.packet_buffer[ip])
            # Return the last 'count' packets
            return packets[-count:] if len(packets) >= count else packets
        return []
    
    def get_recent_packets(self, count=10):
        """Get the most recently captured packets"""
        packets = []
        while not self.packet_queue.empty() and len(packets) < count:
            try:
                packets.append(self.packet_queue.get_nowait())
            except queue.Empty:
                break
        return packets
    
    def has_enough_packets_for_analysis(self, ip, required_count=60):
        """Check if we have enough packets for analysis for a specific IP"""
        return len(self.packet_buffer[ip]) >= required_count
    
    def get_network_stats(self):
        """Get current network statistics"""
        duration = None
        if self.stats['start_time']:
            end_time = self.stats['end_time'] or datetime.now()
            duration = (end_time - self.stats['start_time']).total_seconds()
        
        return {
            **self.stats,
            'duration_seconds': duration,
            'packets_per_second': self.stats['packets_captured'] / duration if duration and duration > 0 else 0,
            'bytes_per_second': self.stats['bytes_captured'] / duration if duration and duration > 0 else 0
        }


class PacketAnalyzer:
    def __init__(self):
        """Initialize packet analyzer"""
        self.feature_columns = [
            'length', 'ttl', 'protocol', 'src_port', 'dst_port', 
            'tcp_flags', 'window_size', 'payload_size', 
            'payload_entropy', 'src_ip_entropy', 'dst_ip_entropy'
        ]
    
    def extract_features_for_ml(self, packet_sequence):
        """
        Extract features from a sequence of packets for ML model
        :param packet_sequence: List of packet dictionaries
        :return: Normalized feature array
        """
        if not packet_sequence:
            return np.array([])
        
        # Create a matrix of features
        features_matrix = []
        
        for packet in packet_sequence:
            features = []
            
            # Add numerical features
            features.append(packet.get('length', 0) / 1500.0)  # Normalize packet length
            features.append(packet.get('ttl', 64) / 255.0)  # Normalize TTL
            features.append(packet.get('protocol', 0) / 255.0)  # Normalize protocol
            
            # Source port (normalize to 0-1)
            src_port = packet.get('src_port', 0)
            features.append(src_port / 65535.0 if src_port else 0)
            
            # Destination port (normalize to 0-1)
            dst_port = packet.get('dst_port', 0)
            features.append(dst_port / 65535.0 if dst_port else 0)
            
            # TCP flags (if available)
            tcp_flags = packet.get('tcp_flags', 0)
            features.append(tcp_flags / 255.0 if tcp_flags else 0)
            
            # Window size (normalize to 0-1)
            window_size = packet.get('window_size', 0)
            features.append(window_size / 65535.0 if window_size else 0)
            
            # Payload size (normalize to 0-1)
            payload_size = packet.get('payload_size', 0)
            features.append(payload_size / 1500.0 if payload_size else 0)
            
            # Payload entropy (already 0-8 range, normalize to 0-1)
            payload_entropy = packet.get('payload_entropy', 0)
            features.append(payload_entropy / 8.0 if payload_entropy else 0)
            
            # Source IP entropy (normalize to 0-1)
            src_ip_entropy = packet.get('src_ip_entropy', 0)
            features.append(src_ip_entropy / 8.0 if src_ip_entropy else 0)
            
            # Destination IP entropy (normalize to 0-1)
            dst_ip_entropy = packet.get('dst_ip_entropy', 0)
            features.append(dst_ip_entropy / 8.0 if dst_ip_entropy else 0)
            
            features_matrix.append(features)
        
        return np.array(features_matrix)
    
    def prepare_sequence_for_model(self, packet_sequence, sequence_length=60, feature_count=10):
        """
        Prepare a sequence of packets for the LSTM/RNN model
        :param packet_sequence: List of packet dictionaries
        :param sequence_length: Required sequence length (default 60)
        :param feature_count: Number of features per packet
        :return: Array ready for model input
        """
        if len(packet_sequence) < sequence_length:
            # Pad with zeros if we don't have enough packets
            padded_sequence = [self._get_zero_packet_features()] * (sequence_length - len(packet_sequence))
            padded_sequence.extend(packet_sequence)
            packet_sequence = padded_sequence
        elif len(packet_sequence) > sequence_length:
            # Take the most recent packets
            packet_sequence = packet_sequence[-sequence_length:]
        
        # Extract features
        features = self.extract_features_for_ml(packet_sequence)
        
        # Ensure we have the right shape
        if features.shape[0] != sequence_length or features.shape[1] != feature_count:
            # Reshape or pad as needed
            if features.shape[0] < sequence_length:
                # Pad with zeros
                padding_needed = sequence_length - features.shape[0]
                padding = np.zeros((padding_needed, feature_count))
                features = np.vstack([padding, features])
            elif features.shape[0] > sequence_length:
                # Take last sequence_length packets
                features = features[-sequence_length:]
            
            if features.shape[1] < feature_count:
                # Pad features
                padding_needed = feature_count - features.shape[1]
                padding = np.zeros((features.shape[0], padding_needed))
                features = np.hstack([features, padding])
            elif features.shape[1] > feature_count:
                # Truncate features
                features = features[:, :feature_count]
        
        # Reshape for LSTM: (1, sequence_length, features)
        return features.reshape(1, sequence_length, feature_count)
    
    def _get_zero_packet_features(self):
        """Get a zero-filled packet feature vector"""
        return [0.0] * 11  # Based on our feature extraction


if __name__ == "__main__":
    if not SCAPY_AVAILABLE:
        print("Scapy is not available. Install it with: pip install scapy")
        exit(1)
    
    # Example usage
    print("Initializing packet capture...")
    
    # Create a capture instance for specific IPs
    target_ips = ["192.168.1.1", "192.168.1.2", "192.168.1.100"]
    capturer = PacketCapture(target_ips=target_ips)
    
    # Start capturing
    if capturer.start_capture():
        print("Packet capture started. Waiting for packets...")
        
        # Let it run for a while to collect packets
        time.sleep(10)
        
        # Stop capture
        capturer.stop_capture()
        
        # Print stats
        stats = capturer.get_network_stats()
        print(f"Captured {stats['packets_captured']} packets in {stats['duration_seconds']:.2f} seconds")
        
        # Show packets for each IP
        for ip in target_ips:
            packets = capturer.get_packets_for_ip(ip, count=5)  # Last 5 packets
            print(f"\nPackets for {ip}:")
            for i, pkt in enumerate(packets):
                print(f"  {i+1}: {pkt.get('length', 0)} bytes, {pkt.get('protocol_type', 'UNKNOWN')} from {pkt.get('src_port', 'N/A')} to {pkt.get('dst_port', 'N/A')}")
    
    # Example of preparing packets for ML model
    print("\nTesting packet preparation for ML model...")
    analyzer = PacketAnalyzer()
    
    # Simulate a sequence of packets
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
    
    prepared_sequence = analyzer.prepare_sequence_for_model(mock_packets)
    print(f"Prepared sequence shape: {prepared_sequence.shape}")
    print("Packet capture functionality implemented successfully!")