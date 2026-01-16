from flask import Flask, render_template, jsonify, request
import subprocess
import socket
import threading
import time
import psutil
import json
from datetime import datetime
import os

# Try to import nmap, but don't fail if it's not available
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

app = Flask(__name__)

class NetworkScanner:
    def __init__(self):
        self.active_hosts = []
        self.scan_results = {}
        self.network_interfaces = []
        
    def get_network_interfaces(self):
        """Get all available network interfaces"""
        interfaces = psutil.net_if_addrs()
        result = []
        
        for interface_name, interface_addresses in interfaces.items():
            for address in interface_addresses:
                if str(address.family) == 'AddressFamily.AF_INET':
                    result.append({
                        'name': interface_name,
                        'address': address.address,
                        'netmask': address.netmask
                    })
        
        self.network_interfaces = result
        return result
    
    def scan_network_arp(self, network_range=None):
        """Scan network using arp-scan --localnet (much faster than nmap)"""
        try:
            import subprocess
            import re

            # Run arp-scan command with --localnet option
            result = subprocess.run(['arp-scan', '--local'],
                                  capture_output=True, text=True, check=True)

            hosts = []
            # Parse arp-scan output
            lines = result.stdout.split('\n')
            for line in lines:
                # Look for lines with IP and MAC address
                match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s+(.+)', line.strip())
                if match:
                    ip, mac, hostname = match.groups()
                    # Get vendor from MAC address (first 3 octets)
                    vendor_prefix = mac[:8].upper().replace(':', '-')
                    vendor = self.get_vendor_from_mac(vendor_prefix)

                    host_info = {
                        'ip': ip,
                        'hostname': hostname if hostname != '' and hostname != '<unknown>' else 'Unknown',
                        'status': 'up',
                        'mac_address': mac,
                        'vendor': vendor
                    }
                    hosts.append(host_info)

            self.active_hosts = hosts
            return hosts

        except subprocess.CalledProcessError as e:
            print(f"Error during arp-scan: {e}")
            # Fallback to nmap if arp-scan fails
            return self.scan_network_nmap_fallback(network_range or "192.168.1.0/24")
        except FileNotFoundError:
            print("arp-scan not found, falling back to nmap")
            # If arp-scan is not installed, fall back to nmap
            return self.scan_network_nmap_fallback(network_range or "192.168.1.0/24")
        except Exception as e:
            print(f"Error during arp-scan: {e}")
            return []

    def scan_network_nmap_fallback(self, network_range="192.168.1.0/24"):
        """Fallback scan using nmap if arp-scan is unavailable"""
        if not NMAP_AVAILABLE:
            print("nmap not available, falling back to ping scan")
            # Use the ping_scan method as another fallback
            return self.ping_scan(network_range.split('/')[0].rsplit('.', 1)[0] + '.', 1, 10)  # Scan first 10 hosts

        try:
            nm = nmap.PortScanner()

            # Perform host discovery scan
            scan_result = nm.scan(hosts=network_range, arguments='-sn')

            hosts = []
            for host in nm.all_hosts():
                host_info = {
                    'ip': host,
                    'hostname': nm[host].hostname() if nm[host].hostname() else 'Unknown',
                    'status': nm[host].state(),
                    'mac_address': 'N/A',
                    'vendor': 'N/A'
                }

                # Get MAC address if available
                if 'mac' in nm[host]['addresses']:
                    host_info['mac_address'] = nm[host]['addresses']['mac']

                # Get vendor information if available
                if 'vendor' in nm[host] and nm[host]['vendor']:
                    vendors = list(nm[host]['vendor'].values())
                    if vendors:
                        host_info['vendor'] = vendors[0]

                hosts.append(host_info)

            self.active_hosts = hosts
            return hosts

        except Exception as e:
            print(f"Error during nmap scan: {e}")
            return []

    def get_vendor_from_mac(self, mac_prefix):
        """Get vendor name from MAC address prefix"""
        # This is a simplified vendor lookup - in production, you'd use a full OUI database
        vendor_db = {
            '00:50:43': 'Siemens AG',
            '00:50:BA': 'Molex Canada Ltd',
            '00:60:23': '3COM CORPORATION',
            '00:80:A0': 'AMD',
            '00:E0:4C': 'REALTEK SEMICONDUCTOR CORP.',
            '08:00:20': 'SUN MICROSYSTEMS INC.',
            '08:00:27': 'PCS Systemtechnik GmbH',
            '10:C3:7B': 'SHENZHEN JUCHIN TECHNOLOGY CO., LTD',
            '18:65:90': 'Asia Optical Co., Inc.',
            '24:4B:03': 'Samsung Electronics Co.,Ltd',
            '28:C6:3F': 'Intel Corporate',
            '30:39:F2': 'Apple, Inc.',
            '38:4F:F0': 'Samsung Electronics Co.,Ltd',
            '40:B0:FA': 'LG Electronics (Mobile Communications)',
            '44:D9:E7': 'Ubiquiti Networks Inc.',
            '50:7B:9D': 'LCFC(HeFei) Electronics Technology co., ltd',
            '54:A0:50': 'Samsung Electronics Co.,Ltd',
            '60:02:B4': 'Wistron Neweb Corporation',
            '6C:72:E7': 'Apple, Inc.',
            '70:85:C2': 'ASUSTek COMPUTER INC.',
            '78:AC:C0': 'Liteon Technology Corporation',
            '80:FA:5B': 'CLEVO CO.',
            '84:8F:69': 'Dell Inc.',
            '88:51:FB': 'Hewlett Packard Enterprise',
            '9C:93:4E': 'Xerox Corporation',
            'A4:5D:36': 'Hewlett Packard',
            'AC:DE:48': 'Private',
            'B8:27:EB': 'Raspberry Pi Foundation',
            'BC:EE:7B': 'Green Wave Telecommunications SA',
            'C8:60:00': 'ASUSTek COMPUTER INC.',
            'CC:B2:55': 'D-Link International',
            'DC:A6:32': 'Raspberry Pi Foundation',
            'EC:43:F6': 'Dell Inc.',
            'F0:18:98': 'RUNCO International',
            'F4:CE:46': 'Hewlett Packard',
            'F8:DB:88': 'Dell Inc.'
        }

        return vendor_db.get(mac_prefix, 'Unknown Vendor')
    
    def ping_scan(self, network_base="192.168.1.", start=1, end=254):
        """Simple ping scan of a network range"""
        active_hosts = []
        
        def check_host(ip):
            try:
                # Use socket to check if host is reachable
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)  # 100ms timeout
                result = sock.connect_ex((ip, 22))  # Try connecting to SSH port
                sock.close()
                
                if result == 0:
                    hostname = 'Unknown'
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        pass
                    
                    active_hosts.append({
                        'ip': ip,
                        'hostname': hostname,
                        'status': 'up',
                        'last_seen': datetime.now().isoformat()
                    })
            except:
                pass
        
        threads = []
        for i in range(start, end + 1):
            ip = f"{network_base}{i}"
            thread = threading.Thread(target=check_host, args=(ip,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        self.active_hosts = active_hosts
        return active_hosts
    
    def get_local_ip(self):
        """Get the local IP address of this machine"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"


# Global scanner instance
scanner = NetworkScanner()

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/api/network/interfaces')
def get_network_interfaces():
    """Get available network interfaces"""
    interfaces = scanner.get_network_interfaces()
    return jsonify(interfaces)

@app.route('/api/network/scan', methods=['POST'])
def scan_network():
    """Scan the network for active hosts"""
    data = request.json
    network_range = data.get('network_range', '192.168.1.0/24')

    # Perform the scan using the faster ARP scan
    hosts = scanner.scan_network_arp(network_range)

    return jsonify({
        'success': True,
        'hosts': hosts,
        'count': len(hosts),
        'scan_time': datetime.now().isoformat()
    })

@app.route('/api/network/local_ip')
def get_local_ip():
    """Get the local IP address"""
    local_ip = scanner.get_local_ip()
    return jsonify({'local_ip': local_ip})

@app.route('/api/network/active_hosts')
def get_active_hosts():
    """Get previously scanned active hosts"""
    return jsonify(scanner.active_hosts)


# Read the simplified template from file
with open('simple_template.html', 'r') as f:
    template_content = f.read()

# Create templates directory and index.html
os.makedirs(os.path.join(app.root_path, 'templates'), exist_ok=True)

with open(os.path.join(app.root_path, 'templates', 'index.html'), 'w') as f:
    f.write(template_content)

# Add monitoring API endpoints
@app.route('/api/monitoring/start', methods=['POST'])
def start_monitoring():
    """Start traffic monitoring"""
    global notification_system

    data = request.json
    target_ips = data.get('target_ips', [])
    interface = data.get('interface')

    if not target_ips:
        return jsonify({'success': False, 'error': 'No target IPs specified'}), 400

    try:
        # Create and start the traffic monitor
        from .anomaly_detection_integration import TrafficMonitor

        # Use the quantized model for Raspberry Pi
        tflite_model_path = "quantized_iot_anomaly_model.tflite"
        if not os.path.exists(tflite_model_path):
            # If quantized model doesn't exist, try the regular model
            model_path = "iot_anomaly_model.h5"
            if os.path.exists(model_path):
                tflite_model_path = None
            else:
                return jsonify({'success': False, 'error': 'No model file found'}), 500

        traffic_monitor = TrafficMonitor(
            model_path="iot_anomaly_model.h5" if os.path.exists("iot_anomaly_model.h5") else None,
            tflite_model_path=tflite_model_path
        )

        if not traffic_monitor.anomaly_detector.is_initialized:
            if not traffic_monitor.anomaly_detector.load_model():
                return jsonify({'success': False, 'error': 'Failed to load anomaly detection model'}), 500

        # Start monitoring
        if traffic_monitor.start_monitoring(target_ips, interface):
            # Store the monitor in the notification system for status updates
            notification_system.traffic_monitor = traffic_monitor
            return jsonify({'success': True, 'message': f'Monitoring started for {len(target_ips)} IPs'})
        else:
            return jsonify({'success': False, 'error': 'Failed to start monitoring'}), 500

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/monitoring/stop', methods=['POST'])
def stop_monitoring():
    """Stop traffic monitoring"""
    global notification_system

    try:
        if hasattr(notification_system, 'traffic_monitor') and notification_system.traffic_monitor:
            notification_system.traffic_monitor.stop_monitoring()
            notification_system.traffic_monitor = None
            return jsonify({'success': True, 'message': 'Monitoring stopped'})
        else:
            return jsonify({'success': False, 'error': 'No active monitoring session'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Import notification system to handle alerts
try:
    from .notification_system import notification_system
except ImportError:
    # Create a mock notification system if the real one isn't available
    class MockNotificationSystem:
        def __init__(self):
            self.alerts = []
            self.traffic_monitor = None

        def get_recent_alerts(self, limit=50):
            return []

    notification_system = MockNotificationSystem()

# Import status model
try:
    from .status_model import status_model
except ImportError:
    # Create a mock status model if the real one isn't available
    class MockStatusModel:
        def get_status(self):
            return {
                'is_monitoring': False,
                'monitored_ips_count': 0,
                'packets_captured': 0,
                'alerts_generated': 0,
                'active_alerts_count': 0
            }

        def get_monitoring_status(self):
            return {
                'is_monitoring': False,
                'monitored_ips_count': 0,
                'packets_captured': 0,
                'active_alerts_count': 0
            }

    status_model = MockStatusModel()

@app.route('/api/notifications/alerts')
def get_alerts():
    """Get recent alerts"""
    try:
        # Get alerts from the notification system
        if hasattr(notification_system, 'get_recent_alerts'):
            alerts = notification_system.get_recent_alerts(limit=50)
        else:
            alerts = []

        return jsonify({'alerts': alerts, 'count': len(alerts)})
    except Exception as e:
        return jsonify({'alerts': [], 'count': 0}), 500

@app.route('/api/system/status')
def get_system_status():
    """Get system status"""
    try:
        status = status_model.get_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/monitoring/status')
def get_monitoring_status():
    """Get monitoring status"""
    try:
        status = status_model.get_monitoring_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)