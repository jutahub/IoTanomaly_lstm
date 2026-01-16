import smtplib
import json
import os
import requests
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import time
import logging
import socket
import psutil

class NotificationSystem:
    def __init__(self):
        self.alerts = []
        self.email_config = {}
        self.webhook_urls = []
        self.notification_callbacks = []
        self.is_active = True
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def configure_email(self, smtp_server, smtp_port, username, password, recipient_emails):
        """
        Configure email notifications
        :param smtp_server: SMTP server address
        :param smtp_port: SMTP server port
        :param username: SMTP username
        :param password: SMTP password
        :param recipient_emails: List of recipient email addresses
        """
        self.email_config = {
            'smtp_server': smtp_server,
            'smtp_port': smtp_port,
            'username': username,
            'password': password,
            'recipients': recipient_emails
        }
        self.logger.info("Email notification configured")
    
    def add_webhook(self, webhook_url):
        """Add a webhook URL for notifications"""
        self.webhook_urls.append(webhook_url)
        self.logger.info(f"Webhook added: {webhook_url}")
    
    def add_notification_callback(self, callback_function):
        """Add a custom callback function for notifications"""
        self.notification_callbacks.append(callback_function)
        self.logger.info(f"Notification callback added: {callback_function.__name__}")
    
    def send_email_alert(self, subject, message):
        """Send an email alert"""
        if not self.email_config:
            self.logger.warning("Email not configured, skipping email alert")
            return False
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_config['username']
            msg['To'] = ', '.join(self.email_config['recipients'])
            msg['Subject'] = subject
            
            msg.attach(MIMEText(message, 'plain'))
            
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.starttls()
            server.login(self.email_config['username'], self.email_config['password'])
            
            text = msg.as_string()
            server.sendmail(self.email_config['username'], self.email_config['recipients'], text)
            server.quit()
            
            self.logger.info("Email alert sent successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
            return False
    
    def send_webhook_alert(self, alert_data):
        """Send an alert via webhook"""
        import requests
        
        success_count = 0
        for webhook_url in self.webhook_urls:
            try:
                response = requests.post(webhook_url, json=alert_data)
                if response.status_code in [200, 201, 202]:
                    success_count += 1
                    self.logger.info(f"Webhook alert sent to {webhook_url}")
                else:
                    self.logger.error(f"Webhook returned status {response.status_code}: {response.text}")
            except Exception as e:
                self.logger.error(f"Failed to send webhook alert to {webhook_url}: {e}")
        
        return success_count > 0
    
    def trigger_callbacks(self, alert_data):
        """Trigger all registered callback functions"""
        for callback in self.notification_callbacks:
            try:
                callback(alert_data)
                self.logger.info(f"Callback {callback.__name__} executed successfully")
            except Exception as e:
                self.logger.error(f"Callback {callback.__name__} failed: {e}")
    
    def notify_anomaly(self, ip_address, confidence, mse_value, additional_info=None):
        """
        Send notification about detected anomaly
        :param ip_address: IP address where anomaly was detected
        :param confidence: Confidence score of the anomaly
        :param mse_value: MSE value that triggered the alert
        :param additional_info: Additional information about the anomaly
        """
        if not self.is_active:
            return
        
        # Create alert data
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'ip_address': ip_address,
            'confidence': confidence,
            'mse_value': mse_value,
            'severity': self._determine_severity(confidence),
            'additional_info': additional_info or {}
        }
        
        # Add to alerts list
        self.alerts.append(alert_data)
        
        # Create notification message
        subject = f"🚨 IoT Anomaly Detected: {ip_address}"
        message = f"""
IoT Network Anomaly Alert

Time: {alert_data['timestamp']}
IP Address: {ip_address}
Confidence: {confidence:.3f}
MSE Value: {mse_value:.6f}
Severity: {alert_data['severity']}

Additional Info:
{json.dumps(additional_info or {}, indent=2)}

This alert was generated by the IoT Anomaly Detection System.
        """
        
        self.logger.info(f"Anomaly detected for {ip_address} with confidence {confidence:.3f}")
        
        # Send notifications through all configured channels
        email_success = False
        webhook_success = False
        callback_success = False
        
        if self.email_config:
            email_success = self.send_email_alert(subject, message)
        
        if self.webhook_urls:
            webhook_success = self.send_webhook_alert(alert_data)
        
        if self.notification_callbacks:
            self.trigger_callbacks(alert_data)
            callback_success = True
        
        # Log notification status
        notification_status = {
            'email': email_success,
            'webhook': webhook_success,
            'callback': callback_success
        }
        
        self.logger.info(f"Notifications sent - Status: {notification_status}")
    
    def _determine_severity(self, confidence):
        """Determine severity level based on confidence score"""
        if confidence > 0.9:
            return "CRITICAL"
        elif confidence > 0.7:
            return "HIGH"
        elif confidence > 0.5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_recent_alerts(self, limit=10):
        """Get recent alerts"""
        return self.alerts[-limit:] if self.alerts else []


# Global notification system instance
notification_system = NotificationSystem()

# Create a callback function to connect anomaly detection with notifications
def anomaly_notification_callback(alert_data):
    """Callback function to send notifications when anomalies are detected"""
    notification_system.notify_anomaly(
        ip_address=alert_data['ip_address'],
        confidence=alert_data['confidence'],
        mse_value=alert_data['mse_value'],
        additional_info=alert_data.get('additional_info', {})
    )

# Register the callback
notification_system.add_notification_callback(anomaly_notification_callback)