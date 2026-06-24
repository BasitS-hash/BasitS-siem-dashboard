"""
Log Parser Module - Parse various log formats
"""
import json
import re
from datetime import datetime
from typing import Dict, Optional


class LogParser:
    """Parse different log formats"""

    def __init__(self):
        self.parsers = {
            'syslog': self.parse_syslog,
            'apache': self.parse_apache,
            'json': self.parse_json,
            'security': self.parse_security
        }

    def parse(self, log_line: str, log_type: str) -> Optional[Dict]:
        """Parse a log line based on its type"""
        parser = self.parsers.get(log_type, self.parse_generic)
        try:
            return parser(log_line)
        except Exception as e:
            print(f"Error parsing log line: {e}")
            return self.parse_generic(log_line)

    def parse_syslog(self, log_line: str) -> Dict:
        """Parse syslog format logs"""
        # Example: Jan 15 10:30:45 hostname process[pid]: message
        pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(\[\d+\])?\s*:\s*(.+)'
        match = re.match(pattern, log_line)

        if match:
            timestamp_str, hostname, process, pid, message = match.groups()

            # Parse timestamp
            try:
                timestamp = datetime.strptime(
                    f"{datetime.now().year} {timestamp_str}",
                    "%Y %b %d %H:%M:%S"
                )
            except ValueError:
                timestamp = datetime.now()

            return {
                'timestamp': timestamp,
                'hostname': hostname,
                'process': process,
                'pid': pid.strip('[]') if pid else None,
                'message': message,
                'severity': self._extract_severity(message),
                'ip_address': self._extract_ip(message),
                'username': self._extract_username(message)
            }

        return self.parse_generic(log_line)

    def parse_apache(self, log_line: str) -> Dict:
        """Parse Apache/NGINX access logs"""
        # Example: 192.168.1.1 - user [01/Jan/2024:10:30:45 +0000] "GET /path HTTP/1.1" 200 1234
        pattern = r'(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)'
        match = re.match(pattern, log_line)

        if match:
            ip, username, timestamp_str, request, status, size = match.groups()

            try:
                timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                timestamp = datetime.now()

            # Parse request
            request_parts = request.split()
            method = request_parts[0] if len(request_parts) > 0 else None
            path = request_parts[1] if len(request_parts) > 1 else None

            return {
                'timestamp': timestamp,
                'ip_address': ip,
                'username': username if username != '-' else None,
                'method': method,
                'path': path,
                'status_code': int(status),
                'size': int(size),
                'message': log_line,
                'severity': 'warning' if int(status) >= 400 else 'info'
            }

        return self.parse_generic(log_line)

    def parse_json(self, log_line: str) -> Dict:
        """Parse JSON formatted logs"""
        try:
            data = json.loads(log_line)

            # Extract timestamp
            timestamp = data.get('timestamp') or data.get('time') or datetime.now().isoformat()
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except ValueError:
                    timestamp = datetime.now()

            return {
                'timestamp': timestamp,
                'message': data.get('message', log_line),
                'severity': data.get('level', data.get('severity', 'info')),
                'ip_address': data.get('ip', data.get('ip_address')),
                'username': data.get('user', data.get('username')),
                'parsed_data': data
            }
        except json.JSONDecodeError:
            return self.parse_generic(log_line)

    def parse_security(self, log_line: str) -> Dict:
        """Parse security-specific logs"""
        # Look for common security event patterns
        data = {
            'timestamp': datetime.now(),
            'message': log_line,
            'severity': 'info'
        }

        # Detect login events
        if re.search(r'(login|authentication|auth)', log_line, re.I):
            data['event_type'] = 'authentication'
            if re.search(r'(failed|failure|denied)', log_line, re.I):
                data['severity'] = 'warning'
                data['status'] = 'failed'
            elif re.search(r'(success|successful|accepted)', log_line, re.I):
                data['status'] = 'success'

        # Detect firewall events
        if re.search(r'(firewall|blocked|dropped)', log_line, re.I):
            data['event_type'] = 'firewall'
            data['severity'] = 'warning'

        # Extract IPs and usernames
        data['ip_address'] = self._extract_ip(log_line)
        data['username'] = self._extract_username(log_line)

        return data

    def parse_generic(self, log_line: str) -> Dict:
        """Generic parser for unknown formats"""
        return {
            'timestamp': datetime.now(),
            'message': log_line,
            'severity': self._extract_severity(log_line),
            'ip_address': self._extract_ip(log_line),
            'username': self._extract_username(log_line)
        }

    def _extract_ip(self, text: str) -> Optional[str]:
        """Extract IP address from text"""
        # IPv4
        ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ipv4_pattern, text)
        if match:
            return match.group(0)

        # IPv6 (simplified)
        ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        match = re.search(ipv6_pattern, text)
        if match:
            return match.group(0)

        return None

    def _extract_username(self, text: str) -> Optional[str]:
        """Extract username from text"""
        patterns = [
            r'user[=:\s]+(\S+)',
            r'username[=:\s]+(\S+)',
            r'for\s+(\S+)',
            r'by\s+(\S+)'
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.I)
            if match:
                username = match.group(1)
                if username not in ['-', 'root', 'system']:
                    return username

        return None

    def _extract_severity(self, text: str) -> str:
        """Determine severity level from text"""
        text_lower = text.lower()

        if any(word in text_lower for word in ['critical', 'fatal', 'emergency']):
            return 'critical'
        elif any(word in text_lower for word in ['error', 'err', 'failed', 'failure']):
            return 'error'
        elif any(word in text_lower for word in ['warning', 'warn']):
            return 'warning'
        elif any(word in text_lower for word in ['info', 'information']):
            return 'info'
        elif any(word in text_lower for word in ['debug', 'trace']):
            return 'debug'

        return 'info'
