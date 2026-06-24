"""
Sample Data Generator - Generate realistic sample logs for testing
"""
import json
import random
from datetime import datetime, timedelta


class SampleDataGenerator:
    """Generate sample log data for testing the SIEM dashboard"""

    def __init__(self):
        self.ip_addresses = [
            '192.168.1.100', '192.168.1.101', '192.168.1.102',
            '10.0.0.50', '10.0.0.51', '172.16.0.10',
            '203.0.113.45', '198.51.100.23', '203.0.113.89'
        ]

        self.usernames = [
            'admin', 'jdoe', 'asmith', 'bjones',
            'mwilson', 'guest', 'root', 'user123'
        ]

        self.paths = [
            '/api/users', '/api/login', '/api/data',
            '/admin/panel', '/dashboard', '/api/products',
            '/search?q=test', '/profile/edit', '/api/auth'
        ]

        self.attack_ips = ['45.123.45.67', '198.51.100.200', '203.0.113.150']

    def generate_syslog(self, timestamp=None):
        """Generate a syslog format entry"""
        if not timestamp:
            timestamp = datetime.now()

        hostname = random.choice(['webserver01', 'appserver01', 'dbserver01'])
        process = random.choice(['sshd', 'kernel', 'systemd', 'cron', 'nginx'])
        pid = random.randint(1000, 9999)

        rand_ip = random.choice(self.ip_addresses)
        rand_port = random.randint(1024, 65535)
        rand_user = random.choice(self.usernames)
        rand_ip2 = random.choice(self.ip_addresses)
        messages = [
            f"Connection from {rand_ip} port {rand_port}",
            f"User {rand_user} logged in",
            "Starting service...",
            "Service stopped",
            f"Failed password for {rand_user} from {rand_ip2}"
        ]

        message = random.choice(messages)

        return f"{timestamp.strftime('%b %d %H:%M:%S')} {hostname} {process}[{pid}]: {message}\n"

    def generate_apache_log(self, timestamp=None):
        """Generate Apache/NGINX access log entry"""
        if not timestamp:
            timestamp = datetime.now()

        ip = random.choice(self.ip_addresses)
        username = random.choice(self.usernames + ['-'])
        method = random.choice(['GET', 'POST', 'PUT', 'DELETE', 'GET', 'GET'])
        path = random.choice(self.paths)
        status = random.choice([200, 200, 200, 200, 301, 404, 500, 403])
        size = random.randint(100, 50000)

        ts_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
        return f'{ip} - {username} [{ts_str}] "{method} {path} HTTP/1.1" {status} {size}\n'

    def generate_json_log(self, timestamp=None):
        """Generate JSON format log entry"""
        if not timestamp:
            timestamp = datetime.now()

        log_data = {
            'timestamp': timestamp.isoformat(),
            'level': random.choice(['info', 'info', 'warning', 'error', 'debug']),
            'message': random.choice([
                'Request processed successfully',
                'Database query completed',
                'Cache miss',
                'Authentication successful',
                'File uploaded'
            ]),
            'ip': random.choice(self.ip_addresses),
            'user': random.choice(self.usernames),
            'duration_ms': random.randint(10, 1000),
            'endpoint': random.choice(self.paths)
        }

        return json.dumps(log_data) + '\n'

    def generate_security_log(self, timestamp=None):
        """Generate security log entry"""
        if not timestamp:
            timestamp = datetime.now()

        ts = timestamp.isoformat()
        sec_user = random.choice(self.usernames)
        sec_ip = random.choice(self.ip_addresses)
        atk_ip = random.choice(self.attack_ips)
        atk_port = random.randint(1, 65535)
        events = [
            f"{ts} SECURITY: Failed login attempt for user {sec_user} from {sec_ip}",
            f"{ts} SECURITY: Successful authentication for {sec_user}",
            f"{ts} FIREWALL: Blocked connection from {atk_ip} to port {atk_port}",
            f"{ts} SECURITY: Permission denied for {sec_user} accessing /admin",
            f"{ts} SECURITY: Session created for user {sec_user}"
        ]

        return random.choice(events) + '\n'

    def generate_attack_logs(self):
        """Generate malicious logs to test threat detection"""
        logs = []

        # Brute force attack simulation
        attack_ip = random.choice(self.attack_ips)
        attack_user = random.choice(self.usernames)
        for i in range(10):
            timestamp = datetime.now() - timedelta(seconds=10 - i)
            ts = timestamp.isoformat()
            logs.append(
                f"{ts} SECURITY: Failed login attempt"
                f" for user {attack_user} from {attack_ip}\n"
            )

        # SQL injection attempt
        timestamp = datetime.now()
        ts_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
        sql_payloads = [
            "' OR '1'='1",
            "UNION SELECT * FROM users",
            "'; DROP TABLE users--"
        ]
        for payload in sql_payloads:
            logs.append(
                f'{attack_ip} - - [{ts_str}]'
                f' "GET /api/users?id={payload} HTTP/1.1" 400 0\n'
            )

        # XSS attempt
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>"
        ]
        for payload in xss_payloads:
            logs.append(
                f'{attack_ip} - - [{ts_str}]'
                f' "GET /search?q={payload} HTTP/1.1" 400 0\n'
            )

        return logs

    def write_sample_logs(self, output_dir='./logs', count=100, include_attacks=True):
        """Write sample logs to files"""
        import os

        os.makedirs(output_dir, exist_ok=True)

        # Generate normal logs
        with open(f'{output_dir}/system.log', 'w') as f:
            for _ in range(count):
                timestamp = datetime.now() - timedelta(minutes=random.randint(0, 1440))
                f.write(self.generate_syslog(timestamp))

        with open(f'{output_dir}/access.log', 'w') as f:
            for _ in range(count):
                timestamp = datetime.now() - timedelta(minutes=random.randint(0, 1440))
                f.write(self.generate_apache_log(timestamp))

        with open(f'{output_dir}/app.log', 'w') as f:
            for _ in range(count):
                timestamp = datetime.now() - timedelta(minutes=random.randint(0, 1440))
                f.write(self.generate_json_log(timestamp))

        with open(f'{output_dir}/security.log', 'w') as f:
            for _ in range(count):
                timestamp = datetime.now() - timedelta(minutes=random.randint(0, 1440))
                f.write(self.generate_security_log(timestamp))

            # Add attack logs if requested
            if include_attacks:
                for log_line in self.generate_attack_logs():
                    f.write(log_line)

        print(f"✅ Generated {count} sample logs in {output_dir}/")
        if include_attacks:
            print("⚠️  Included simulated attack patterns for threat detection testing")


if __name__ == '__main__':
    generator = SampleDataGenerator()
    generator.write_sample_logs(count=200, include_attacks=True)
