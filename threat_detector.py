"""
Threat Detection Engine - Detect security threats in logs
"""
import re
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional
from models import db, ThreatAlert


class ThreatDetector:
    """Detect security threats based on rules and patterns"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.rules = config.get('threat_detection', {}).get('rules', [])
        self.event_cache = defaultdict(list)
        self.baseline_traffic = {}
        
    def analyze_log(self, log_data: Dict) -> List[ThreatAlert]:
        """Analyze a log entry for threats"""
        alerts = []
        
        for rule in self.rules:
            if not rule.get('enabled', True):
                continue
                
            alert = self._check_rule(log_data, rule)
            if alert:
                alerts.append(alert)
        
        return alerts
    
    def _check_rule(self, log_data: Dict, rule: Dict) -> Optional[ThreatAlert]:
        """Check if log data matches a specific rule"""
        rule_type = rule.get('type')
        
        if rule_type == 'failed_login':
            return self._detect_brute_force(log_data, rule)
        elif rule_type == 'sql_injection':
            return self._detect_sql_injection(log_data, rule)
        elif rule_type == 'xss':
            return self._detect_xss(log_data, rule)
        elif rule_type == 'port_scan':
            return self._detect_port_scan(log_data, rule)
        elif rule_type == 'traffic_anomaly':
            return self._detect_traffic_anomaly(log_data, rule)
        
        return None
    
    def _detect_brute_force(self, log_data: Dict, rule: Dict) -> Optional[ThreatAlert]:
        """Detect brute force attacks"""
        message = log_data.get('message', '').lower()
        status = log_data.get('status', '')
        
        # Check if this is a failed login
        is_failed_login = (
            'failed' in message or 
            'failure' in message or 
            'denied' in message or
            status == 'failed'
        )
        
        if not is_failed_login:
            return None
        
        ip_address = log_data.get('ip_address')
        username = log_data.get('username')
        
        if not ip_address and not username:
            return None
        
        # Track failed attempts
        key = f"failed_login_{ip_address or username}"
        timestamp = log_data.get('timestamp', datetime.now())
        
        self.event_cache[key].append(timestamp)
        
        # Clean old events
        threshold = rule.get('threshold', 5)
        time_window = rule.get('time_window', 300)  # seconds
        cutoff_time = timestamp - timedelta(seconds=time_window)
        
        self.event_cache[key] = [
            t for t in self.event_cache[key] 
            if t > cutoff_time
        ]
        
        # Check if threshold exceeded
        if len(self.event_cache[key]) >= threshold:
            return ThreatAlert(
                alert_type='Brute Force Attack',
                severity=rule.get('severity', 'high'),
                description=f"Detected {len(self.event_cache[key])} failed login attempts within {time_window} seconds",
                source_ip=ip_address,
                username=username,
                rule_name=rule.get('name', 'Brute Force Detection'),
                confidence=min(len(self.event_cache[key]) / (threshold * 2), 1.0),
                metadata={
                    'failed_attempts': len(self.event_cache[key]),
                    'time_window': time_window,
                    'threshold': threshold
                }
            )
        
        return None
    
    def _detect_sql_injection(self, log_data: Dict, rule: Dict) -> Optional[ThreatAlert]:
        """Detect SQL injection attempts"""
        message = log_data.get('message', '')
        path = log_data.get('path', '')
        
        # Check against SQL injection patterns
        patterns = rule.get('patterns', [])
        
        for pattern in patterns:
            if re.search(pattern, message, re.IGNORECASE) or re.search(pattern, path, re.IGNORECASE):
                return ThreatAlert(
                    alert_type='SQL Injection Attempt',
                    severity=rule.get('severity', 'critical'),
                    description=f"SQL injection pattern detected: {pattern}",
                    source_ip=log_data.get('ip_address'),
                    username=log_data.get('username'),
                    rule_name=rule.get('name', 'SQL Injection Detection'),
                    confidence=0.8,
                    metadata={
                        'pattern': pattern,
                        'matched_text': message[:200],
                        'path': path
                    }
                )
        
        return None
    
    def _detect_xss(self, log_data: Dict, rule: Dict) -> Optional[ThreatAlert]:
        """Detect XSS (Cross-Site Scripting) attempts"""
        message = log_data.get('message', '')
        path = log_data.get('path', '')
        
        patterns = rule.get('patterns', [])
        
        for pattern in patterns:
            if re.search(pattern, message, re.IGNORECASE) or re.search(pattern, path, re.IGNORECASE):
                return ThreatAlert(
                    alert_type='XSS Attempt',
                    severity=rule.get('severity', 'high'),
                    description=f"XSS pattern detected: {pattern}",
                    source_ip=log_data.get('ip_address'),
                    username=log_data.get('username'),
                    rule_name=rule.get('name', 'XSS Detection'),
                    confidence=0.75,
                    metadata={
                        'pattern': pattern,
                        'matched_text': message[:200],
                        'path': path
                    }
                )
        
        return None
    
    def _detect_port_scan(self, log_data: Dict, rule: Dict) -> Optional[ThreatAlert]:
        """Detect port scanning activity"""
        ip_address = log_data.get('ip_address')
        
        if not ip_address:
            return None
        
        # Track connection attempts
        key = f"port_scan_{ip_address}"
        timestamp = log_data.get('timestamp', datetime.now())
        
        self.event_cache[key].append(timestamp)
        
        # Clean old events
        threshold = rule.get('threshold', 10)
        time_window = rule.get('time_window', 60)
        cutoff_time = timestamp - timedelta(seconds=time_window)
        
        self.event_cache[key] = [
            t for t in self.event_cache[key] 
            if t > cutoff_time
        ]
        
        # Check if threshold exceeded
        if len(self.event_cache[key]) >= threshold:
            return ThreatAlert(
                alert_type='Port Scan',
                severity=rule.get('severity', 'medium'),
                description=f"Detected {len(self.event_cache[key])} connection attempts within {time_window} seconds",
                source_ip=ip_address,
                rule_name=rule.get('name', 'Port Scan Detection'),
                confidence=0.7,
                metadata={
                    'connection_attempts': len(self.event_cache[key]),
                    'time_window': time_window,
                    'threshold': threshold
                }
            )
        
        return None
    
    def _detect_traffic_anomaly(self, log_data: Dict, rule: Dict) -> Optional[ThreatAlert]:
        """Detect unusual traffic volume"""
        ip_address = log_data.get('ip_address')
        
        if not ip_address:
            return None
        
        # Track traffic volume
        key = f"traffic_{ip_address}"
        timestamp = log_data.get('timestamp', datetime.now())
        
        self.event_cache[key].append(timestamp)
        
        # Calculate baseline (last hour)
        hour_ago = timestamp - timedelta(hours=1)
        recent_events = [t for t in self.event_cache[key] if t > hour_ago]
        
        # Calculate current traffic (last 5 minutes)
        five_min_ago = timestamp - timedelta(minutes=5)
        current_events = [t for t in recent_events if t > five_min_ago]
        
        if len(recent_events) < 10:  # Not enough data for baseline
            return None
        
        # Check if current traffic is anomalous
        avg_traffic = len(recent_events) / 12  # Average per 5-minute window
        threshold_multiplier = rule.get('threshold_multiplier', 3.0)
        
        if len(current_events) > avg_traffic * threshold_multiplier:
            return ThreatAlert(
                alert_type='Traffic Anomaly',
                severity=rule.get('severity', 'medium'),
                description=f"Unusual traffic volume: {len(current_events)} requests in 5 minutes (baseline: {avg_traffic:.1f})",
                source_ip=ip_address,
                rule_name=rule.get('name', 'Unusual Traffic Volume'),
                confidence=0.6,
                metadata={
                    'current_volume': len(current_events),
                    'baseline_volume': avg_traffic,
                    'multiplier': len(current_events) / avg_traffic if avg_traffic > 0 else 0
                }
            )
        
        return None
    
    def cleanup_cache(self, hours: int = 24):
        """Clean up old events from cache"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        for key in list(self.event_cache.keys()):
            self.event_cache[key] = [
                t for t in self.event_cache[key] 
                if t > cutoff_time
            ]
            
            if not self.event_cache[key]:
                del self.event_cache[key]
