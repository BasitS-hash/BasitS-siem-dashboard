"""
Log Ingestion Service - Monitor and ingest logs from various sources
"""
import os
import time
import threading
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from models import db, LogEntry
from log_parser import LogParser
from threat_detector import ThreatDetector


class LogFileHandler(FileSystemEventHandler):
    """Handle log file changes"""
    
    def __init__(self, log_parser, threat_detector, log_source_config, app):
        self.log_parser = log_parser
        self.threat_detector = threat_detector
        self.config = log_source_config
        self.app = app
        self.last_position = {}
        
    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return
        
        if event.src_path == self.config['path']:
            self.process_new_lines(event.src_path)
    
    def process_new_lines(self, file_path):
        """Process new lines added to the log file"""
        try:
            # Get last read position
            current_position = self.last_position.get(file_path, 0)
            
            with open(file_path, 'r') as f:
                # Seek to last position
                f.seek(current_position)
                
                # Read new lines
                new_lines = f.readlines()
                
                # Update position
                self.last_position[file_path] = f.tell()
            
            # Process each new line
            for line in new_lines:
                line = line.strip()
                if not line:
                    continue
                
                self.ingest_log_line(line)
        
        except Exception as e:
            print(f"Error processing log file {file_path}: {e}")
    
    def ingest_log_line(self, log_line):
        """Ingest a single log line"""
        try:
            # Parse log
            parsed_data = self.log_parser.parse(log_line, self.config['type'])
            
            if not parsed_data:
                return
            
            with self.app.app_context():
                # Create log entry
                log_entry = LogEntry(
                    timestamp=parsed_data.get('timestamp', datetime.now()),
                    source=self.config['name'],
                    log_type=self.config['type'],
                    severity=parsed_data.get('severity', 'info'),
                    message=parsed_data.get('message', log_line),
                    raw_data=log_line,
                    ip_address=parsed_data.get('ip_address'),
                    username=parsed_data.get('username'),
                    parsed_data=parsed_data
                )
                
                db.session.add(log_entry)
                db.session.commit()
                
                # Check for threats
                alerts = self.threat_detector.analyze_log(parsed_data)
                
                for alert in alerts:
                    db.session.add(alert)
                
                if alerts:
                    db.session.commit()
                    print(f"🚨 {len(alerts)} threat(s) detected in log entry")
        
        except Exception as e:
            print(f"Error ingesting log line: {e}")


class LogIngestionService:
    """Service to monitor and ingest logs from multiple sources"""
    
    def __init__(self, config, app, log_parser, threat_detector):
        self.config = config
        self.app = app
        self.log_parser = log_parser
        self.threat_detector = threat_detector
        self.observers = []
        
    def start(self):
        """Start monitoring all configured log sources"""
        log_sources = self.config.get('log_sources', [])
        
        for source in log_sources:
            if not source.get('enabled', True):
                continue
            
            log_path = source['path']
            
            # Ensure log file exists
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            if not os.path.exists(log_path):
                open(log_path, 'a').close()
            
            # Create event handler
            event_handler = LogFileHandler(
                self.log_parser,
                self.threat_detector,
                source,
                self.app
            )
            
            # Create observer
            observer = Observer()
            observer.schedule(
                event_handler,
                path=os.path.dirname(log_path),
                recursive=False
            )
            observer.start()
            self.observers.append(observer)
            
            print(f"📊 Monitoring log source: {source['name']} ({log_path})")
            
            # Process existing content
            if os.path.getsize(log_path) > 0:
                event_handler.process_new_lines(log_path)
    
    def stop(self):
        """Stop all observers"""
        for observer in self.observers:
            observer.stop()
            observer.join()
        
        print("Stopped log ingestion service")


def run_periodic_tasks(app, threat_detector, compliance_checker, config):
    """Run periodic maintenance tasks"""
    from compliance import ComplianceChecker
    from datetime import timedelta
    
    while True:
        try:
            time.sleep(3600)  # Run every hour
            
            with app.app_context():
                # Clean up old cache entries
                threat_detector.cleanup_cache()
                
                # Generate compliance reports (once per day)
                hour = datetime.now().hour
                if hour == 0:  # Midnight
                    frameworks = config.get('compliance', {}).get('frameworks', [])
                    end_date = datetime.now()
                    start_date = end_date - timedelta(days=1)
                    
                    for framework in frameworks:
                        report = compliance_checker.generate_report(
                            framework,
                            start_date,
                            end_date
                        )
                        db.session.add(report)
                    
                    db.session.commit()
                    print(f"📋 Generated compliance reports for {len(frameworks)} frameworks")
        
        except Exception as e:
            print(f"Error in periodic tasks: {e}")


if __name__ == '__main__':
    import yaml
    from flask import Flask
    from models import db
    
    # Load config
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Initialize Flask app
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = config['database']['uri']
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    
    # Initialize components
    log_parser = LogParser()
    threat_detector = ThreatDetector(config)
    compliance_checker = ComplianceChecker(config)
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    # Start log ingestion
    ingestion_service = LogIngestionService(
        config,
        app,
        log_parser,
        threat_detector
    )
    ingestion_service.start()
    
    # Start periodic tasks in background
    periodic_thread = threading.Thread(
        target=run_periodic_tasks,
        args=(app, threat_detector, compliance_checker, config),
        daemon=True
    )
    periodic_thread.start()
    
    print("🛡️  SIEM Log Ingestion Service started")
    print("Press Ctrl+C to stop...")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        ingestion_service.stop()
        print("\nStopping service...")
