"""
Database initialization and management utilities
"""
from app import db, server
from models import ComplianceReport, LogEntry, ThreatAlert


def init_db():
    """Initialize the database"""
    with server.app_context():
        db.create_all()
        print("✅ Database tables created successfully")


def reset_db():
    """Reset the database (WARNING: Deletes all data)"""
    with server.app_context():
        db.drop_all()
        db.create_all()
        print("✅ Database reset successfully")


def show_stats():
    """Display database statistics"""
    with server.app_context():
        log_count = db.session.query(LogEntry).count()
        alert_count = db.session.query(ThreatAlert).count()
        report_count = db.session.query(ComplianceReport).count()

        print("\n📊 Database Statistics:")
        print(f"   Log Entries: {log_count:,}")
        print(f"   Threat Alerts: {alert_count:,}")
        print(f"   Compliance Reports: {report_count:,}")
        print()


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python db_utils.py [init|reset|stats]")
        sys.exit(1)

    command = sys.argv[1]

    if command == 'init':
        init_db()
    elif command == 'reset':
        confirm = input("⚠️  This will delete all data. Continue? (yes/no): ")
        if confirm.lower() == 'yes':
            reset_db()
        else:
            print("Operation cancelled")
    elif command == 'stats':
        show_stats()
    else:
        print(f"Unknown command: {command}")
        print("Available commands: init, reset, stats")
