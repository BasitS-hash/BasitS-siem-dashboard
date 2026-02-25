#!/bin/bash

# SIEM Dashboard Startup Script

echo "🛡️  Starting SIEM Dashboard..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install/update dependencies
echo "Installing dependencies..."
pip install -q -r requirements.txt

# Generate sample data if logs directory is empty
if [ ! -f "logs/system.log" ]; then
    echo "Generating sample log data..."
    python generate_sample_data.py
fi

# Initialize database
echo "Initializing database..."
python -c "from app import server, db; app_context = server.app_context(); app_context.push(); db.create_all(); app_context.pop()"

# Start log ingestion service in background
echo "Starting log ingestion service..."
python log_ingestion.py > ingestion.log 2>&1 &
INGESTION_PID=$!
echo "Log ingestion service started (PID: $INGESTION_PID)"

# Wait a moment for ingestion to start
sleep 2

# Start dashboard
echo "Starting dashboard..."
echo "Dashboard will be available at http://localhost:8050"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Trap Ctrl+C to cleanup
trap "echo 'Stopping services...'; kill $INGESTION_PID 2>/dev/null; exit" INT

# Start the dashboard (this will block)
python app.py

# Cleanup on exit
kill $INGESTION_PID 2>/dev/null
