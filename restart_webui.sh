#!/bin/bash

echo "🔄 Restarting Provider Discovery WebUI..."
echo "   This will apply updated timeout settings"

# Kill existing Streamlit processes
pkill -f "streamlit run app.py" 2>/dev/null || true

# Wait a moment
sleep 2

# Start fresh instance
echo "🚀 Starting WebUI with updated settings..."
streamlit run app.py --server.port 8501

echo "✅ WebUI restarted with improved timeout handling!"