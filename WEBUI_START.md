# WebUI Start Guide

## VirusTotal WebUI Toggle Feature

The WebUI now includes an interactive VirusTotal toggle with the following features:

### 🎛️ **Interactive Controls:**
- **Toggle Switch**: Enable/disable VirusTotal in real-time
- **Smart Status**: Header shows "VirusTotal ON/OFF" + module count
- **Live Updates**: System status updates immediately

### ⚠️ **Rate Limit Warnings:**
- **CSV Batch Processing**: Automatic warning when VT is enabled
- **Time Estimates**: Shows processing time with/without VT
- **Clear Guidance**: Recommends disabling VT for bulk analysis

### 📊 **Information Display:**
- **When ENABLED**: Shows rate limits (4 req/min, 500/day max)
- **When DISABLED**: Shows optimization benefits (7 core modules, no delays)
- **API Status**: Shows if VT API is properly configured

## To Start the WebUI:

```bash
# Navigate to project directory
cd /Users/anton/code-dev/provider_discovery

# Start Streamlit server
streamlit run app.py

# Or use custom port
streamlit run app.py --server.port 8501
```

## VirusTotal Settings:

### Enable VirusTotal:
- Check the "Enable VirusTotal" checkbox
- See: 8 analysis modules + security validation
- Good for: Single URL analysis with maximum security

### Disable VirusTotal:
- Uncheck the "Enable VirusTotal" checkbox  
- See: 7 core modules, no rate limits
- Good for: CSV batch processing, fast bulk analysis

## Rate Limits (Free API):
- **Requests**: 4 per minute
- **Daily**: 500 requests maximum
- **Cache**: 1 hour (reduces API calls)
- **Premium**: 300 requests/minute

## System Status:
- Shows current module count (7 or 8)
- Displays VirusTotal status in sidebar
- Updates health percentage in real-time

The UnboundLocalError has been fixed - detector is now properly initialized in main().