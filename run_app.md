# 🚀 Provider Discovery Web App Launch

## Install Dependencies

```bash
cd /Users/anton/code-dev/provider_discovery
pip install -r requirements.txt
```

## Run Application

```bash
streamlit run app.py
```

After launch, browser will open at: `http://localhost:8501`

## Application Features

### 📁 CSV File Upload
- Upload CSV with `Company` and `URL` columns
- Automatic analysis of all websites
- Real-time progress bar
- Statistics and top providers
- Download results

### 🔗 Single URL Analysis  
- Quick analysis of individual website
- Detailed information on click
- View HTTP headers

## Input CSV Format

```csv
Company,URL
Google,google.com
GitHub,github.com
Cloudflare,cloudflare.com
```

## What It Detects

✅ **Major providers**: Cloudflare, AWS, Google, Microsoft, GitHub

✅ **CDN/Edge**: Akamai, Fastly, Netlify, Vercel

✅ **Cloud hosting**: DigitalOcean, Linode, Vultr, OVH, Hetzner

✅ **Regional providers**: Gcore, Scaleway, Rackspace

✅ **ANY provider**: Via enhanced WHOIS analysis with RIPE/APNIC

✅ **Real-time updates**: Official IP ranges from AWS/Cloudflare

✅ **Output**: Company, URL, Provider, IP_Address
