#!/usr/bin/env python3
import csv
import subprocess
import socket
import openai
import os
from urllib.parse import urlparse
# --- Fetch headers using curl ---
def get_headers(url):
    try:
        result = subprocess.run(['curl', '-sI', url], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        return result.stdout.decode()
    except Exception as e:
        return f"Error fetching headers: {e}"
# --- Resolve hostname to IP ---
def resolve_ip(url):
    try:
        hostname = urlparse(url).hostname or url
        return socket.gethostbyname(hostname)
    except Exception as e:
        return f"Error resolving IP: {e}"
# --- WHOIS lookup ---
def get_whois(ip):
    try:
        result = subprocess.run(['whois', ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        return result.stdout.decode()
    except Exception as e:
        return f"Error running whois: {e}"
# --- Ask OpenAI to classify provider ---
def ask_openai(headers, whois_data):
    client = openai.OpenAI()
    prompt = f"""
Based on the HTTP response headers and WHOIS info below, identify the provider (e.g., Cloudflare, AWS, Akamai, Fastly, etc.). Only return a **single word** like: Cloudflare, Akamai, AWS, Fastly, Google, Unknown.
--- HEADERS ---
{headers}
--- WHOIS ---
{whois_data}
Answer:"""
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=10
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Error: {e}"
# --- Main CSV processing ---
def process_csv(input_path, output_path):
    with open(input_path, newline='', encoding='utf-8') as infile, \
         open(output_path, 'w', newline='', encoding='utf-8') as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)
        header = next(reader)
        writer.writerow(header + ['Provider'])
        for row in reader:
            company, url = row
            print(f"Processing: {company} - {url}")
            headers = get_headers(url)
            ip = resolve_ip(url)
            if ip.startswith("Error"):
                provider = "Unknown"
            else:
                whois_data = get_whois(ip)
                provider = ask_openai(headers, whois_data)
            writer.writerow([company, url, provider])
if __name__ == "__main__":
    input_csv = os.path.expanduser("~/Downloads/Cloudflare BGP - BGP.csv")
    output_csv = os.path.expanduser("~/Downloads/Cloudflare BGP - BGP_with_providers.csv")
    process_csv(input_csv, output_csv)
    print("Done.")
