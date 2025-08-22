#!/usr/bin/env python3
"""
Streamlit web application for CDN/hosting provider detection
"""
import streamlit as st
import pandas as pd
import subprocess
import socket
import re
import ipaddress
import io
import time
import os
import sys
from urllib.parse import urlparse

# Add src to path for new modular imports
sys.path.insert(0, 'src')

from provider_discovery.core import get_provider_detector

# Page configuration
st.set_page_config(
    page_title="Provider Discovery Tool",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize the provider detector (cached for performance)
@st.cache_resource
def get_detector_instance():
    """Get cached instance of ProviderDetector with new modular architecture"""
    # Check for VirusTotal API key in environment or secrets
    vt_api_key = None
    try:
        # Try Streamlit secrets first
        vt_api_key = st.secrets.get("VT_API_KEY")
    except:
        pass
    
    if not vt_api_key:
        # Try environment variable
        vt_api_key = os.getenv("VT_API_KEY")
    
    det = get_provider_detector(vt_api_key=vt_api_key)
    # Clear any existing cache to avoid issues (backward compatibility)
    det.ip_cache = {}
    det.dns_cache = {}
    return det

detector = get_detector_instance()

def validate_url(url):
    """Validate and clean URL format"""
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty"
    
    # Clean whitespace and common issues
    url = str(url).strip()
    if not url or url.lower() in ['nan', 'n/a', 'null', 'none']:
        return False, "URL cannot be empty"
    
    # Remove common prefixes that users might add
    url = url.replace('www.', '').replace('WWW.', '')
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False, "Invalid URL format"
        
        # Extract clean domain
        domain = parsed.netloc.lower()
        
        # More flexible domain validation - allow subdomains and various TLDs
        if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$', domain):
            return False, f"Invalid domain format: {domain}"
        
        # Return clean URL without protocol for processing
        clean_url = domain + (parsed.path if parsed.path != '/' else '')
        return True, clean_url
    except:
        return False, "Invalid URL format"

def validate_csv_structure(df):
    """Validate and clean CSV file structure and content"""
    errors = []
    warnings = []
    
    # Check required columns
    required_columns = ['Company', 'URL']
    missing_columns = [col for col in required_columns if col not in df.columns]
    
    if missing_columns:
        errors.append(f"Missing required columns: {', '.join(missing_columns)}")
        return errors, warnings, None
    
    # Check for empty DataFrame
    if df.empty:
        errors.append("CSV file is empty")
        return errors, warnings, None
    
    # Clean and validate data
    df_clean = df.copy()
    
    # Clean whitespace and normalize data
    for col in df_clean.columns:
        if df_clean[col].dtype == 'object':
            df_clean[col] = df_clean[col].astype(str).str.strip()
    
    # Process each row and try to fix issues
    valid_rows = []
    cleaned_count = 0
    
    for idx, row in df_clean.iterrows():
        # Clean Company name
        company = str(row.get('Company', '')).strip()
        if not company or company.lower() in ['nan', 'n/a', 'null', 'none', '']:
            # Try to generate company name from URL if possible
            url_val = str(row.get('URL', '')).strip()
            if url_val and url_val.lower() not in ['nan', 'n/a', 'null', 'none', '']:
                is_valid_url, clean_url = validate_url(url_val)
                if is_valid_url:
                    # Extract domain as company name
                    company = clean_url.split('.')[0].title()
                    df_clean.at[idx, 'Company'] = company
                    warnings.append(f"Row {idx + 2}: Generated company name '{company}' from URL")
                    cleaned_count += 1
                else:
                    continue  # Skip row - no valid company or URL
            else:
                continue  # Skip row - no company or URL
        
        # Clean and validate URL
        url = str(row.get('URL', '')).strip()
        if not url or url.lower() in ['nan', 'n/a', 'null', 'none', '']:
            continue  # Skip row - no URL
        
        is_valid, url_or_error = validate_url(url)
        if not is_valid:
            # Try common fixes
            if 'invalid domain format' in url_or_error.lower():
                # Try adding .com if it looks like a company name
                if '.' not in url and len(url) > 2:
                    is_valid, url_or_error = validate_url(url + '.com')
                    if is_valid:
                        warnings.append(f"Row {idx + 2}: Added .com to '{url}' -> '{url_or_error}'")
                        cleaned_count += 1
            
            if not is_valid:
                warnings.append(f"Row {idx + 2}: Skipped invalid URL '{url}' - {url_or_error}")
                continue
        
        # Update with cleaned URL
        df_clean.at[idx, 'URL'] = url_or_error
        df_clean.at[idx, 'Company'] = company
        valid_rows.append(idx)
    
    # Filter only valid rows
    if valid_rows:
        df_clean = df_clean.iloc[valid_rows].reset_index(drop=True)
    else:
        df_clean = pd.DataFrame(columns=['Company', 'URL'])
    
    # Add informative warnings
    skipped_count = len(df) - len(df_clean)
    if skipped_count > 0:
        warnings.append(f"Automatically cleaned {cleaned_count} rows and excluded {skipped_count} invalid rows")
    
    if len(df_clean) > 50:
        warnings.append("Large file detected. Processing may take several minutes.")
    
    if len(df_clean) == 0:
        errors.append("No valid data rows found after cleaning")
    
    return errors, warnings, df_clean

def detect_provider(headers, ip, whois_data):
    """Detect provider using ultimate detection logic"""
    return detector.detect_provider_ultimate(headers, ip, whois_data)

def process_single_url(url, progress_callback=None):
    """Process single URL with Phase 2A enhanced DNS analysis"""
    if progress_callback:
        progress_callback(f"Analyzing {url}...")
    
    domain = urlparse(url).netloc or url.replace('https://', '').replace('http://', '').split('/')[0]
    
    headers = detector.get_headers(url)
    ip = detector.get_ip(url)
    whois_data = detector.get_whois(ip) if ip else ""
    
    # Phase 2B: Enhanced multi-layer detection with DNS analysis + VirusTotal
    enhanced_result = detector.detect_provider_ultimate_with_virustotal(headers, ip, whois_data, domain)
    
    # Format providers by role
    origin_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'Origin']
    cdn_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'CDN']
    waf_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'WAF']
    lb_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'Load Balancer']
    dns_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'DNS']
    
    return {
        'URL': url,
        'IP_Address': ip or 'N/A',
        'Primary_Provider': enhanced_result['primary_provider'],
        'Origin_Provider': ', '.join(origin_providers) if origin_providers else 'Unknown',
        'CDN_Providers': ', '.join(cdn_providers) if cdn_providers else 'None',
        'WAF_Providers': ', '.join(waf_providers) if waf_providers else 'None',
        'LB_Providers': ', '.join(lb_providers) if lb_providers else 'None',
        'DNS_Providers': ', '.join(dns_providers) if dns_providers else 'Unknown',
        'Confidence_Factors': '; '.join(enhanced_result['confidence_factors']) if enhanced_result['confidence_factors'] else 'Low',
        'DNS_Chain': enhanced_result['dns_chain'],
        'DNS_Analysis': enhanced_result.get('dns_analysis', {}),
        'TTL_Analysis': enhanced_result.get('ttl_analysis', {})
    }

# Main application
def main():
    st.title("🔍 Provider Discovery Tool")
    st.markdown("**Detects CDN/hosting providers for your websites**")
    
    # Sidebar with information
    with st.sidebar:
        st.header("ℹ️ Information")
        # Check VirusTotal status
        vt_status = "✅ Enabled" if detector.vt_integrator and detector.vt_integrator.is_enabled else "⚠️ Not configured"
        
        st.markdown(f"""
        **🆕 Phase 2B - VirusTotal Integration:**
        - **VirusTotal Status**: {vt_status}
        - **Cross-validation** with VT database
        - **Historical DNS data** (Premium feature)
        - **Domain reputation** scoring
        - **Security threat** detection
        
        **🔬 Phase 2A - Advanced DNS Analysis:**
        1. **NS Record Analysis** - DNS provider identification
        2. **TTL Analysis** - Migration pattern detection  
        3. **Reverse DNS Lookup** - Additional validation
        4. **DNS Chain Analysis** - CNAME resolution paths
        5. **HTTP Headers** - 50+ provider patterns
        6. **Official IP Ranges** - AWS, Cloudflare, etc.
        7. **WHOIS Analysis** - RIPE/APNIC integration
        8. **Provider Roles** - Origin/CDN/WAF/LB/DNS separation
        
        **Supported providers:**
        - **Major**: Cloudflare, AWS, Google, Microsoft
        - **CDNs**: Akamai, Fastly, Netlify, Vercel
        - **Cloud**: DigitalOcean, Linode, Vultr, OVH
        - **ANY provider** via dynamic WHOIS analysis
        
        **🎯 Phase 2B Key improvements:**
        - ✅ VirusTotal cross-validation
        - ✅ Domain reputation analysis
        - ✅ Security threat detection
        - ✅ Historical DNS analysis (Premium)
        - ✅ Enhanced confidence scoring
        - ✅ DNS provider separation from web hosting
        - ✅ Migration pattern detection via TTL analysis
        - ✅ Reverse DNS validation 
        - ✅ Multi-provider detection
        """)
        
        st.header("📋 CSV Format")
        st.markdown("""
        **Required columns:**
        - **Company** - company name
        - **URL** - website address
        
        **Smart auto-fixing:**
        - ✅ Trims whitespace and normalizes data
        - ✅ Removes www. prefixes automatically
        - ✅ Adds .com to company names if needed
        - ✅ Generates company names from URLs
        - ✅ Flexible validation with helpful warnings
        
        **Example:**
        ```
        Company,URL
        Google,google.com
        GitHub,github.com
        Cloudflare,cloudflare.com
        ```
        """)
    
    # Main interface
    tab1, tab2 = st.tabs(["📁 CSV Upload", "🔗 Single URL"])
    
    with tab1:
        st.header("Upload CSV File")
        
        uploaded_file = st.file_uploader(
            "Choose CSV file",
            type=['csv'],
            help="CSV file with Company and URL columns"
        )
        
        if uploaded_file is not None:
            try:
                # Read CSV
                df = pd.read_csv(uploaded_file)
                
                st.success(f"✅ File uploaded! Found {len(df)} records")
                
                # Validate CSV structure and content
                errors, warnings, df_clean = validate_csv_structure(df)
                
                # Show validation results
                if errors:
                    st.error("❌ **Validation Errors:**")
                    for error in errors:
                        st.error(f"• {error}")
                    
                    st.info("**Please fix the errors above and re-upload the file**")
                    
                    # Show original data for reference
                    with st.expander("📋 Original Data Preview"):
                        st.dataframe(df.head(10))
                        
                else:
                    # Show warnings if any
                    if warnings:
                        st.warning("⚠️ **Warnings:**")
                        for warning in warnings:
                            st.warning(f"• {warning}")
                    
                    # Show validation success
                    st.success(f"✅ **Validation passed!** {len(df_clean)} valid records ready for processing")
                    
                    # Show cleaned data preview
                    st.subheader("📋 Cleaned Data Preview:")
                    st.dataframe(df_clean.head())
                    
                    # Show data cleaning summary
                    if len(df_clean) != len(df):
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Original Records", len(df))
                        with col2:
                            st.metric("Valid Records", len(df_clean))
                        with col3:
                            st.metric("Excluded Records", len(df) - len(df_clean))
                    
                    # Processing button (only show if validation passed)
                    if len(df_clean) > 0:
                        if st.button("🚀 Start Analysis", type="primary"):
                            # Progress bar
                            progress_bar = st.progress(0)
                            status_text = st.empty()
                        
                            results = []
                            
                            for idx, row in df_clean.iterrows():
                                company = row['Company']
                                url = row['URL']
                            
                                # Update progress
                                progress = (idx + 1) / len(df_clean)
                                progress_bar.progress(progress)
                                status_text.text(f"Processing {idx + 1}/{len(df_clean)}: {company}")
                            
                                # Phase 2A: Enhanced multi-layer analysis with DNS
                                domain = urlparse(url).netloc or url.replace('https://', '').replace('http://', '').split('/')[0]
                                
                                headers = detector.get_headers(url)
                                ip = detector.get_ip(url)
                                whois_data = detector.get_whois(ip) if ip else ""
                                enhanced_result = detector.detect_provider_ultimate_with_virustotal(headers, ip, whois_data, domain)
                                
                                # Format providers by role
                                origin_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'Origin']
                                cdn_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'CDN']
                                waf_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'WAF']
                                lb_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'Load Balancer']
                                dns_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'DNS']
                                
                                result = {
                                    'Company': company,
                                    'URL': url,
                                    'Primary_Provider': enhanced_result['primary_provider'],
                                    'Origin_Provider': ', '.join(origin_providers) if origin_providers else 'Unknown',
                                    'CDN_Providers': ', '.join(cdn_providers) if cdn_providers else 'None',
                                    'WAF_Providers': ', '.join(waf_providers) if waf_providers else 'None',
                                    'LB_Providers': ', '.join(lb_providers) if lb_providers else 'None',
                                    'DNS_Providers': ', '.join(dns_providers) if dns_providers else 'Unknown',
                                    'IP_Address': ip or 'N/A',
                                    'Confidence': '; '.join(enhanced_result['confidence_factors']) if enhanced_result['confidence_factors'] else 'Low'
                                }
                                results.append(result)
                        
                            # Create enhanced result DataFrame
                            results_df = pd.DataFrame(results)
                            # Reorder columns for better display (Phase 2A update)
                            column_order = ['Company', 'URL', 'Primary_Provider', 'Origin_Provider', 
                                          'CDN_Providers', 'WAF_Providers', 'LB_Providers', 
                                          'DNS_Providers', 'IP_Address', 'Confidence']
                            results_df = results_df[column_order]
                        
                            # Clear progress
                            progress_bar.empty()
                            status_text.empty()
                            
                            # Show results
                            st.success("🎉 Analysis completed!")
                            
                            # Statistics
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric("Total Websites", len(results_df))
                            with col2:
                                identified = len(results_df[results_df['Primary_Provider'] != 'Unknown'])
                                st.metric("Identified", identified)
                            with col3:
                                multi_provider = len(results_df[(results_df['CDN_Providers'] != 'None') | 
                                                              (results_df['WAF_Providers'] != 'None')])
                                st.metric("Multi-Provider", multi_provider)
                            
                            # Results
                            st.subheader("📊 Results:")
                            st.dataframe(results_df, use_container_width=True)
                            
                            # Enhanced analytics
                            if len(results_df) > 0:
                                col1, col2 = st.columns(2)
                                
                                with col1:
                                    st.subheader("📈 Primary Providers:")
                                    provider_counts = results_df['Primary_Provider'].value_counts()
                                    if len(provider_counts) > 1:
                                        st.bar_chart(provider_counts)
                                
                                with col2:
                                    st.subheader("🌐 CDN Usage:")
                                    cdn_data = results_df[results_df['CDN_Providers'] != 'None']['CDN_Providers'].str.split(', ').explode().value_counts()
                                    if len(cdn_data) > 0:
                                        st.bar_chart(cdn_data)
                                    else:
                                        st.info("No CDN providers detected")
                            
                            # Download results
                            csv_buffer = io.StringIO()
                            results_df.to_csv(csv_buffer, index=False)
                            csv_data = csv_buffer.getvalue()
                            
                            st.download_button(
                                label="💾 Download Results CSV",
                                data=csv_data,
                                file_name="provider_analysis_results.csv",
                                mime="text/csv"
                            )
                        
            except Exception as e:
                st.error(f"❌ Error reading file: {str(e)}")
    
    with tab2:
        st.header("Single URL Analysis")
        
        url_input = st.text_input(
            "Enter URL for analysis:",
            placeholder="example.com or https://example.com"
        )
        
        if st.button("🔍 Analyze"):
            if url_input:
                # Validate URL
                is_valid, url_or_error = validate_url(url_input)
                
                if not is_valid:
                    st.error(f"❌ {url_or_error}")
                    st.info("**Examples of valid URLs:**")
                    st.code("example.com\nhttps://example.com\nwww.example.com")
                else:
                    clean_url = url_or_error.replace('https://', '').replace('http://', '')
                    
                    with st.spinner("Analyzing..."):
                        result = process_single_url(clean_url)
                
                    # Result
                    st.success("✅ Analysis completed!")
                    
                    # Enhanced result display (Phase 2A update)
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("URL", result['URL'])
                        st.metric("IP Address", result['IP_Address'])
                    with col2:
                        st.metric("Primary Provider", result['Primary_Provider'])
                        st.metric("Origin", result['Origin_Provider'])
                    with col3:
                        st.metric("CDN", result['CDN_Providers'])
                        st.metric("DNS Provider", result['DNS_Providers'])
                    with col4:
                        st.metric("WAF/LB", f"{result['WAF_Providers']}/{result['LB_Providers']}")
                        st.metric("Confidence", result['Confidence_Factors'][:15] + "..." if len(result['Confidence_Factors']) > 15 else result['Confidence_Factors'])
                    
                    # Multi-provider summary
                    if result['CDN_Providers'] != 'None' or result['WAF_Providers'] != 'None':
                        st.success("🎯 **Multi-provider setup detected!**")
                        provider_summary = []
                        if result['Origin_Provider'] != 'Unknown':
                            provider_summary.append(f"**Origin**: {result['Origin_Provider']}")
                        if result['CDN_Providers'] != 'None':
                            provider_summary.append(f"**CDN**: {result['CDN_Providers']}")
                        if result['WAF_Providers'] != 'None':
                            provider_summary.append(f"**WAF**: {result['WAF_Providers']}")
                        if result['LB_Providers'] != 'None':
                            provider_summary.append(f"**Load Balancer**: {result['LB_Providers']}")
                        if result['DNS_Providers'] != 'Unknown':
                            provider_summary.append(f"**DNS**: {result['DNS_Providers']}")
                        
                        st.markdown(" | ".join(provider_summary))
                    
                    # Phase 2A: Enhanced DNS Analysis Display
                    if result.get('DNS_Analysis') or result.get('TTL_Analysis'):
                        with st.expander("🔬 Advanced DNS Analysis (Phase 2A)"):
                            if result.get('DNS_Analysis'):
                                dns_data = result['DNS_Analysis']
                                if dns_data.get('dns_providers'):
                                    st.subheader("NS Record Analysis")
                                    for dns_prov in dns_data['dns_providers']:
                                        st.write(f"**{dns_prov['provider']}**: {dns_prov['ns_server']}")
                                    
                                    if dns_data.get('dns_diversity', 0) > 1:
                                        st.warning(f"⚠️ Multiple DNS providers detected ({dns_data['dns_diversity']}) - Complex setup")
                                    else:
                                        st.info("✅ Single DNS provider configuration")
                            
                            if result.get('TTL_Analysis'):
                                st.subheader("TTL Analysis")
                                ttl_data = result['TTL_Analysis']
                                for record_type, ttl_info in ttl_data.items():
                                    if 'ttl' in ttl_info:
                                        indicator = ttl_info.get('migration_indicator', 'unknown')
                                        if indicator == 'high':
                                            st.error(f"🚨 **{record_type}**: {ttl_info['description']}")
                                        elif indicator == 'medium':
                                            st.warning(f"⚠️ **{record_type}**: {ttl_info['description']}")
                                        else:
                                            st.success(f"✅ **{record_type}**: {ttl_info['description']}")
                    
                    # Phase 2B: VirusTotal Analysis Display
                    if result.get('virustotal_enhanced') and result.get('virustotal_data'):
                        with st.expander("🦠 VirusTotal Analysis (Phase 2B)"):
                            vt_data = result['virustotal_data']
                            
                            # Confidence and reputation
                            col1, col2 = st.columns(2)
                            with col1:
                                confidence = vt_data.get('confidence_score', 0)
                                st.metric("VT Confidence", f"{confidence}%")
                            with col2:
                                reputation = vt_data.get('reputation', 0)
                                rep_color = "green" if reputation > 0 else "red" if reputation < 0 else "gray"
                                st.metric("Reputation", reputation)
                            
                            # Security analysis
                            stats = vt_data.get('last_analysis_stats', {})
                            if stats:
                                st.subheader("Security Analysis")
                                col1, col2, col3, col4 = st.columns(4)
                                with col1:
                                    st.metric("Harmless", stats.get('harmless', 0))
                                with col2:
                                    malicious = stats.get('malicious', 0)
                                    if malicious > 0:
                                        st.error(f"Malicious: {malicious}")
                                    else:
                                        st.metric("Malicious", malicious)
                                with col3:
                                    suspicious = stats.get('suspicious', 0)
                                    if suspicious > 0:
                                        st.warning(f"Suspicious: {suspicious}")
                                    else:
                                        st.metric("Suspicious", suspicious)
                                with col4:
                                    st.metric("Undetected", stats.get('undetected', 0))
                            
                            # VirusTotal providers
                            vt_providers = vt_data.get('providers', {})
                            if any(vt_providers.values()):
                                st.subheader("VirusTotal Provider Analysis")
                                if vt_providers.get('origin'):
                                    st.write(f"**Origin**: {vt_providers['origin']}")
                                if vt_providers.get('cdn'):
                                    st.write(f"**CDN**: {', '.join(vt_providers['cdn'])}")
                                if vt_providers.get('dns_provider'):
                                    st.write(f"**DNS**: {vt_providers['dns_provider']}")
                    
                    # DNS Chain Analysis
                    if result['DNS_Chain']:
                        with st.expander("🔗 DNS Resolution Chain"):
                            for i, step in enumerate(result['DNS_Chain']):
                                if step['type'] == 'CNAME':
                                    st.write(f"**Step {i+1}**: `{step['domain']}` → `{step['cname']}` ({step['provider'] or 'Unknown'}) - {step['role']}")
                                else:
                                    st.write(f"**Step {i+1}**: `{step['domain']}` → `{step['ip']}` ({step['provider'] or 'Unknown'}) - {step['role']}")
                    
                    # Detailed information
                    with st.expander("🔍 Technical Details"):
                        headers = detector.get_headers(clean_url)
                        if headers:
                            st.text_area("HTTP headers (first 500 characters):", headers[:500], height=150)
                        
                        st.write("**Confidence Factors:**")
                        if result['Confidence_Factors']:
                            for factor in result['Confidence_Factors'].split('; '):
                                st.write(f"• {factor}")
                        else:
                            st.write("• Low confidence - based on fallback methods")
            else:
                st.warning("⚠️ Please enter a URL")

if __name__ == "__main__":
    main()
