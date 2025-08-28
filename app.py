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
import time
import os
import sys
import io
from urllib.parse import urlparse

# Add src to path for new modular imports
sys.path.insert(0, 'src')

from provider_discovery import get_enhanced_provider_detector, ENHANCED_DETECTOR_AVAILABLE

# Import comprehensive analysis
COMPREHENSIVE_ANALYSIS_AVAILABLE = False
get_comprehensive_analysis = None

try:
    # Import from src path
    import sys
    import os
    src_path = os.path.join(os.path.dirname(__file__), 'src')
    if src_path not in sys.path:
        sys.path.insert(0, src_path)
    
    print(f"🔧 Attempting to import from: {src_path}")
    from provider_discovery.integrations.comprehensive_analysis import get_comprehensive_analysis
    COMPREHENSIVE_ANALYSIS_AVAILABLE = True
    print("✅ Comprehensive Analysis module loaded successfully!")
    print(f"🔧 Module path: {get_comprehensive_analysis.__module__}")
except ImportError as e:
    print(f"⚠️ ImportError: {e}")
    COMPREHENSIVE_ANALYSIS_AVAILABLE = False
    get_comprehensive_analysis = None
except Exception as e:
    print(f"⚠️ Other error loading Comprehensive Analysis: {e}")
    COMPREHENSIVE_ANALYSIS_AVAILABLE = False
    get_comprehensive_analysis = None

print(f"🔧 Final status: COMPREHENSIVE_ANALYSIS_AVAILABLE = {COMPREHENSIVE_ANALYSIS_AVAILABLE}")

# Page configuration
st.set_page_config(
    page_title="Provider Discovery Tool v4.0",
    page_icon="⚫",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Force dark theme
if "theme" not in st.session_state:
    st.session_state.theme = "dark"

# Terminal-style CSS
st.markdown("""
<style>
    /* Import monospace font */
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500&display=swap');
    
    /* Force dark theme */
    html, body, .stApp {
        background-color: #0e1117 !important;
        color: #fafafa !important;
    }
    
    /* Override any light theme remnants */
    [data-theme="light"] {
        background-color: #0e1117 !important;
        color: #fafafa !important;
    }
    
    /* Global font settings */
    .main .block-container {
        font-family: 'JetBrains Mono', 'Courier New', monospace;
        font-size: 10px;
        max-width: none;
        padding: 1rem;
    }
    
    /* Headers */
    h1, h2, h3 {
        font-family: 'JetBrains Mono', monospace;
        font-weight: 500;
        color: #e8e8e8;
        font-size: 9px;
        margin-top: 0.3rem;
        margin-bottom: 0.3rem;
    }
    
    /* Metrics */
    [data-testid="metric-container"] {
        background-color: #1a1a1a;
        border: 1px solid #333;
        border-radius: 2px;
        padding: 4px;
        min-height: 40px;
    }
    
    [data-testid="metric-container"] > div {
        font-family: 'JetBrains Mono', monospace;
        font-size: 8px;
        line-height: 1.2;
    }
    
    /* Metric labels */
    [data-testid="metric-container"] label {
        font-size: 7px !important;
        text-transform: uppercase;
    }
    
    /* Metric values */
    [data-testid="metric-container"] [data-testid="metric-value"] {
        font-size: 9px !important;
        font-weight: 600;
    }
    
    /* Text inputs */
    .stTextInput input {
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        background-color: #2a2a2a;
        border: 1px solid #555;
        color: #e8e8e8;
        padding: 8px;
    }
    
    /* Input labels */
    .stTextInput label {
        font-size: 9px !important;
        font-family: 'JetBrains Mono', monospace;
    }
    
    /* Buttons */
    .stButton button {
        font-family: 'JetBrains Mono', monospace;
        font-size: 9px;
        background-color: #333;
        border: 1px solid #555;
        color: #e8e8e8;
        border-radius: 2px;
    }
    
    .stButton button:hover {
        background-color: #444;
        border: 1px solid #777;
    }
    
    /* Info boxes */
    .stAlert {
        font-family: 'JetBrains Mono', monospace;
        font-size: 9px;
        background-color: #2a2a2a;
        border: 1px solid #555;
        border-radius: 2px;
    }
    
    /* Sidebar */
    .css-1d391kg {
        background-color: #1a1a1a;
    }
    
    /* Remove default padding */
    .block-container {
        padding-top: 0.5rem;
    }
    
    /* Radio buttons */
    .stRadio > div {
        font-size: 9px;
    }
    
    .stRadio label {
        font-size: 8px !important;
    }
    
    /* Radio button text */
    .stRadio > div > label > div {
        font-size: 8px !important;
    }
    
    /* Selectbox */
    .stSelectbox > div > div {
        font-size: 9px;
    }
    
    /* File uploader */
    .stFileUploader > div {
        font-size: 9px;
    }
    
    /* Markdown */
    .markdown-text-container {
        font-size: 9px !important;
    }
    
    /* Progress bar */
    .stProgress > div {
        height: 8px;
    }
    
    /* Reduce spacing between elements */
    .element-container {
        margin-bottom: 0.3rem !important;
    }
    
    /* Subheaders */
    .stSubheader {
        font-size: 8px !important;
        margin: 0.2rem 0 !important;
    }
</style>
""", unsafe_allow_html=True)

# Initialize the enhanced provider detector (cached for performance)
@st.cache_resource
def get_detector_instance():
    """Get cached instance of Enhanced Provider Detector with 6 integrations"""
    if not ENHANCED_DETECTOR_AVAILABLE:
        st.error("❌ Enhanced Provider Detector not available")
        return None
    
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
    
    det = get_enhanced_provider_detector(vt_api_key=vt_api_key)
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
    
    # Auto-detect columns: First by name (case-insensitive), then by position
    required_columns = ['Company', 'URL']
    
    # Method 1: Try to find columns by name (case-insensitive)
    column_mapping = {}
    for req_col in required_columns:
        req_col_lower = req_col.lower()
        for df_col in df.columns:
            if df_col.lower() == req_col_lower:
                column_mapping[req_col] = df_col
                break
    
    # Method 2: If columns not found by name, use position-based mapping
    if len(column_mapping) < 2 and len(df.columns) >= 2:
        column_mapping = {
            'Company': df.columns[0],  # First column = Company
            'URL': df.columns[1]       # Second column = URL
        }
        warnings.append(f"Auto-detected columns by position: '{df.columns[0]}' → Company, '{df.columns[1]}' → URL")
    
    # Check if we have enough columns
    if len(column_mapping) < 2:
        available_cols = ', '.join(df.columns)
        errors.append(f"Need at least 2 columns (Company, URL). Available columns: {available_cols}")
        return errors, warnings, None
    
    # Rename columns to standard format
    df_renamed = df.rename(columns={v: k for k, v in column_mapping.items()})
    df = df_renamed
    
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

def detect_provider(headers, ip, whois_data, domain=""):
    """Detect provider using Enhanced Provider Detection System"""
    # Get detector instance
    detector = get_detector_instance()
    
    if hasattr(detector, 'detect_provider_comprehensive'):
        # Apply VirusTotal setting from UI
        if 'vt_enabled' in st.session_state:
            detector = apply_virustotal_setting(detector, st.session_state.vt_enabled)
        return detector.detect_provider_comprehensive(headers, ip, whois_data, domain)
    else:
        # Fallback to original method
        return detector.detect_provider_ultimate(headers, ip, whois_data)

def process_single_url(url, progress_callback=None):
    """Process single URL with Phase 2A enhanced DNS analysis"""
    # Enable logging for debugging FIRST
    import logging
    from datetime import datetime
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    
    logger.info(f"🚀 Starting analysis for URL: {url}")
    
    if progress_callback:
        progress_callback(f"Analyzing {url}...")
    
    # Get detector instance
    detector = get_detector_instance()
    
    domain = urlparse(url).netloc or url.replace('https://', '').replace('http://', '').split('/')[0]
    logger.info(f"📝 Extracted domain: {domain}")
    
    logger.info(f"🌐 Step 1/5: Fetching headers...")
    headers = detector.get_headers(url)
    logger.info(f"✅ Headers fetched: {len(headers)} chars")
    
    logger.info(f"🔍 Step 2/5: Resolving IP...")
    ip = detector.get_ip(url)
    logger.info(f"✅ IP resolved: {ip}")
    logger.info(f"📋 Step 3/5: Getting WHOIS data...")
    whois_data = detector.get_whois(ip) if ip else ""
    logger.info(f"✅ WHOIS data fetched: {len(whois_data)} chars")
    
    # Enhanced Provider Detection System v4.0 with 6 integrations
    logger.info(f"🚀 Step 4/5: Running enhanced provider detection (6 integrations)...")
    enhanced_result = detect_provider(headers, ip, whois_data, domain)
    logger.info(f"✅ Enhanced provider detection completed!")
    
    # Comprehensive Analysis (Full DNS, Subdomains, Raw Headers)
    comprehensive_analysis_result = {}
    logger.info(f"🔧 Debug: COMPREHENSIVE_ANALYSIS_AVAILABLE = {COMPREHENSIVE_ANALYSIS_AVAILABLE}")
    if COMPREHENSIVE_ANALYSIS_AVAILABLE:
        try:
            logger.info(f"🔍 Step 5/5: Running comprehensive analysis (Full DNS, Subdomains, Headers)...")
            comprehensive_analyzer = get_comprehensive_analysis()
            comprehensive_analysis_result = comprehensive_analyzer.analyze_domain_comprehensive(domain)
            logger.info(f"✅ Comprehensive analysis completed!")
            logger.info(f"🔧 Debug: comprehensive_analysis_result keys: {list(comprehensive_analysis_result.keys()) if comprehensive_analysis_result else 'None or empty'}")
            logger.info(f"🔧 Debug: comprehensive_analysis_result size: {len(str(comprehensive_analysis_result)) if comprehensive_analysis_result else 0} chars")
        except Exception as e:
            logger.warning(f"⚠️ Comprehensive analysis failed: {e}")
            comprehensive_analysis_result = {'error': str(e)}
    else:
        logger.info("⏭️ Step 5/5: Comprehensive analysis not available (install additional dependencies)")
    
    # Format providers by role
    origin_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'Origin']
    cdn_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'CDN']
    waf_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] in ['WAF', 'Security']]
    lb_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'Load Balancer']
    dns_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] == 'DNS']
    hosting_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] in ['Hosting', 'Host']]
    cloud_providers = [p['name'] for p in enhanced_result['providers'] if p['role'] in ['Cloud', 'Cloud Provider']]
    
    # Debug: Check IP value before creating result
    logger.info(f"🔧 Debug: IP value before result creation: {ip}")
    
    result = {
        'URL': url,
        'IP_Address': ip or 'N/A',
        'Primary_Provider': enhanced_result['primary_provider'],
        'Origin_Provider': ', '.join(origin_providers) if origin_providers else 'Unknown',
        'CDN_Providers': ', '.join(cdn_providers) if cdn_providers else 'None',
        'WAF_Providers': ', '.join(waf_providers) if waf_providers else 'None',
        'LB_Providers': ', '.join(lb_providers) if lb_providers else 'None',
        'DNS_Providers': ', '.join(dns_providers) if dns_providers else 'Unknown',
        'Hosting_Providers': ', '.join(hosting_providers) if hosting_providers else 'None',
        'Cloud_Providers': ', '.join(cloud_providers) if cloud_providers else 'None',
        'Security_Providers': ', '.join(waf_providers) if waf_providers else 'None',  # Same as WAF for now
        'Confidence_Factors': '; '.join(enhanced_result['confidence_factors']) if enhanced_result['confidence_factors'] else 'Low',
        'DNS_Chain': enhanced_result.get('dns_chain', 'N/A'),
        'DNS_Analysis': enhanced_result.get('dns_analysis', {}),
        'TTL_Analysis': enhanced_result.get('ttl_analysis', {}),
        'Enhanced_Analysis': enhanced_result.get('Enhanced_Analysis', {}),
        'Comprehensive_Analysis': comprehensive_analysis_result,
        'Enhanced_Confidence': enhanced_result.get('Enhanced_Confidence', 100),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'analysis_steps_report': enhanced_result.get('analysis_steps_report', {})
    }
    
    # Save analysis results to backend (moved here after comprehensive analysis)
    try:
        logger.info(f"🔧 Debug: Attempting to save analysis results...")
        from src.provider_discovery.core.enhanced_detector import EnhancedProviderDetector
        from datetime import datetime
        logger.info(f"🔧 Debug: Imports successful")
        
        detector_instance = EnhancedProviderDetector()
        logger.info(f"🔧 Debug: Detector instance created")
        
        # Create combined result for saving  
        combined_result = {
            **result,  # Original result with IP_Address, URL, providers
            **enhanced_result,  # All enhanced detection results
            'Comprehensive_Analysis': comprehensive_analysis_result  # Add comprehensive analysis
        }
        logger.info(f"🔧 Debug: Combined result created with {len(str(combined_result))} chars")
        
        detector_instance._save_analysis_to_backend(combined_result, domain)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        logger.info(f"✅ Analysis results saved to backend: analysis_{domain.replace('.', '_')}_{timestamp}.json, summary_{domain.replace('.', '_')}_{timestamp}.csv")
    except Exception as e:
        logger.error(f"⚠️ Failed to save analysis results: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
    
    return result

# Main application
def apply_virustotal_setting(detector, enabled):
    """Apply VirusTotal enable/disable setting to detector"""
    if detector and hasattr(detector, 'vt_integration') and detector.vt_integration:
        # Temporarily override the enable_virustotal setting
        detector.vt_integration.settings.enable_virustotal = enabled
    return detector

def main():
    # Get detector instance
    detector = get_detector_instance()
    
    st.title("PROVIDER DISCOVERY TOOL v4.0")
    
    # Show current VirusTotal status in header
    if 'vt_enabled' in st.session_state:
        vt_header_status = "VirusTotal ON" if st.session_state.vt_enabled else "VirusTotal OFF"
        module_count = "10 Modules" if st.session_state.vt_enabled else "9 Core Modules"
    else:
        vt_header_status = "VirusTotal AUTO"
        module_count = "9+ Modules"
    
    st.markdown(f"**Multi-Layer Provider Detection - {module_count} | {vt_header_status}**")
    
    # Show system status
    if detector:
        # Apply current VT setting to detector for accurate status
        if 'vt_enabled' in st.session_state:
            detector = apply_virustotal_setting(detector, st.session_state.vt_enabled)
        
        test_results = detector.test_all_integrations()
        working_count = test_results.get('total_available', 0)
        
        # Count Advanced BGP Classifier
        if hasattr(detector, 'advanced_bgp_classifier') and detector.advanced_bgp_classifier:
            working_count += 1
        
        # Count Shodan Integration
        if hasattr(detector, 'shodan_integration') and detector.shodan_integration and detector.shodan_integration.is_enabled:
            working_count += 1
        
        # Count Comprehensive Analysis
        if COMPREHENSIVE_ANALYSIS_AVAILABLE:
            working_count += 1
        
        # Adjust total modules based on VirusTotal status
        # Base: SSL, DNS, Geo, BGP, Hurricane Electric, Threat Intelligence, Advanced BGP, Shodan, Comprehensive Analysis = 9
        # VirusTotal is optional 10th module
        total_modules = 10  # Core modules (9) + Comprehensive Analysis (1)
        
        # Note: VirusTotal is considered bonus functionality, not core
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("SYSTEM STATUS", f"{working_count}/{total_modules} modules", "ONLINE")
        with col2:
            health_status = "OPTIMAL" if working_count >= 6 else "DEGRADED" if working_count >= 4 else "CRITICAL"
            st.metric("SYSTEM HEALTH", f"{(working_count/total_modules*100):.0f}%", health_status)
        with col3:
            st.metric("LICENSE", "OPEN", "NO API REQUIRED")
    
    st.markdown("---")
    
    # Sidebar with information
    with st.sidebar:
        st.header("SYSTEM v4.0")
        
        # Integration status
        if detector:
            test_results = detector.test_all_integrations()
            st.markdown("**MODULE STATUS:**")
            
            integration_names = {
                'ssl_analysis': 'SSL_CERT_ANALYSIS',
                'enhanced_dns': 'DNS_FRAMEWORK',
                'geographic_intelligence': 'GEO_INTELLIGENCE',
                'bgp_analysis': 'BGP_ANALYSIS',
                'hurricane_electric': 'BGP_FALLBACK',
                'threat_intelligence': 'THREAT_INTEL',
                'shodan_integration': 'SHODAN_PREMIUM_WAF'
            }
            
            for integration, name in integration_names.items():
                status = test_results.get(integration, False)
                details = test_results.get('integration_status', {}).get(integration, {})
                
                if status:
                    status_indicator = "[ONLINE]"
                    status_text = ""
                elif details.get('rate_limited'):
                    status_indicator = "[LIMITED]"
                    status_text = " - FALLBACK_READY"
                else:
                    status_indicator = "[OFFLINE]"
                    status_text = ""
                
                # Special handling for Shodan to show credits
                if integration == 'shodan_integration' and status:
                    if hasattr(detector, 'shodan_integration') and detector.shodan_integration:
                        try:
                            account_info = detector.shodan_integration.get_account_info()
                            if account_info.get('success'):
                                credits = account_info.get('credits_remaining', 0)
                                credit_status = account_info.get('credit_status', {})
                                icon = credit_status.get('icon', '💳')
                                
                                if credits >= 100:
                                    credit_display = f" ({credits} credits {icon})"
                                elif credits > 0:
                                    credit_display = f" ({credits} credits {icon})"
                                else:
                                    credit_display = f" (0 credits ❌)"
                                    status_indicator = "[LIMITED]"
                                
                                status_text += credit_display
                        except Exception:
                            status_text += " (credits unknown)"
                
                st.markdown(f"`{status_indicator} {name}{status_text}`")
        
        # Show Advanced BGP Classifier status
        if hasattr(detector, 'advanced_bgp_classifier') and detector.advanced_bgp_classifier:
            st.markdown(f"`[ONLINE] ADVANCED_BGP_CLASSIFIER`")
        else:
            st.markdown(f"`[OFFLINE] ADVANCED_BGP_CLASSIFIER`")
        
        # Check VirusTotal status (use session state if available)
        if 'vt_enabled' in st.session_state:
            session_vt_enabled = st.session_state.vt_enabled
            # Apply the setting to get accurate status
            temp_detector = apply_virustotal_setting(detector, session_vt_enabled)
            vt_enabled = temp_detector and hasattr(temp_detector, 'vt_integration') and temp_detector.vt_integration and temp_detector.vt_integration.is_enabled
        else:
            vt_enabled = detector and hasattr(detector, 'vt_integration') and detector.vt_integration and detector.vt_integration.is_enabled
        
        if vt_enabled:
            vt_status = "[ENABLED]"
        elif detector and hasattr(detector, 'vt_integration') and detector.vt_integration:
            vt_status = "[DISABLED]"  # VT integration exists but is disabled
        else:
            vt_status = "[OPTIONAL]"  # VT not configured
        
        st.markdown(f"""
        **CORE FEATURES:**
        ```
        [✓] SSL_SECURITY_ANALYSIS  - A-F grading
        [✓] MULTI_RESOLVER_DNS     - 4 resolver consensus
        [✓] GEO_INTELLIGENCE       - Multi-provider location
        [✓] DUAL_BGP_ANALYSIS      - BGPView + HE fallback
        [✓] ADVANCED_BGP_CLASSIFIER - Customer type detection
        [✓] THREAT_INTELLIGENCE    - Security assessment
        [✓] CROSS_VALIDATION       - Multi-source confidence
        ```
        
        **OPTIONAL MODULES:**
        ```
        [✓] VIRUSTOTAL_STATUS: {vt_status}
        ```
        """)
        
        # Shodan Account Information (if enabled)
        if detector and hasattr(detector, 'shodan_integration') and detector.shodan_integration and detector.shodan_integration.is_enabled:
            try:
                account_info = detector.shodan_integration.get_account_info()
                if account_info.get('success'):
                    credits = account_info.get('credits_remaining', 0)
                    plan = account_info.get('plan', 'Unknown')
                    credit_status = account_info.get('credit_status', {})
                    
                    st.markdown("**SHODAN PREMIUM ACCOUNT:**")
                    
                    # Credit status with color coding
                    icon = credit_status.get('icon', '💳')
                    message = credit_status.get('message', 'Status unknown')
                    color = credit_status.get('color', 'gray')
                    
                    if color == 'green':
                        st.success(f"{icon} **{credits}** Query Credits - {message}")
                    elif color == 'orange':
                        st.warning(f"{icon} **{credits}** Query Credits - {message}")
                    elif color == 'red':
                        st.error(f"{icon} **{credits}** Query Credits - {message}")
                    else:
                        st.info(f"{icon} **{credits}** Query Credits - {message}")
                    
                    # Plan information
                    scan_credits = account_info.get('scan_credits', 0)
                    st.markdown(f"""
                    ```
                    PLAN:          {plan.upper()}
                    QUERY CREDITS: {credits:,}
                    SCAN CREDITS:  {scan_credits:,}
                    STATUS:        {credit_status.get('level', 'unknown').upper()}
                    ```
                    """)
                    
                    # Usage recommendations
                    if credits < 50:
                        st.error("⚠️ **LOW CREDITS WARNING**")
                        st.markdown("Consider upgrading your Shodan plan for continued analysis.")
                        st.markdown("[Upgrade Plan](https://account.shodan.io/billing)")
                    elif credits < 100:
                        st.warning("💡 **MODERATE USAGE**")
                        st.markdown("Monitor credit usage for optimal analysis.")
                else:
                    st.warning("⚠️ **SHODAN API ERROR**")
                    st.markdown(f"Cannot retrieve account info: {account_info.get('error', 'Unknown error')}")
            except Exception as e:
                st.error("❌ **SHODAN CONNECTION ISSUE**")
                st.markdown(f"Error checking account: {str(e)}")
        
        st.markdown(f"""
        
        **SYSTEM CAPABILITIES:**
        ```
        > 7x data integrations
        > Cross-validation algorithms
        > Enhanced confidence scoring
        > Customer type classification
        > Security threat detection
        > Geographic risk analysis
        > BGP routing intelligence
        > SSL certificate grading
        > 68+ known provider database
        ```
        
        **PERFORMANCE METRICS:**
        ```
        COST:      OPEN SOURCE
        ACCURACY:  95%+ on known domains
        LATENCY:   <2 seconds average
        SECURITY:  Built-in assessment
        ```
        """)
        
        st.markdown("""
        **FALLBACK SYSTEMS:**
        ```
        > Hurricane Electric BGP backup
        > Automatic recovery on limit reset
        > Domain reputation analysis
        > Security threat detection
        > Enhanced confidence scoring
        > DNS provider separation
        > Migration pattern detection
        > Multi-provider detection
        ```
        """)
        
        # Show recent analysis files
        st.header("RECENT ANALYSIS")
        try:
            import os
            results_dir = 'results'
            if os.path.exists(results_dir):
                # Get recent analysis files (JSON files only)
                json_files = [f for f in os.listdir(results_dir) if f.startswith('analysis_') and f.endswith('.json')]
                json_files.sort(key=lambda x: os.path.getmtime(os.path.join(results_dir, x)), reverse=True)
                
                if json_files:
                    st.markdown("**Last 5 analyses:**")
                    for i, filename in enumerate(json_files[:5], 1):
                        # Extract domain and timestamp from filename
                        parts = filename.replace('analysis_', '').replace('.json', '').split('_')
                        if len(parts) >= 2:
                            domain = parts[0].replace('_', '.')
                            timestamp = parts[-2] + '_' + parts[-1]
                            # Format timestamp for display
                            try:
                                from datetime import datetime
                                dt = datetime.strptime(timestamp, '%Y%m%d_%H%M%S')
                                time_str = dt.strftime('%m/%d %H:%M')
                            except:
                                time_str = timestamp
                            
                            file_size = os.path.getsize(os.path.join(results_dir, filename)) / 1024  # KB
                            st.markdown(f"`{i}.` **{domain}**  \n`{time_str}` ({file_size:.1f}KB)")
                        else:
                            st.markdown(f"`{i}.` {filename[:20]}...")
                else:
                    st.markdown("`No analyses yet`")
            else:
                st.markdown("`Results folder not found`")
        except Exception as e:
            st.markdown(f"`Error loading recent files: {str(e)[:30]}...`")
        
        st.header("CSV FORMAT")
        st.markdown("""
        **Required columns:**
        - **Company** - company name
        - **URL** - website address
        
        **Example:**
        ```
        Company,URL
        Google,google.com
        GitHub,github.com
        Cloudflare,cloudflare.com
        ```
        """)
    
    # Initialize session state for analysis mode
    if 'analysis_mode' not in st.session_state:
        st.session_state.analysis_mode = "Single URL"
    
    # Initialize VirusTotal toggle state
    if 'vt_enabled' not in st.session_state:
        # Check current VT status from detector
        current_vt_enabled = detector and hasattr(detector, 'vt_integration') and detector.vt_integration and detector.vt_integration.is_enabled
        st.session_state.vt_enabled = current_vt_enabled
    
    # Main interface - use radio buttons instead of tabs
    st.subheader("ANALYSIS MODE")
    analysis_mode = st.radio(
        "Select target type:",
        ["SINGLE_URL", "CSV_BATCH"],
        index=0 if st.session_state.analysis_mode == "Single URL" else 1,
        horizontal=True,
        key="analysis_mode_radio"
    )
    
    # VirusTotal toggle section
    st.subheader("⚙️ VIRUSTOTAL SETTINGS")
    
    col_vt1, col_vt2 = st.columns([1, 3])
    
    with col_vt1:
        # VirusTotal toggle
        vt_toggle = st.checkbox(
            "Enable VirusTotal",
            value=st.session_state.vt_enabled,
            key="vt_toggle",
            help="Toggle VirusTotal API integration"
        )
        
        # Update session state
        if vt_toggle != st.session_state.vt_enabled:
            st.session_state.vt_enabled = vt_toggle
            st.rerun()  # Refresh to apply changes
    
    with col_vt2:
        # VirusTotal information and warning
        if st.session_state.vt_enabled:
            st.info("""
            **✅ VirusTotal ENABLED** - Additional security validation and DNS history
            
            **Rate Limits:**
            - Free API: 4 requests/minute (500/day max)
            - Premium API: 300 requests/minute
            
            **⚠️ For CSV batch processing:** Consider disabling VirusTotal to avoid rate limits
            """)
        else:
            st.warning("""
            **❌ VirusTotal DISABLED** - System operates with 9 core modules
            
            **Recommended for:**
            - CSV batch processing (no rate limits)
            - Fast bulk analysis
            - When VirusTotal API quota is exceeded
            
            **Note:** All other detection methods remain fully functional
            """)
        
        # Show current VT API status
        if detector and hasattr(detector, 'vt_integration') and detector.vt_integration:
            actual_vt_status = detector.vt_integration.is_enabled
            if actual_vt_status != st.session_state.vt_enabled:
                if st.session_state.vt_enabled:
                    st.error("⚠️ VirusTotal API not properly configured. Check your VT_API_KEY environment variable.")
                else:
                    st.success("✅ VirusTotal disabled as requested")
    
    # Update session state
    if analysis_mode == "SINGLE_URL":
        st.session_state.analysis_mode = "Single URL"
    else:
        st.session_state.analysis_mode = "CSV Upload"
    
    st.markdown("---")
    
    if st.session_state.analysis_mode == "CSV Upload":
        st.header("CSV_BATCH_PROCESSING")
        
        # VirusTotal warning for CSV batch processing
        if st.session_state.vt_enabled:
            st.warning("""
            ⚠️ **VirusTotal is currently ENABLED** - This may cause delays in batch processing!
            
            **Free API Limits:** 4 requests/minute (500/day max)  
            **For faster batch processing:** Consider disabling VirusTotal above
            
            **Estimated processing time with VT:** ~15 seconds per domain (due to rate limiting)
            """)
        else:
            st.info("""
            ✅ **VirusTotal is DISABLED** - Optimal configuration for batch processing!
            
            **Fast processing:** No rate limits, all 9 core modules active  
            **Estimated time:** ~2-3 seconds per domain
            """)
        
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
                        if st.button("START_ANALYSIS", type="primary"):
                            # Progress bar
                            progress_bar = st.progress(0)
                            status_text = st.empty()
                        
                            results = []
                            
                            # Track success/failure stats
                            success_count = 0
                            error_count = 0
                            
                            for idx, row in df_clean.iterrows():
                                company = row['Company']
                                url = row['URL']
                            
                                # Update progress
                                progress = (idx + 1) / len(df_clean)
                                progress_bar.progress(progress)
                                status_text.text(f"Processing {idx + 1}/{len(df_clean)}: {company}")
                                
                                try:
                                    # Use the same comprehensive analysis as single URL processing
                                    clean_url = url.replace('https://', '').replace('http://', '')
                                    analysis_result = process_single_url(clean_url)
                                    
                                    # Extract data from analysis result for CSV display
                                    result = {
                                        'Company': company,
                                        'URL': analysis_result.get('URL', url),
                                        'Primary_Provider': analysis_result.get('Primary_Provider', 'Unknown'),
                                        'Origin_Provider': analysis_result.get('Origin_Provider', 'Unknown'),
                                        'CDN_Providers': analysis_result.get('CDN_Providers', 'None'),
                                        'WAF_Providers': analysis_result.get('WAF_Providers', 'None'),
                                        'LB_Providers': analysis_result.get('LB_Providers', 'None'),
                                        'DNS_Providers': analysis_result.get('DNS_Providers', 'Unknown'),
                                        'Hosting_Providers': analysis_result.get('Hosting_Providers', 'None'),
                                        'Cloud_Providers': analysis_result.get('Cloud_Providers', 'None'),
                                        'Security_Providers': analysis_result.get('Security_Providers', 'None'),
                                        'IP_Address': analysis_result.get('IP_Address', 'N/A'),
                                        'Confidence': analysis_result.get('Confidence_Factors', 'Low'),
                                        'Enhanced_Confidence': analysis_result.get('Enhanced_Confidence', 'N/A')
                                    }
                                    results.append(result)
                                    success_count += 1
                                    
                                except Exception as e:
                                    # Create error result but continue processing
                                    error_msg = str(e)
                                    if 'timeout' in error_msg.lower() or 'connection' in error_msg.lower():
                                        error_status = 'Connection Timeout'
                                    elif 'ssl' in error_msg.lower():
                                        error_status = 'SSL Error'
                                    else:
                                        error_status = 'Analysis Error'
                                    
                                    result = {
                                        'Company': company,
                                        'URL': url,
                                        'Primary_Provider': error_status,
                                        'Origin_Provider': 'Error',
                                        'CDN_Providers': 'Error',
                                        'WAF_Providers': 'Error', 
                                        'LB_Providers': 'Error',
                                        'DNS_Providers': 'Error',
                                        'IP_Address': 'Error',
                                        'Confidence': f'Error: {error_msg[:50]}...' if len(error_msg) > 50 else f'Error: {error_msg}'
                                    }
                                    results.append(result)
                                    error_count += 1
                        
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
                            
                            # Show results with stats
                            if error_count > 0:
                                st.warning(f"⚠️ Analysis completed with {error_count} errors out of {len(results_df)} total")
                            else:
                                st.success("🎉 Analysis completed successfully!")
                            
                            # Statistics
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric("Total Websites", len(results_df))
                            with col2:
                                st.metric("Successful", success_count, delta=success_count if success_count > 0 else None)
                            with col3:
                                st.metric("Errors", error_count, delta=-error_count if error_count > 0 else None)
                            
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
    
    elif st.session_state.analysis_mode == "Single URL":
        st.header("SINGLE_TARGET_ANALYSIS")
        
        # Initialize session state for URL and results
        if 'last_url' not in st.session_state:
            st.session_state.last_url = ""
        if 'last_result' not in st.session_state:
            st.session_state.last_result = None
        
        # Use form to prevent double-click issues
        with st.form("url_analysis_form", clear_on_submit=False):
            url_input = st.text_input(
                "Enter URL for analysis:",
                value=st.session_state.last_url,
                placeholder="example.com or https://example.com"
            )
            
            col1, col2 = st.columns([1, 4])
            with col1:
                # Simple button logic
                if url_input == st.session_state.last_url and st.session_state.last_result:
                    button_text = "RE_ANALYZE"
                else:
                    button_text = "ANALYZE"
                
                analyze_button = st.form_submit_button(button_text, type="primary")
            with col2:
                # Clear button outside form to avoid conflicts
                pass
        
        # Clear button outside form
        if st.session_state.last_result:
            if st.button("CLEAR_RESULTS"):
                st.session_state.last_result = None
                st.session_state.last_url = ""
                st.rerun()
        
        # Show hint about URL change
        if url_input != st.session_state.last_url and st.session_state.last_result and url_input:
            st.info("URL changed - click ANALYZE to run analysis for the new URL")
        
        if analyze_button and url_input:
            # Validate URL
            is_valid, url_or_error = validate_url(url_input)
            
            if not is_valid:
                st.error(f"INVALID_URL: {url_or_error}")
                st.info("**Valid formats:**")
                st.code("example.com\nhttps://example.com\nwww.example.com")
            else:
                clean_url = url_or_error.replace('https://', '').replace('http://', '')
                
                # Run analysis immediately
                with st.spinner("ANALYZING_TARGET..."):
                    try:
                        result = process_single_url(clean_url)
                        # Save to session state
                        st.session_state.last_result = result
                        st.session_state.last_url = url_input
                        st.success("ANALYSIS_COMPLETED")
                    except Exception as e:
                        st.error(f"ANALYSIS_FAILED: {str(e)}")
                        st.session_state.last_result = None
        
        # Display results if available  
        if st.session_state.last_result:
            result = st.session_state.last_result
            st.markdown("---")
            st.subheader("ANALYSIS_RESULTS")
            
            # Basic results summary
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("TARGET", result['URL'])
                st.metric("IP_ADDRESS", result['IP_Address'])
            with col2:
                st.metric("PRIMARY_PROVIDER", result['Primary_Provider'])
                enhanced_conf = result.get('Enhanced_Confidence', 'N/A')
                st.metric("CONFIDENCE", f"{enhanced_conf}%" if str(enhanced_conf).isdigit() else enhanced_conf)
            with col3:
                enhanced_analysis = result.get('Enhanced_Analysis', {})
                # Count all 8 integrations including Shodan
                main_integrations = ['ssl_analysis', 'enhanced_dns', 'geographic_intelligence', 
                                   'bgp_analysis', 'hurricane_electric_bgp', 'threat_intelligence',
                                   'advanced_bgp_classification', 'shodan_analysis']
                working_count = sum(1 for key in main_integrations 
                                  if key in enhanced_analysis 
                                  and isinstance(enhanced_analysis[key], dict) 
                                  and 'error' not in enhanced_analysis[key])
                st.metric("MODULES_ACTIVE", f"{working_count}/10")
                st.metric("CDN_STATUS", result['CDN_Providers'])
            
            # Advanced BGP Classification Summary
            bgp_classification = result.get('Enhanced_Analysis', {}).get('advanced_bgp_classification', {})
            if bgp_classification and 'error' not in bgp_classification:
                customer_type = bgp_classification.get('classification', 'Unknown')
                bgp_confidence = bgp_classification.get('confidence', 0)
                
                if customer_type != 'UNKNOWN':
                    if customer_type in ['END_CUSTOMER', 'ENTERPRISE_CUSTOMER']:
                        st.info(f"🏢 **CUSTOMER DETECTED**: {customer_type.replace('_', ' ').title()} ({bgp_confidence:.1%} confidence)")
                    elif customer_type in ['HOSTING_PROVIDER', 'CLOUD_PROVIDER', 'CDN_PROVIDER']:
                        st.success(f"⚡ **SERVICE PROVIDER**: {customer_type.replace('_', ' ').title()} ({bgp_confidence:.1%} confidence)")
                    
            # Basic provider summary
            if result['CDN_Providers'] != 'None' or result['WAF_Providers'] != 'None':
                st.success("MULTI_PROVIDER_SETUP_DETECTED")
                provider_info = f"**Origin**: {result['Origin_Provider']} | **CDN**: {result['CDN_Providers']}"
                st.markdown(provider_info)
            
            # Show intelligent DNS detection indicator
            confidence_factors = result.get('Confidence_Factors', '')
            if 'Intelligent DNS analysis' in confidence_factors and result['DNS_Providers'] != 'Unknown':
                st.info(f"🧠 **INTELLIGENT DNS DETECTION**: {result['DNS_Providers']} (AI-powered analysis)")
            elif result['DNS_Providers'] != 'Unknown':
                st.write(f"🌐 **DNS Provider**: {result['DNS_Providers']}")
            
            # Enhanced analysis details
            with st.expander("DETAILED_ANALYSIS"):
                # Show DNS Intelligence Analysis first if available
                confidence_factors = result.get('Confidence_Factors', '')
                if 'Intelligent DNS analysis' in confidence_factors or 'Learning:' in confidence_factors:
                    st.subheader("🧠 Intelligent DNS Detection")
                    st.success("✨ **Advanced AI-powered DNS analysis was used for this domain**")
                    
                    # Extract intelligent DNS findings from confidence factors
                    dns_findings = []
                    if confidence_factors:
                        for factor in confidence_factors.split('; '):
                            if 'DNS analysis' in factor or 'NS record' in factor:
                                dns_findings.append(factor)
                    
                    if dns_findings:
                        st.write("**Intelligent Analysis Results:**")
                        for finding in dns_findings:
                            st.write(f"• {finding}")
                    
                    st.info("🎯 **How it works**: When DNS patterns aren't recognized, the system automatically analyzes WHOIS data, domain patterns, and IP information to identify the DNS provider intelligently.")
                    st.write("---")
                
                # Show Advanced BGP Classification details
                bgp_classification = result.get('Enhanced_Analysis', {}).get('advanced_bgp_classification', {})
                if bgp_classification and 'error' not in bgp_classification:
                    st.subheader("🎯 Advanced BGP Classification")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Classification**: {bgp_classification.get('classification', 'Unknown')}")
                        st.write(f"**Confidence**: {bgp_classification.get('confidence', 0):.1%}")
                        data_sources = bgp_classification.get('data_sources', [])
                        if data_sources:
                            st.write(f"**Data Sources**: {', '.join(data_sources)}")
                    
                    with col2:
                        evidence = bgp_classification.get('evidence', [])
                        if evidence:
                            st.write("**Evidence**:")
                            for ev in evidence[:3]:  # Show top 3 pieces of evidence
                                st.write(f"• {ev}")
                    
                    # Show ML features if available
                    if 'ml_features' in bgp_classification:
                        ml_features = bgp_classification['ml_features']
                        st.write("**ML Analysis Features**:")
                        st.json({
                            'Facilities': ml_features.get('facility_count', 0),
                            'IX Points': ml_features.get('ix_count', 0),
                            'Data Sources': ml_features.get('data_sources_count', 0),
                            'Provider Keywords': ml_features.get('has_provider_keywords', False),
                            'Customer Keywords': ml_features.get('has_customer_keywords', False)
                        })
                
                # Show customer insights if available
                customer_insights = result.get('bgp_customer_insights', [])
                if customer_insights:
                    st.subheader("💡 Customer Insights")
                    for insight in customer_insights[:4]:
                        st.write(f"• {insight}")
                
                # Show Comprehensive Analysis if available
                comprehensive_analysis = result.get('Comprehensive_Analysis', {})
                if comprehensive_analysis and 'error' not in comprehensive_analysis:
                    st.subheader("🔍 Comprehensive Domain Analysis")
                    
                    # DNS Records Analysis
                    dns_records = comprehensive_analysis.get('dns_records', {})
                    if dns_records and 'records' in dns_records:
                        st.write("**📊 Complete DNS Records:**")
                        
                        dns_summary = {}
                        for record_type, records in dns_records['records'].items():
                            if records:  # Only show record types that have data
                                dns_summary[record_type] = len(records)
                        
                        if dns_summary:
                            col1, col2 = st.columns(2)
                            with col1:
                                for record_type, count in list(dns_summary.items())[:4]:
                                    st.metric(f"{record_type} Records", count)
                            with col2:
                                for record_type, count in list(dns_summary.items())[4:8]:
                                    st.metric(f"{record_type} Records", count)
                    
                    # Subdomain Analysis
                    subdomains = comprehensive_analysis.get('subdomains', {})
                    if subdomains and subdomains.get('total_found', 0) > 0:
                        st.write(f"**🌐 Subdomains Discovered:** {subdomains['total_found']}")
                        methods = subdomains.get('enumeration_methods', [])
                        if methods:
                            st.write(f"**Methods Used:** {', '.join(methods)}")
                    
                    # HTTP Analysis
                    http_analysis = comprehensive_analysis.get('http_analysis', {})
                    if http_analysis:
                        protocols = http_analysis.get('protocols', {})
                        if protocols:
                            st.write("**🌐 HTTP/HTTPS Analysis:**")
                            for protocol, data in protocols.items():
                                if data.get('accessible'):
                                    security_score = data.get('security_headers', {}).get('security_score', 0)
                                    st.write(f"• {protocol.upper()}: Accessible (Security Score: {security_score}/100)")
                    
                    # Origin Detection
                    origin_detection = comprehensive_analysis.get('origin_detection', {})
                    if origin_detection and origin_detection.get('potential_origins'):
                        st.write(f"**🎯 Origin Server Detection:** {len(origin_detection['potential_origins'])} candidates found")
                        methods = origin_detection.get('detection_methods', [])
                        if methods:
                            st.write(f"**Detection Methods:** {', '.join(methods)}")
                
                # Show Shodan WAF Analysis if available
                shodan_analysis = result.get('Enhanced_Analysis', {}).get('shodan_analysis', {})
                if shodan_analysis and 'error' not in shodan_analysis:
                    st.subheader("🛡️ Shodan Premium WAF Analysis")
                    
                    waf_detection = shodan_analysis.get('waf_detection', {})
                    if waf_detection.get('success') and waf_detection.get('waf_detected'):
                        waf_type = waf_detection.get('waf_type', 'Unknown WAF')
                        confidence = waf_detection.get('confidence', 0)
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("WAF DETECTED", waf_type)
                        with col2:
                            st.metric("CONFIDENCE", f"{confidence}%")
                        
                        security_headers = waf_detection.get('security_headers', [])
                        if security_headers:
                            st.write(f"**Security Headers**: {len(security_headers)} detected")
                    else:
                        st.write("🔍 **No WAF detected** via Shodan analysis")
                    
                    # Technology stack info
                    tech_stack = shodan_analysis.get('technology_stack', {})
                    if tech_stack.get('success'):
                        technologies = tech_stack.get('technologies', [])
                        if technologies:
                            st.write(f"**Technologies**: {len(technologies)} identified via Shodan")
                elif shodan_analysis and 'error' in shodan_analysis:
                    st.subheader("🛡️ Shodan Premium WAF Analysis")
                    st.write(f"❌ **Shodan analysis failed**: {shodan_analysis['error']}")
                
                st.subheader("📊 All Integrations Status")
                # Show enhanced analysis if available
                enhanced_analysis = result.get('Enhanced_Analysis', {})
                if enhanced_analysis:
                    for section, data in enhanced_analysis.items():
                        if isinstance(data, dict) and 'error' not in data:
                            st.write(f"✅ **{section.replace('_', ' ').title()}**: Working")
                        elif isinstance(data, dict) and 'error' in data:
                            st.write(f"❌ **{section.replace('_', ' ').title()}**: {data['error']}")
                
                # Show security findings
                security_findings = result.get('security_findings', [])
                if security_findings:
                    st.subheader("🛡️ Security Findings")
                    for finding in security_findings[:5]:  # Show first 5
                        st.write(f"• {finding}")
                
                # Show comprehensive step-by-step analysis report
                st.subheader("📋 Complete Analysis Report (9 Steps)")
                
                steps_report = result.get('analysis_steps_report', {})
                if steps_report:
                    for step_key, step_data in steps_report.items():
                        if step_data.get('status') in ['completed', 'failed']:
                            step_name = step_data.get('step_name', step_key.replace('_', ' ').title())
                            status = step_data.get('status', 'unknown')
                            findings = step_data.get('findings', [])
                            methods = step_data.get('methods', [])
                            confidence_impact = step_data.get('confidence_impact', 0)
                            
                            # Status indicator
                            if status == 'completed':
                                status_icon = "✅"
                            elif status == 'failed':
                                status_icon = "❌"
                            else:
                                status_icon = "⏭️"
                            
                            # Create expandable section for each step
                            with st.expander(f"{status_icon} **{step_name}** (+{confidence_impact}% confidence)"):
                                
                                col1, col2 = st.columns(2)
                                
                                with col1:
                                    st.write("**Status:**", status.title())
                                    st.write("**Methods Used:**")
                                    for method in methods:
                                        st.write(f"• {method}")
                                
                                with col2:
                                    st.write(f"**Confidence Impact:** +{confidence_impact}%")
                                    if findings:
                                        st.write("**Key Findings:**")
                                        for finding in findings:
                                            st.write(f"• {finding}")
                                    else:
                                        st.write("**Key Findings:** No specific findings")
                
                # Show backend saved files information
                backend_files = result.get('backend_files')
                if backend_files:
                    st.success(f"✅ **Analysis automatically saved to backend:**")
                    col_a, col_b = st.columns(2)
                    with col_a:
                        st.write(f"📄 **Complete Data:** `{backend_files['json_filename']}`")
                    with col_b:
                        st.write(f"📊 **Summary:** `{backend_files['csv_filename']}`")
                    
                    st.info("💡 **Backend Storage**: All analysis results are automatically saved to the `results/` folder for persistent storage and batch processing")
                
                # Download analysis results functionality
                st.subheader("💾 Download Analysis Results")
                
                # Prepare comprehensive data for download
                download_data = {
                    "analysis_metadata": {
                        "domain": result.get('URL'),
                        "ip_address": result.get('IP_Address'),
                        "analysis_timestamp": result.get('timestamp', 'N/A'),
                        "analysis_version": "Provider Discovery Tool v4.0",
                        "enhanced_confidence": result.get('Enhanced_Confidence'),
                        "total_analysis_steps": len(result.get('analysis_steps_report', {}))
                    },
                    "detection_results": {
                        "primary_provider": result.get('Primary_Provider'),
                        "cdn_providers": result.get('CDN_Providers'),
                        "dns_providers": result.get('DNS_Providers'), 
                        "hosting_providers": result.get('Hosting_Providers'),
                        "cloud_providers": result.get('Cloud_Providers'),
                        "security_providers": result.get('Security_Providers')
                    },
                    "step_by_step_analysis": result.get('analysis_steps_report', {}),
                    "enhanced_analysis_details": result.get('Enhanced_Analysis', {}),
                    "security_findings": result.get('security_findings', []),
                    "geographic_insights": result.get('geographic_insights', []),
                    "bgp_insights": result.get('bgp_insights', []),
                    "recommendations": result.get('Recommendations', []),
                    "technical_details": {
                        "confidence_factors": result.get('confidence_factors', []),
                        "enhanced_confidence_factors": result.get('enhanced_confidence_factors', []),
                        "analysis_methods": result.get('analysis_methods', []),
                        "dns_chain": result.get('dns_chain'),
                        "whois_data": result.get('whois_data')
                    },
                    "comprehensive_analysis": result.get('Comprehensive_Analysis', {})
                }
                
                # Format data for different download formats
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    # JSON download
                    import json
                    json_data = json.dumps(download_data, indent=2, ensure_ascii=False)
                    st.download_button(
                        label="📄 Download JSON",
                        data=json_data,
                        file_name=f"provider_analysis_{result.get('URL', 'unknown').replace('.', '_')}.json",
                        mime="application/json"
                    )
                
                with col2:
                    # CSV download (comprehensive view with full Shodan analytics)
                    
                    # Generate comprehensive CSV using the same logic as file saves
                    try:
                        from src.provider_discovery.core.enhanced_detector import EnhancedProviderDetector
                        
                        # Create detector instance to use CSV generation method
                        detector_instance = EnhancedProviderDetector()
                        
                        # Use the same comprehensive CSV generation as file saves
                        csv_content = detector_instance._generate_comprehensive_csv(download_data, result.get('URL', 'unknown'))
                        
                        csv_buffer = io.StringIO()
                        csv_buffer.write(csv_content)
                        
                    except Exception as e:
                        # Fallback to basic CSV if comprehensive generation fails
                        st.warning(f"Using simplified CSV due to error: {str(e)}")
                        
                        # Create basic CSV data as fallback
                        csv_rows = []
                        
                        # Basic info
                        csv_rows.append({'Category': 'Domain', 'Key': 'URL', 'Value': result.get('URL', 'N/A')})
                        csv_rows.append({'Category': 'Network', 'Key': 'IP_Address', 'Value': result.get('IP_Address', 'N/A')})
                        csv_rows.append({'Category': 'Confidence', 'Key': 'Enhanced_Confidence', 'Value': f"{result.get('Enhanced_Confidence', 0)}%"})
                        
                        # Provider results
                        provider_categories = {
                            'Primary_Provider': 'Primary Provider',
                            'CDN_Providers': 'CDN Providers', 
                            'DNS_Providers': 'DNS Providers',
                            'Hosting_Providers': 'Hosting Providers',
                            'Cloud_Providers': 'Cloud Providers',
                            'Security_Providers': 'Security Providers'
                        }
                        
                        for key, category in provider_categories.items():
                            value = result.get(key, 'None')
                            if isinstance(value, list):
                                unique_values = list(dict.fromkeys([str(v) for v in value if v]))
                                value = ', '.join(unique_values) if unique_values else 'None'
                            elif not value:
                                value = 'None'
                            csv_rows.append({'Category': 'Providers', 'Key': category, 'Value': value})
                        
                        df = pd.DataFrame(csv_rows)
                        csv_buffer = io.StringIO()
                        df.to_csv(csv_buffer, index=False)
                    
                    st.download_button(
                        label="📊 Download CSV",
                        data=csv_buffer.getvalue(),
                        file_name=f"provider_analysis_{result.get('URL', 'unknown').replace('.', '_')}.csv",
                        mime="text/csv"
                    )
                
                with col3:
                    # TXT download (human-readable report)
                    # Fix domain display
                    domain_name = result.get('URL') or 'N/A'
                    
                    # Fix confidence display
                    confidence_value = result.get('Enhanced_Confidence', 0)
                    if isinstance(confidence_value, (int, float)):
                        confidence_display = f"{confidence_value}%"
                    else:
                        confidence_display = str(confidence_value)
                    
                    # Helper function to format provider lists
                    def format_providers(provider_list, none_value='None'):
                        if not provider_list:
                            return none_value
                        if isinstance(provider_list, list):
                            # Remove duplicates and empty values
                            unique_providers = list(dict.fromkeys([str(p) for p in provider_list if p]))
                            return ', '.join(unique_providers) if unique_providers else none_value
                        return str(provider_list) if provider_list else none_value
                    
                    # Get comprehensive analysis data
                    comp_analysis = result.get('Comprehensive_Analysis', {})
                    
                    txt_report = f"""PROVIDER DISCOVERY TOOL v4.0 - ANALYSIS REPORT
{'='*60}

DOMAIN: {domain_name}
IP ADDRESS: {result.get('IP_Address', 'N/A')}
ANALYSIS TIMESTAMP: {result.get('timestamp', 'N/A')}
ENHANCED CONFIDENCE: {confidence_display}

PROVIDER DETECTION RESULTS:
{'='*30}
Primary Provider: {result.get('Primary_Provider', 'Unknown')}
CDN Providers: {format_providers(result.get('CDN_Providers'))}
DNS Providers: {format_providers(result.get('DNS_Providers'))}
Hosting Providers: {format_providers(result.get('Hosting_Providers'))}
Cloud Providers: {format_providers(result.get('Cloud_Providers'))}
Security Providers: {format_providers(result.get('Security_Providers'))}

COMPREHENSIVE TECHNICAL ANALYSIS:
{'='*35}"""

                    # Add comprehensive analysis sections
                    if comp_analysis:
                        # DNS Records Analysis
                        dns_records = comp_analysis.get('dns_records', {}).get('records', {})
                        if dns_records:
                            txt_report += f"""

DNS RECORDS DISCOVERED:
{'-'*23}"""
                            for record_type, records in dns_records.items():
                                if records:
                                    if isinstance(records, list) and len(records) > 0:
                                        txt_report += f"\n{record_type}: {len(records)} record(s)"
                                        # Show first few records for readability
                                        for i, record in enumerate(records[:3]):
                                            if isinstance(record, dict):
                                                txt_report += f"\n  • {record.get('value', record)}"
                                            else:
                                                txt_report += f"\n  • {record}"
                                        if len(records) > 3:
                                            txt_report += f"\n  • ... and {len(records) - 3} more"
                        
                        # Subdomains Analysis
                        subdomains = comp_analysis.get('subdomains', {})
                        if subdomains and subdomains.get('total_found', 0) > 0:
                            txt_report += f"""

SUBDOMAINS DISCOVERED:
{'-'*22}
Total Found: {subdomains.get('total_found', 0)}
Discovery Methods: {', '.join(subdomains.get('enumeration_methods', []))}"""
                            discovered = subdomains.get('discovered_subdomains', {})
                            if discovered:
                                txt_report += "\nSubdomains:"
                                for subdomain, info in list(discovered.items())[:5]:  # Show first 5
                                    ips = info.get('ip_addresses', [])
                                    status = info.get('http_status', 'N/A')
                                    txt_report += f"\n  • {subdomain} → {', '.join(ips)} (HTTP: {status})"
                                if len(discovered) > 5:
                                    txt_report += f"\n  • ... and {len(discovered) - 5} more"
                        
                        # HTTP Analysis
                        http_analysis = comp_analysis.get('http_analysis', {})
                        if http_analysis:
                            protocols = http_analysis.get('protocols', {})
                            if protocols:
                                for protocol, data in protocols.items():
                                    if data.get('accessible', False):
                                        txt_report += f"""

HTTP SECURITY ANALYSIS ({protocol.upper()}):
{'-'*30}
Status: {data.get('status_code', 'N/A')}
Security Score: {data.get('security_headers', {}).get('security_score', 'N/A')}/100"""
                                        
                                        security_headers = data.get('security_headers', {}).get('headers_present', [])
                                        if security_headers:
                                            txt_report += "\nSecurity Headers:"
                                            for header in security_headers[:5]:
                                                if isinstance(header, dict):
                                                    txt_report += f"\n  • {header.get('header', 'Unknown')}: {header.get('value', 'N/A')}"
                                        
                                        cdn_detection = data.get('cdn_detection', {})
                                        if cdn_detection.get('detected_cdns'):
                                            txt_report += f"\nCDN Detection: {', '.join(cdn_detection['detected_cdns'])} (Confidence: {cdn_detection.get('confidence', 'N/A')}%)"
                        
                        # Origin Detection
                        origin_detection = comp_analysis.get('origin_detection', {})
                        if origin_detection and origin_detection.get('potential_origins'):
                            txt_report += f"""

ORIGIN SERVERS DETECTION:
{'-'*25}
Detection Methods: {', '.join(origin_detection.get('detection_methods', []))}
Potential Origins Found: {len(origin_detection.get('potential_origins', []))}"""
                            for origin in origin_detection.get('potential_origins', [])[:3]:
                                origin_type = origin.get('type', 'unknown')
                                confidence = origin.get('confidence', 'unknown')
                                if 'ip' in origin:
                                    txt_report += f"\n  • IP: {origin['ip']} (Type: {origin_type}, Confidence: {confidence})"
                                elif 'subdomain' in origin:
                                    txt_report += f"\n  • Subdomain: {origin['subdomain']} → {origin.get('ip', 'N/A')} (Confidence: {confidence})"

                    txt_report += f"""

STEP-BY-STEP ANALYSIS:
{'='*25}"""
                    
                    # Add step details to TXT report
                    steps_report = result.get('analysis_steps_report', {})
                    for step_key, step_data in steps_report.items():
                        step_name = step_data.get('step_name', step_key.replace('_', ' ').title())
                        status = step_data.get('status', 'unknown')
                        confidence_impact = step_data.get('confidence_impact', 0)
                        findings = step_data.get('findings', [])
                        methods = step_data.get('methods', [])
                        
                        txt_report += f"\n\n{step_name.upper()}:"
                        txt_report += f"\n  Status: {status.title()}"
                        txt_report += f"\n  Confidence Impact: +{confidence_impact}%"
                        txt_report += f"\n  Methods Used: {', '.join(methods) if methods else 'None'}"
                        if findings:
                            txt_report += f"\n  Key Findings:"
                            for finding in findings:
                                # Clean finding text for better formatting
                                clean_finding = str(finding).replace('\n', ' ').replace('\r', ' ').strip()
                                txt_report += f"\n    • {clean_finding}"
                        else:
                            txt_report += f"\n  Key Findings: No specific findings"
                    
                    # Add recommendations
                    recommendations = result.get('Recommendations', [])
                    if recommendations:
                        txt_report += f"\n\nRECOMMENDATIONS:\n{'='*15}"
                        for i, rec in enumerate(recommendations, 1):
                            # Clean recommendation text
                            clean_rec = str(rec).replace('\n', ' ').replace('\r', ' ').strip()
                            txt_report += f"\n{i}. {clean_rec}"
                    else:
                        txt_report += f"\n\nRECOMMENDATIONS:\n{'='*15}\nNo specific recommendations available."
                    
                    txt_report += f"\n\n{'='*60}\nReport generated by Provider Discovery Tool v4.0\n"
                    
                    # Generate safe filename for TXT
                    safe_domain_txt = (domain_name or 'unknown').replace('.', '_').replace('/', '_').replace(':', '_')
                    
                    st.download_button(
                        label="📝 Download TXT",
                        data=txt_report,
                        file_name=f"provider_analysis_{safe_domain_txt}.txt",
                        mime="text/plain"
                    )
                
                # Show file size information
                json_size = len(json_data) / 1024  # KB
                csv_size = len(csv_buffer.getvalue()) / 1024  # KB 
                txt_size = len(txt_report) / 1024  # KB
                
                st.info(f"💡 **Download Options**: JSON ({json_size:.1f}KB) - complete data | CSV ({csv_size:.1f}KB) - spreadsheet format | TXT ({txt_size:.1f}KB) - human-readable report")
                
                # Show what's included in downloads
                with st.expander("📦 What's included in downloads"):
                    st.write("**All formats include:**")
                    st.write("• Complete analysis metadata (domain, IP, timestamp, confidence)")
                    st.write("• All 9 step-by-step analysis results")
                    st.write("• **JSON**: Full comprehensive analysis (DNS records, subdomains, HTTP headers, origin detection)")
                    st.write("• **CSV**: Complete Shodan analytics (80+ metrics, security scores, technologies, vulnerabilities)")
                    st.write("• **TXT**: Human-readable report with comprehensive analysis (DNS records, subdomains, HTTP security, origin detection)")
                    st.write("• Provider detection results (CDN, DNS, hosting, cloud)")
                    st.write("• Security findings and recommendations")
                    
                    st.write("**JSON format additionally includes:**")
                    st.write("• Complete technical details from all integrations")
                    st.write("• Raw data from SSL, DNS, BGP, geographic, and threat analysis")
                    st.write("• Full confidence factor breakdowns")
                    st.write("• WHOIS data and DNS chain information")
                
                # Show basic technical details
                st.subheader("🔧 Technical Details")
                st.json({
                    "URL": result.get('URL'),
                    "IP": result.get('IP_Address'), 
                    "Primary_Provider": result.get('Primary_Provider'),
                    "CDN": result.get('CDN_Providers'),
                    "Enhanced_Confidence": result.get('Enhanced_Confidence')
                })

if __name__ == "__main__":
    main()
