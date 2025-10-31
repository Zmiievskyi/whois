#!/usr/bin/env python3
"""
Application launcher for Provider Discovery Tool
"""
import sys
import os
from pathlib import Path

# Add src directory to path
PROJECT_ROOT = Path(__file__).parent.parent
SRC_PATH = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_PATH))

def main():
    """Main launcher function"""
    print("🚀 Provider Discovery Tool Launcher")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not SRC_PATH.exists():
        print("❌ Error: src directory not found")
        print(f"Expected path: {SRC_PATH}")
        print("Please run this script from the project root directory")
        sys.exit(1)
    
    # Show environment info
    from provider_discovery.config import get_settings
    settings = get_settings()
    
    print(f"📍 Project root: {PROJECT_ROOT}")
    print(f"🐍 Python version: {sys.version}")
    print(f"🦠 VirusTotal: {'✅ Enabled' if settings.is_virustotal_enabled() else '❌ Disabled'}")
    print(f"🔍 DNS Analysis: {'✅ Enabled' if settings.enable_dns_analysis else '❌ Disabled'}")
    
    # Check arguments
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "web":
            print("\n🌐 Starting web interface...")
            launch_web_app()
        elif command == "test":
            print("\n🧪 Running tests...")
            run_tests()
        elif command == "config":
            print("\n🔧 Configuration information:")
            show_config()
        else:
            print(f"\n❌ Unknown command: {command}")
            show_help()
    else:
        show_help()

def launch_web_app():
    """Launch Streamlit web application"""
    try:
        import streamlit.web.cli as stcli
        import streamlit as st
        
        # Path to web app
        web_app_path = SRC_PATH / "provider_discovery" / "web" / "app.py"
        
        if not web_app_path.exists():
            print(f"❌ Web app not found at: {web_app_path}")
            print("The web app hasn't been moved to the new structure yet.")
            
            # Try old location
            old_app_path = PROJECT_ROOT / "app.py"
            if old_app_path.exists():
                print(f"🔄 Using legacy app at: {old_app_path}")
                sys.argv = ["streamlit", "run", str(old_app_path)]
                stcli.main()
            else:
                print("❌ No web app found")
                sys.exit(1)
        else:
            # Launch new structured app
            sys.argv = ["streamlit", "run", str(web_app_path)]
            stcli.main()
            
    except ImportError:
        print("❌ Streamlit not installed")
        print("Install with: pip install streamlit")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error launching web app: {e}")
        sys.exit(1)

def run_tests():
    """Run test suite"""
    import subprocess
    
    test_files = [
        PROJECT_ROOT / "test_phase_2a.py",
        PROJECT_ROOT / "test_phase_2b.py",
    ]
    
    for test_file in test_files:
        if test_file.exists():
            print(f"\n🧪 Running {test_file.name}...")
            try:
                result = subprocess.run([sys.executable, str(test_file)], 
                                     capture_output=True, text=True, cwd=PROJECT_ROOT)
                
                if result.returncode == 0:
                    print(f"✅ {test_file.name} passed")
                    if result.stdout:
                        print(result.stdout)
                else:
                    print(f"❌ {test_file.name} failed")
                    if result.stderr:
                        print(result.stderr)
                        
            except Exception as e:
                print(f"❌ Error running {test_file.name}: {e}")

def show_config():
    """Show detailed configuration"""
    from provider_discovery.config.settings import get_settings, print_configuration_info
    
    settings = get_settings()
    print_configuration_info(settings)

def show_help():
    """Show help information"""
    print("""
📋 Usage:
    python scripts/run_app.py [command]

🔧 Available commands:
    web     - Launch Streamlit web interface
    test    - Run test suite
    config  - Show configuration information
    
📖 Examples:
    python scripts/run_app.py web
    python scripts/run_app.py test
    python scripts/run_app.py config

🌍 Environment:
    Set VT_API_KEY environment variable for VirusTotal integration
    Copy env.example to .env and configure settings
    
🔗 For more information, see README.md
""")

if __name__ == "__main__":
    main()
