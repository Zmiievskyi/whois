"""Web interface module"""

# Import main app function for easy access
try:
    from .app import main as run_web_app
    __all__ = ['run_web_app']
except ImportError:
    # Streamlit might not be available in all environments
    __all__ = []
