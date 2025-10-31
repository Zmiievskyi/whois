"""
Tests for Streamlit front-end helpers (process_single_url progress reporting)
"""
from types import SimpleNamespace, ModuleType
import sys
import pytest

import app


class DummyDetector:
    """Minimal detector stub used by process_single_url"""

    def __init__(self):
        self.headers_called = False
        self.ip_called = False
        self.whois_called = False

    def get_headers(self, url):
        self.headers_called = True
        return "Server: example\nX-Test: true"

    def get_ip(self, url):
        self.ip_called = True
        return "203.0.113.10"

    def get_whois(self, ip):
        self.whois_called = True
        return "NetRange: 203.0.113.0 - 203.0.113.255"


class DummyEnhancedDetector:
    """Minimal backend saver stub"""

    def __init__(self, *args, **kwargs):
        pass

    def _save_analysis_to_backend(self, result, domain):
        # Pretend to persist results without touching the filesystem
        self.saved = (result, domain)


def _patch_core_dependencies(monkeypatch, *, comprehensive_ok=True):
    """Helper to stub heavy dependencies used inside process_single_url"""
    dummy_detector = DummyDetector()

    # get_detector_instance -> DummyDetector
    monkeypatch.setattr(app, "get_detector_instance", lambda: dummy_detector)

    # detect_provider -> deterministic response
    def fake_detect_provider(headers, ip, whois_data, domain):
        return {
            "providers": [
                {"name": "ExampleOrigin", "role": "Origin"},
                {"name": "ExampleCDN", "role": "CDN"},
                {"name": "ExampleWAF", "role": "WAF"},
            ],
            "primary_provider": "ExampleCDN",
            "confidence_factors": ["Official IP range match"],
            "dns_chain": [],
            "dns_analysis": {},
            "ttl_analysis": {},
            "Enhanced_Analysis": {},
            "Enhanced_Confidence": 96,
            "analysis_steps_report": {},
        }

    monkeypatch.setattr(app, "detect_provider", fake_detect_provider)

    # Comprehensive analysis stub
    app.COMPREHENSIVE_ANALYSIS_AVAILABLE = True

    class DummyComprehensive:
        def analyze_domain_comprehensive(self, domain):
            if not comprehensive_ok:
                raise RuntimeError("CT service unavailable")
            return {
                "domain": domain,
                "dns_records": {},
                "subdomains": {"discovered_subdomains": {}},
            }

    monkeypatch.setattr(app, "get_comprehensive_analysis", lambda: DummyComprehensive())

    # Inject fake EnhancedProviderDetector module so import inside process_single_url works
    fake_module = ModuleType("fake_enhanced_detector")
    fake_module.EnhancedProviderDetector = DummyEnhancedDetector
    sys.modules["src.provider_discovery.core.enhanced_detector"] = fake_module

    return dummy_detector


@pytest.mark.frontend
def test_process_single_url_emits_progress_events(monkeypatch):
    """Ensure progress callback receives ordered updates and completes successfully."""
    _patch_core_dependencies(monkeypatch, comprehensive_ok=True)

    events = []

    def progress(event):
        events.append(event)

    result = app.process_single_url("https://example.com", progress_callback=progress)

    labels = [event["label"] for event in events]

    assert labels[0].startswith("🚀 Initializing analysis")
    assert any("Step 1" in label for label in labels)
    assert any("Step 2" in label for label in labels)
    assert any("Step 4" in label for label in labels)
    assert "✅ Analysis complete" in labels[-1]

    # Final event should be marked as complete
    assert events[-1]["state"] == "complete"
    assert result["Primary_Provider"] == "ExampleCDN"


@pytest.mark.frontend
def test_process_single_url_reports_errors(monkeypatch):
    """If comprehensive analysis fails, progress callback should receive an error status."""
    _patch_core_dependencies(monkeypatch, comprehensive_ok=False)

    events = []

    def progress(event):
        events.append(event)

    result = app.process_single_url("https://example.org", progress_callback=progress)

    error_events = [e for e in events if e["state"] == "error"]
    assert error_events, "Expected at least one error event when comprehensive analysis fails"
    assert any("Comprehensive analysis failed" in e["label"] for e in error_events)

    # Final notification should reflect warnings
    assert events[-1]["label"].startswith("⚠️ Analysis completed with warnings")
    assert result["Primary_Provider"] == "ExampleCDN"
