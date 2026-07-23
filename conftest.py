"""
pytest configuration.

serp_monitor now sources its path settings ONLY from the environment (no
built-in fallbacks), so importing it requires those variables to be set. The
tests stub out all real filesystem/browser I/O, so dummy values are enough —
except LOG_FILE, which a logging FileHandler opens at import time, so it must
point at a writable location.

setdefault is used so a real environment / .env still takes precedence.
"""
import os
import tempfile

_tmp = tempfile.gettempdir()

os.environ.setdefault("PROFILE_DIR", os.path.join(_tmp, "serim-test-profile"))
os.environ.setdefault("TRIAGE_FILE", os.path.join(_tmp, "serim-test-triaged.json"))
os.environ.setdefault("EVIDENCE_DIR", os.path.join(_tmp, "serim-test-evidence"))
os.environ.setdefault("FINDINGS_DB", os.path.join(_tmp, "serim-test-findings.db"))
os.environ.setdefault("LOG_FILE", os.path.join(_tmp, "serim-test-brand_monitor.log"))
