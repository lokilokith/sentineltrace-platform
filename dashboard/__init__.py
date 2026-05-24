import platform
import sys
import socket
import logging

# ---------------------------------------------------------------------------
# Python 3.13 Windows Hang Patch
# ---------------------------------------------------------------------------
# platform.uname() can hang on Windows due to slow WMI queries.
# Pandas imports platform and calls uname() for WASM checks.
# We monkeypatch it early to return a static result.
if sys.platform == "win32":
    from collections import namedtuple
    _UnameResult = namedtuple("uname_result", ["system", "node", "release", "version", "machine"])
    
    def _patched_uname():
        try:
            node = socket.gethostname()
        except Exception:
            node = "SentinelTrace-Host"
        # Return standard Windows 10/11 results to satisfy most library checks
        return _UnameResult("Windows", node, "10", "10.0.19045", "AMD64")
    
    # Apply monkeypatches
    platform.uname   = _patched_uname
    platform.machine = lambda: "AMD64"
    platform.node    = lambda: _patched_uname().node
    platform.system  = lambda: "Windows"
    platform.release = lambda: "10"
    platform.version = lambda: "10.0.19045"
    
    # Silence the WMI-related loggers if they exist
    _wmi_log = logging.getLogger("WMI")
    if _wmi_log:
        _wmi_log.setLevel(logging.CRITICAL)
