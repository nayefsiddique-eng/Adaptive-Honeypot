# conftest.py
# Suppress known third-party deprecation warnings that originate strictly
# inside Starlette/FastAPI/SQLAlchemy internals, not in PRAETOR application code.
#
# WHY HERE and not just pyproject.toml filterwarnings:
#   pytest processes pyproject.toml filterwarnings only after test modules are
#   imported. The Starlette warning fires at import time during collection, before
#   the ini filters are active. A warnings.filterwarnings() call in conftest.py
#   is executed at process startup and covers that gap.
#
# SCOPE: Each filter uses the exact message string and module pattern so that
# any new warning from PRAETOR's own code is still surfaced.

import warnings

# Starlette 1.3+ deprecates using the old httpx transport in TestClient.
# This is a test-tooling migration note (httpx -> httpx2), not a runtime issue.
# Our FastAPI application does not use httpx at runtime.
warnings.filterwarnings(
    "ignore",
    message=r"Using `httpx` with `starlette\.testclient` is deprecated; install `httpx2` instead\.",
    category=Warning,
    module=r"starlette\.testclient",
)

# SQLAlchemy's schema default compiler internally calls datetime.utcnow() to
# generate column default values. All PRAETOR code has been migrated to
# datetime.now(UTC); this residual warning is entirely inside third-party code.
warnings.filterwarnings(
    "ignore",
    message=r"datetime\.datetime\.utcnow\(\) is deprecated",
    category=DeprecationWarning,
    module=r"sqlalchemy\.sql\.schema",
)
