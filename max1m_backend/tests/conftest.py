"""Isolate test configuration before application modules are imported."""
import os
import tempfile

_test_data = tempfile.TemporaryDirectory(prefix="max1m-tests-")
os.environ["MAX1M_DATA_DIR"] = _test_data.name
os.environ["SECRET_KEY"] = "test-only-secret-not-for-production"
