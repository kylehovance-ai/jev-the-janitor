"""Keep the suite hermetic: journals go to a temp cache dir, and no test can reach the API."""

import pytest


@pytest.fixture(autouse=True)
def _isolated_cache_dir(tmp_path_factory, monkeypatch):
    monkeypatch.setenv("JEV_JANITOR_CACHE_DIR", str(tmp_path_factory.mktemp("jev-cache")))


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    # If a test ever constructs a real client by mistake, the request fails fast and locally.
    monkeypatch.setenv("TYPESAFE_BASE_URL", "http://127.0.0.1:9")
