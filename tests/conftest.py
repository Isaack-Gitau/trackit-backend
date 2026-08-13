"""
TRACKIT Pytest Configuration.

Shared fixtures for unit and integration tests.
"""

import pytest


@pytest.fixture
def test_marker() -> str:
    """
    Basic fixture proving that the TRACKIT test environment loads.
    """
    return "TRACKIT"