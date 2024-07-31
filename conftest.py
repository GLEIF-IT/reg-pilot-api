import pytest


def pytest_collection_modifyitems(config, items):
    if not config.getoption("-m"):
        skip_manual = pytest.mark.skip(reason="need to add -m 'manual' option to run")
        for item in items:
            if "manual" in item.keywords:
                item.add_marker(skip_manual)
