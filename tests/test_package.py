"""The first test: the package can be imported and has a version."""

import iacgraph


def test_the_package_has_a_version():
    assert iacgraph.__version__ == "0.1.0"
