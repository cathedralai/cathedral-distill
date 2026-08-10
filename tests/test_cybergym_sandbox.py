"""The adversarial-PoC sandbox must NOT cap virtual address space by default.

CyberGym targets are sanitizer builds (ASan/MSan) that reserve ~20 TiB of *virtual*
shadow memory at init and abort under any small RLIMIT_AS. Capping virtual AS there
turns every genuine crash into "did not crash" (the enclave differential path via
`cybergym_enclave_solver` did exactly that), so `sandboxed_subprocess_backend` must
leave RLIMIT_AS untouched unless a caller explicitly asks. These tests read the
child's own RLIMIT_AS to pin that, without depending on overcommit behaviour.
"""
from __future__ import annotations

import resource
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral_distill.cybergym_verifier import sandboxed_subprocess_backend  # noqa: E402

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="RLIMIT_AS preexec sandbox is Linux-only"
)

_PARENT_AS_SOFT, _ = resource.getrlimit(resource.RLIMIT_AS)
_CAP = 2 * 1024**3

# Each child exits 0 iff its OWN RLIMIT_AS soft limit matches the expectation.
_EXPECT_UNLIMITED = (
    'python3 -c "import resource,sys;'
    "s,_=resource.getrlimit(resource.RLIMIT_AS);"
    'sys.exit(0 if s==resource.RLIM_INFINITY else 1)"'
)
_EXPECT_CAP = (
    'python3 -c "import resource,sys;'
    "s,_=resource.getrlimit(resource.RLIMIT_AS);"
    f'sys.exit(0 if s=={_CAP} else 1)"'
)


@pytest.mark.skipif(
    _PARENT_AS_SOFT != resource.RLIM_INFINITY,
    reason="test environment itself caps RLIMIT_AS; cannot distinguish inherited from set",
)
def test_address_space_uncapped_by_default():
    # No memory_bytes -> the backend must not set RLIMIT_AS, so a sanitizer target's
    # ~20 TiB virtual reservation is never refused; the child sees an unlimited AS.
    backend = sandboxed_subprocess_backend(_EXPECT_UNLIMITED)
    assert backend("t", b"", "vul") == 0


def test_address_space_capped_only_when_requested():
    # An explicit memory_bytes still caps AS for a non-sanitizer workload that wants it.
    backend = sandboxed_subprocess_backend(_EXPECT_CAP, memory_bytes=_CAP)
    assert backend("t", b"", "vul") == 0
