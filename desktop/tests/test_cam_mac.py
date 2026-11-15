"""A camera's locally-administered MAC must NOT be treated as a rotating 'randomized' MAC (so it can be reserved)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_core as C  # noqa: E402


def test_locally_administered_bit_detected():
    assert C.is_random_mac("5A:5A:02:8C:D5:F2") is True   # 5A has the locally-administered bit set
    assert C.is_random_mac("00:12:31:84:0B:C0") is False  # a normal vendor MAC


def test_cameras_and_gear_are_fixed_mac_categories():
    for cat in (C.CAT_CAM, C.CAT_NET, C.CAT_ROUTER, C.CAT_PRN, C.CAT_BIO):
        assert cat in C.FIXED_MAC_CATS
    # phones / PCs / unknown really DO randomize, so they stay flagged
    for cat in (C.CAT_PHONE, C.CAT_PC, C.CAT_UNK):
        assert cat not in C.FIXED_MAC_CATS
