import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_core as c


def test_category_counts_splits_nvr_from_cameras():
    # cameras and NVR/DVR must be counted separately, exactly like the top summary bar, so the Home card
    # never disagrees with it (Rakesh, 24 Nov).
    devs = [{"category": c.CAT_CAM}, {"category": c.CAT_CAM},
            {"category": c.CAT_CAM, "kind": "nvr"}, {"category": c.CAT_CAM, "name": "Main DVR"}]
    out = c.category_counts(devs)
    assert out.get("CCTV cameras") == 2
    assert out.get("DVR / NVR") == 2


def test_category_counts_plain_cameras_only():
    devs = [{"category": c.CAT_CAM}, {"category": c.CAT_CAM}, {"category": c.CAT_CAM}]
    assert c.category_counts(devs) == {"CCTV cameras": 3}
