import json

from security_engine.calibration import calibrate, fit_category_thresholds, fit_min_review_thresholds, load_thresholds


def test_fit_uses_only_validation_rows_and_respects_fpr_cap():
    rows = [
        {"score": 90, "label": True, "predicted_category": "reconnaissance"},
        {"score": 70, "label": True, "predicted_category": "reconnaissance"},
        {"score": 80, "label": False, "predicted_category": "reconnaissance"},
        {"score": 20, "label": False, "predicted_category": "reconnaissance"},
    ]
    fitted = fit_category_thresholds(rows, max_fpr=0)
    assert fitted["reconnaissance"]["threshold"] == 90
    assert fitted["reconnaissance"]["false_positive_rate"] == 0
    assert fitted["credential_abuse"]["threshold"] == 101


def test_calibration_has_four_outcomes():
    thresholds = {"credential_abuse": 65}
    assert calibrate(10, "credential_abuse", thresholds).disposition == "BENIGN"
    assert calibrate(70, "credential_abuse", thresholds).disposition == "REVIEW"
    assert calibrate(95, "credential_abuse", thresholds).disposition == "HIGH_RISK"
    assert calibrate(95, "credential_abuse", thresholds, confidence=.2).disposition == "UNCERTAIN"

def test_minimum_review_point_meets_validation_recall_target():
    rows=[{"score":s,"label":label,"predicted_category":"credential_abuse","true_category":"credential_abuse"}
          for s,label in [(95,True),(80,True),(60,True),(40,True),(90,False),(30,False)]]
    result=fit_min_review_thresholds(rows,.75)["credential_abuse"]
    assert result["recall"] >= .75
    assert result["threshold"] == 60


def test_threshold_cache_refreshes_when_calibration_file_changes(tmp_path):
    path = tmp_path / "calibration.json"
    path.write_text(json.dumps({"hybrid_thresholds": {"benign": 41}}))
    assert load_thresholds(path)["benign"] == 41
    path.write_text(json.dumps({"hybrid_thresholds": {"benign": 73}}))
    import os
    os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1_000_000))
    assert load_thresholds(path)["benign"] == 73
