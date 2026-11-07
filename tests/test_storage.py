import storage


def test_scan_log_roundtrip(tmp_path, monkeypatch):
    path = tmp_path / "logs" / "scan_log.csv"
    monkeypatch.setattr(storage, "LOG_PATH", path)

    storage.append_scan_log("hello", "SAFE", 90.0)
    storage.append_scan_log("bad", "PHISHING", 80.0)

    rows = storage.read_scan_log()
    assert [r["Verdict"] for r in rows] == ["SAFE", "PHISHING"]
    assert rows[0]["Message"] == "hello"
    assert path.read_text().count("Timestamp") == 1


def test_scan_log_created_with_directory(tmp_path, monkeypatch):
    path = tmp_path / "nested" / "logs" / "scan_log.csv"
    monkeypatch.setattr(storage, "LOG_PATH", path)
    storage.append_scan_log("x", "SAFE", 1.0)
    assert path.exists()


def test_clear_scan_log(tmp_path, monkeypatch):
    path = tmp_path / "scan_log.csv"
    monkeypatch.setattr(storage, "LOG_PATH", path)
    storage.append_scan_log("x", "SAFE", 1.0)
    storage.clear_scan_log()
    assert storage.read_scan_log() == []


def test_feedback_roundtrip_and_header_once(tmp_path, monkeypatch):
    path = tmp_path / "data" / "feedback.csv"
    monkeypatch.setattr(storage, "FEEDBACK_PATH", path)

    storage.append_feedback("first", 1)
    storage.append_feedback("second", 0)

    assert storage.read_feedback() == [
        {"text": "first", "label": 1},
        {"text": "second", "label": 0},
    ]
    assert path.read_text().count("text,label") == 1


def test_feedback_headerless_file(tmp_path, monkeypatch):
    path = tmp_path / "feedback.csv"
    path.write_text("hello,1\n", encoding="utf-8")
    monkeypatch.setattr(storage, "FEEDBACK_PATH", path)
    assert storage.read_feedback() == [{"text": "hello", "label": 1}]


def test_feedback_skips_invalid_rows(tmp_path, monkeypatch):
    path = tmp_path / "feedback.csv"
    path.write_text("text,label\n,\nbad,2\ngood,0\n", encoding="utf-8")
    monkeypatch.setattr(storage, "FEEDBACK_PATH", path)
    assert storage.read_feedback() == [{"text": "good", "label": 0}]


def test_feedback_rejects_invalid_label(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "FEEDBACK_PATH", tmp_path / "f.csv")
    try:
        storage.append_feedback("x", 5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
