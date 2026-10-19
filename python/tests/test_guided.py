import json

from aeos_receipts import ReceiptLog
from aeos_receipts import demo, setup, status
from aeos_receipts.cli import main


def test_demo_runs_and_leaves_example_files(tmp_path, capsys):
    folder = tmp_path / "demo"
    assert demo.run(folder) == 0
    text = capsys.readouterr().out
    assert text.count("VALID") >= 2 and "Match: yes" in text
    assert "readable view differs" in text
    assert ReceiptLog.open(folder / "log", read_only=True).verify().ok
    assert (folder / "payment-receipt.json").exists() and (folder / "public-key.txt").exists()
    assert demo.run(folder) == 2                     # refuses to overwrite


def test_setup_with_typed_answers(tmp_path):
    answers = iter(["Acme AP", str(tmp_path / "ap-log"), str(tmp_path / "keys" / "ap.key"),
                    "", "3"])
    out = []
    code = setup.run(setup.Wizard(ask=lambda q: next(answers), out=out.append))
    assert code == 0
    log = ReceiptLog.open(tmp_path / "ap-log", key_path=tmp_path / "keys" / "ap.key")
    assert log.log_id == "urn:aeos:acme-ap" and log.can_sign
    assert not (tmp_path / "ap-log" / "signing.key").exists()
    hooks = json.loads((tmp_path / "ap-log" / "claude-settings.json").read_text())["hooks"]
    assert "aeos-receipts hook" in hooks["PreToolUse"][0]["hooks"][0]["command"]
    assert (tmp_path / "ap-log" / "NEXT-STEPS.txt").exists()
    assert (tmp_path / "ap-log" / "public-key.txt").read_text().strip() == log.public_key.hex()


def test_setup_from_options_for_a_gateway(tmp_path, capsys):
    code = main(["setup", "--yes", "--name", "ops", "--log", str(tmp_path / "ops"),
                 "--key", str(tmp_path / "k" / "ops.key"), "--mode", "gateway"])
    assert code == 0
    assert (tmp_path / "k" / "ops.sink-token").stat().st_mode & 0o777 == 0o600
    assert "aeos-receipts sink" in capsys.readouterr().out
    assert main(["setup", "--yes", "--log", str(tmp_path / "ops")]) == 2   # already a log


def test_status_and_plain_language_results(tmp_path, capsys):
    demo.run(tmp_path / "d")
    capsys.readouterr()
    assert main(["status", str(tmp_path / "d" / "log")]) == 0
    text = capsys.readouterr().out
    assert "6 records" in text and "Every record is covered" in text
    s = status.summary(ReceiptLog.open(tmp_path / "d" / "log", read_only=True))
    assert s["tool_calls"] == 1 and s["checkpoints"] == 2
    assert main(["verify", str(tmp_path / "d" / "tampered-copy")]) == 1
    assert "What to do:" in capsys.readouterr().out


def test_empty_log_status_and_missing_record(tmp_path, capsys):
    key = str(tmp_path / "k.key")
    assert main(["init", str(tmp_path / "log"), "--key", key]) == 0
    capsys.readouterr()
    assert main(["status", str(tmp_path / "log"), "--key", key]) == 0
    text = capsys.readouterr().out
    assert "No records yet" in text and "covered by a signed checkpoint" not in text
    assert main(["receipt", str(tmp_path / "log"), "0", "--key", key]) == 1
    assert "No record 0" in capsys.readouterr().err
