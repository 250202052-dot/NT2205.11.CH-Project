"""Isolated policy/privacy regression plus validation of actual lab logs."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("metadata_validator", ROOT / "data/schemas/validate_zeek_metadata.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def main():
    schema = json.loads(validator.SCHEMA_PATH.read_text())
    script = (ROOT / "sensors/zeek/metadata_fields.zeek").read_text()
    for module, stream in (("Conn", "conn"), ("SSL", "ssl"), ("X509", "x509"),
                           ("SSH", "ssh"), ("Notice", "notice"), ("Weird", "weird")):
        fields = re.findall(r'"([^"]+)"', re.search(r'\[' + module + r'::LOG\]\s*=\s*set\((.*?)\)', script, re.S)[1])
        assert set(fields) == set(schema["streams"][stream]), f"Schema drift: {stream}"
    with tempfile.TemporaryDirectory(prefix="topic4-zeek-") as temporary:
        args = ["docker", "run", "--rm", "--network", "none",
                "--mount", f"type=bind,source={ROOT / 'sensors/zeek'},target=/config,readonly",
                "--mount", f"type=bind,source={ROOT / 'tests/zeek'},target=/tests,readonly",
                "--mount", f"type=bind,source={temporary},target=/output", "--workdir", "/output",
                "--entrypoint", "zeek", "topic4-zeek", "-b", "/config/local.zeek", "/tests/policy_cases.zeek"]
        result = subprocess.run(args, capture_output=True, text=True, timeout=45)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "PASS:" in result.stdout
        directory = Path(temporary)
        counts = validator.validate(directory)
        assert {"conn", "ssl", "ssh", "notice", "weird"} <= set(counts), counts
        for path in directory.glob("*.log"):
            assert "PRIVATE_PAYLOAD_MARKER" not in path.read_text(), path.name
        # Validator must reject a newly added L7 field and an unexpected stream.
        bad = directory / "conn.invalid.log"
        bad.write_text(json.dumps({"uid": "test", "http.body": "sentinel"}) + "\n")
        try:
            validator.validate(directory)
        except ValueError as error:
            assert "Disallowed fields" in str(error)
        else:
            raise AssertionError("Validator accepted L7 field")
        bad.unlink()
        bad = directory / "http.log"
        bad.write_text('{}\n')
        try:
            validator.validate(directory)
        except ValueError as error:
            assert "Disallowed stream" in str(error)
        else:
            raise AssertionError("Validator accepted HTTP log")
    print(result.stdout.strip())
    print("PASS: output removes SNI, subject, banner comments and free-text weird details")
    print("PASS live metadata:", dict(validator.validate(ROOT / "data/lab_metadata/zeek")))


if __name__ == "__main__":
    main()
