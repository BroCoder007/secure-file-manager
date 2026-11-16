"""CLI/security regression tests. Each case uses a disposable working directory."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLI = Path(os.environ.get("SFM_CLI", ROOT / "bin" / "secure_file_manager")).resolve()
if not CLI.exists() and CLI.with_suffix(".exe").exists():
    CLI = CLI.with_suffix(".exe")
PASSWORD = "test password with spaces & punctuation!"


class SecureFileManagerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sfm-test-")
        self.addCleanup(self.directory.cleanup)
        self.cwd = Path(self.directory.name)

    def run_cli(self, *args, success=True, stdin=None):
        result = subprocess.run(
            [str(CLI), *map(str, args)], cwd=self.cwd, input=stdin,
            capture_output=True, text=True, timeout=30,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def write(self, name, data):
        path = self.cwd / name
        path.write_bytes(data)
        return path

    def encrypt(self, data=b"private content", name="input.bin"):
        self.write(name, data)
        self.run_cli("encrypt", name, "encrypted.sfm", PASSWORD)
        return self.cwd / "encrypted.sfm"

    def test_round_trips_stream_boundaries_and_binary(self):
        for size in (0, 1, 15, 16, 17, 65535, 65536, 65537, 2 * 1024 * 1024 + 3):
            with self.subTest(size=size):
                data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
                source = f"source-{size}.bin"
                encrypted = f"encrypted-{size}.sfm"
                restored = f"restored-{size}.bin"
                self.write(source, data)
                self.run_cli("encrypt", source, encrypted, PASSWORD)
                self.run_cli("decrypt", encrypted, restored, PASSWORD)
                self.assertEqual((self.cwd / restored).read_bytes(), data)

    def test_ciphertext_is_randomized(self):
        self.encrypt()
        self.run_cli("encrypt", "input.bin", "second.sfm", PASSWORD)
        self.assertNotEqual((self.cwd / "encrypted.sfm").read_bytes(),
                            (self.cwd / "second.sfm").read_bytes())

    def test_wrong_password_does_not_publish_plaintext(self):
        self.encrypt()
        self.run_cli("decrypt", "encrypted.sfm", "restored", "wrong password", success=False)
        self.assertFalse((self.cwd / "restored").exists())
        self.assertEqual(sorted(p.name for p in self.cwd.iterdir()), ["encrypted.sfm", "input.bin"])

    def test_tamper_and_truncation_rejected_without_output(self):
        encrypted = self.encrypt(bytes(range(256)) * 300)
        data = encrypted.read_bytes()
        variants = []
        for position in (0, 10, len(data) // 2, len(data) - 1):
            damaged = bytearray(data)
            damaged[position] ^= 1
            variants.append(bytes(damaged))
        malformed_kdf = bytearray(data)
        malformed_kdf[12:16] = b"\xff" * 4
        variants.append(bytes(malformed_kdf))
        variants.extend(data[:length] for length in (0, 1, 7, 16, len(data) - 1))
        for index, damaged in enumerate(variants):
            with self.subTest(index=index):
                self.write(f"damaged-{index}.sfm", damaged)
                self.run_cli("decrypt", f"damaged-{index}.sfm", f"output-{index}", PASSWORD, success=False)
                self.assertFalse((self.cwd / f"output-{index}").exists())

    def test_existing_destination_and_same_path_are_preserved(self):
        self.encrypt()
        expected_source = (self.cwd / "input.bin").read_bytes()
        self.write("existing", b"keep this file")
        self.run_cli("encrypt", "input.bin", "existing", PASSWORD, success=False)
        self.run_cli("decrypt", "encrypted.sfm", "existing", PASSWORD, success=False)
        self.run_cli("encrypt", "input.bin", "input.bin", PASSWORD, success=False)
        self.assertEqual((self.cwd / "existing").read_bytes(), b"keep this file")
        self.assertEqual((self.cwd / "input.bin").read_bytes(), expected_source)
        before = (self.cwd / "encrypted.sfm").read_bytes()
        self.run_cli("decrypt", "encrypted.sfm", "encrypted.sfm", PASSWORD, success=False)
        self.assertEqual((self.cwd / "encrypted.sfm").read_bytes(), before)

    def test_hashes_and_verification(self):
        data = b"abc"
        self.write("data", data)
        for algorithm in ("sha256", "sha512"):
            digest = hashlib.new(algorithm, data).hexdigest()
            result = self.run_cli("hash", algorithm, "data")
            self.assertIn(digest, result.stdout.lower())
            self.run_cli("verify", algorithm, "data", digest)
            self.run_cli("verify", algorithm, "data", digest.upper())
            self.run_cli("verify", algorithm, "data", "0" * len(digest), success=False)
        for digest in ("", "g" * 64, "0" * 63, "0" * 65):
            self.run_cli("verify", "sha256", "data", digest, success=False)
        self.run_cli("hash", "md5", "data", success=False)
        self.run_cli("hash", "sha256", "missing", success=False)

    def test_vault_duplicate_retrieve_and_authenticated_delete(self):
        self.write("report.txt", b"vault contents")
        self.run_cli("add", "report.txt", PASSWORD)
        vault_file = self.cwd / ".vault" / "report.txt.enc"
        before = vault_file.read_bytes()
        self.run_cli("add", "report.txt", PASSWORD, success=False)
        self.assertEqual(vault_file.read_bytes(), before)
        self.assertIn("report.txt.enc", self.run_cli("list").stdout)
        self.run_cli("retrieve", "report.txt.enc", "retrieved.txt", PASSWORD)
        self.assertEqual((self.cwd / "retrieved.txt").read_bytes(), b"vault contents")
        self.run_cli("delete", "report.txt.enc", "wrong", success=False)
        self.assertEqual(vault_file.read_bytes(), before)
        damaged = bytearray(before)
        damaged[-1] ^= 1
        vault_file.write_bytes(damaged)
        self.run_cli("delete", "report.txt.enc", PASSWORD, success=False)
        self.assertEqual(vault_file.read_bytes(), damaged)
        vault_file.write_bytes(before)
        self.run_cli("delete", "report.txt.enc", PASSWORD)
        self.assertFalse(vault_file.exists())
        self.assertFalse((self.cwd / "temp_delete_check.tmp").exists())
        self.assertEqual(sorted(p.name for p in self.cwd.iterdir()),
                         [".vault", "report.txt", "retrieved.txt"])

    def test_vault_rejects_traversal_and_non_regular_input(self):
        self.encrypt()
        for name in ("../encrypted.sfm", "..\\encrypted.sfm", ".", "..", "a/b.enc"):
            self.run_cli("retrieve", name, "output", PASSWORD, success=False)
            self.run_cli("delete", name, PASSWORD, success=False)
        self.assertTrue((self.cwd / "encrypted.sfm").exists())
        self.run_cli("encrypt", ".", "directory.sfm", PASSWORD, success=False)
        self.assertFalse((self.cwd / "directory.sfm").exists())

    @unittest.skipIf(os.name == "nt", "POSIX symlink semantics")
    def test_symlink_vault_and_entries_rejected(self):
        self.encrypt()
        (self.cwd / "source-link").symlink_to(self.cwd / "input.bin")
        self.run_cli("encrypt", "source-link", "linked.sfm", PASSWORD, success=False)
        os.mkfifo(self.cwd / "pipe")
        self.run_cli("encrypt", "pipe", "pipe.sfm", PASSWORD, success=False)
        self.assertFalse((self.cwd / "pipe.sfm").exists())
        outside = self.cwd / "outside"
        outside.mkdir()
        (self.cwd / ".vault").symlink_to(outside, target_is_directory=True)
        self.run_cli("add", "input.bin", PASSWORD, success=False)
        (self.cwd / ".vault").unlink()
        (self.cwd / ".vault").mkdir(mode=0o700)
        (self.cwd / ".vault" / "link.enc").symlink_to(self.cwd / "encrypted.sfm")
        self.run_cli("retrieve", "link.enc", "output", PASSWORD, success=False)
        self.run_cli("delete", "link.enc", PASSWORD, success=False)
        self.assertTrue((self.cwd / "encrypted.sfm").exists())

    @unittest.skipIf(os.name == "nt", "Windows files inherit directory ACLs")
    def test_private_permissions(self):
        self.encrypt()
        self.assertEqual((self.cwd / "encrypted.sfm").stat().st_mode & 0o077, 0)
        self.run_cli("add", "input.bin", PASSWORD)
        self.assertEqual((self.cwd / ".vault").stat().st_mode & 0o077, 0)
        self.assertEqual((self.cwd / ".vault" / "input.bin.enc").stat().st_mode & 0o077, 0)

    def test_legacy_cbc_read_compatibility(self):
        fixture = ROOT / "tests" / "fixtures" / "legacy-cbc.enc"
        self.run_cli("decrypt", fixture, "rejected.txt", "legacy-password", success=False)
        self.assertFalse((self.cwd / "rejected.txt").exists())
        self.run_cli("decrypt-legacy", fixture, "legacy.txt", "legacy-password")
        self.assertEqual((self.cwd / "legacy.txt").read_bytes(), b"Legacy vault compatibility\n")

    def test_damaged_magic_never_downgrades_to_legacy(self):
        # This payload produces a size compatible with CBC; detection cannot rely
        # on padding alignment to reject a damaged modern-format header.
        encrypted = self.encrypt(b"twelve bytes")
        damaged = bytearray(encrypted.read_bytes())
        damaged[:8] = b"\x00" * 8
        encrypted.write_bytes(damaged)
        self.run_cli("decrypt", "encrypted.sfm", "output", PASSWORD, success=False)
        self.assertFalse((self.cwd / "output").exists())

    def test_password_from_stdin_and_usage(self):
        self.write("input", b"stdin password")
        self.run_cli("encrypt", "input", "encrypted", "-", stdin=PASSWORD + "\n")
        self.run_cli("decrypt", "encrypted", "restored", "-", stdin=PASSWORD + "\n")
        self.assertEqual((self.cwd / "restored").read_bytes(), b"stdin password")
        self.run_cli("encrypt", "input", "empty-password", "", success=False)
        self.run_cli("--help")
        self.run_cli("--version")
        self.run_cli("unknown-command", success=False)
        self.run_cli("encrypt", success=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
