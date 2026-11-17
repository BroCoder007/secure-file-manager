"""Compare two benchmark_crypto runners; never writes inside the repository."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import tempfile
import time


def measure(executable, *arguments):
    started = time.perf_counter()
    subprocess.run([str(executable), *map(str, arguments)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=120)
    return time.perf_counter() - started


def file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(65536):
            digest.update(block)
    return digest.digest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("updated", type=Path)
    parser.add_argument("--mib", type=int, default=64)
    parser.add_argument("--trials", type=int, default=3)
    args = parser.parse_args()
    if args.mib < 1 or args.trials < 1:
        parser.error("--mib and --trials must be positive")
    results = {"input_bytes": args.mib * 1024 * 1024, "trials": args.trials,
               "method": "Median subprocess wall time, warm file cache; host-specific."}
    with tempfile.TemporaryDirectory(prefix="sfm-benchmark-") as temporary:
        folder = Path(temporary)
        source, empty = folder / "input", folder / "empty"
        block = bytes(range(256)) * 256
        with source.open("wb") as output:
            for _ in range(args.mib * 16):
                output.write(block)
        empty.write_bytes(b"")
        expected = file_digest(source)
        for name, executable in (("original", args.original), ("updated", args.updated)):
            executable = executable.resolve(strict=True)
            metrics = {}
            measure(executable, "hash", "sha256", source)
            for algorithm in ("sha256", "sha512"):
                times = [measure(executable, "hash", algorithm, source)
                         for _ in range(args.trials)]
                metrics[algorithm] = {"seconds": statistics.median(times), "trials": times}
            times = {"encrypt": [], "decrypt": [], "empty_encrypt": []}
            for _ in range(args.trials):
                encrypted, restored = folder / "encrypted", folder / "restored"
                tiny = folder / "tiny"
                times["encrypt"].append(measure(executable, "encrypt", source, encrypted,
                                                "public-benchmark-password"))
                times["decrypt"].append(measure(executable, "decrypt", encrypted, restored,
                                                "public-benchmark-password"))
                times["empty_encrypt"].append(measure(executable, "encrypt", empty, tiny,
                                                      "public-benchmark-password"))
                assert file_digest(restored) == expected, "Round-trip mismatch"
                encrypted.unlink()
                restored.unlink()
                tiny.unlink()
            metrics.update({operation: {"seconds": statistics.median(values), "trials": values}
                            for operation, values in times.items()})
            results[name] = metrics
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
