# Validation notes

Local verification on 16 November 2026 used a workspace-local MSYS2 UCRT64 toolchain on Windows. Production dependencies remain C, GTK3, and OpenSSL. No toolchain or generated binaries are committed.

## Build and analysis

- Both CLI and GTK3 targets compiled with GCC 16, C11, `-O2`, `-Wall`, `-Wextra`, and `-Wpedantic`, without warnings.
- GCC `-fanalyzer` compiled the crypto, vault, CLI, and GUI sources without diagnostics.
- Source is formatted consistently using the included `.clang-format`.
- `git diff --check` passed.

## Regression coverage

The native CLI suite executed 13 cases: **11 passed and 2 POSIX-only cases were skipped**. Coverage includes empty/binary/large files and buffer boundaries, independent encryption randomness, incorrect passwords, header/ciphertext/tag damage, truncated files, refusal to overwrite existing destinations, preservation of the input, SHA-256/SHA-512 vectors and comparison, vault duplicates and path confinement, authenticated removal, password input via standard input, explicit legacy recovery, and refusal to downgrade damaged authenticated files to CBC.

The GTK integration harness runs the production main loop and worker jobs with disposable files and settings. **51 assertions passed**, including:

- Empty and populated vault states; disabled actions without a selection.
- Batch import and a main-loop heartbeat while encryption runs in a background worker.
- Case-folded search, including `ß` matching `SS`, and no-results presentation.
- Exported content matching the original bytes.
- An incorrect removal password preserving the vault file, followed by authorized removal.
- SHA-256/SHA-512 comparisons, invalid expected checksums, and clearing stale results after input changes.
- Blank, short, mismatched, and matching password confirmation states, generated 32-character passwords, and cancellation.

The GTK tests passed with `G_DEBUG=fatal-warnings`. The native empty and populated windows were also visually inspected; actual table headings are present. Pure widget-only screenshots can omit native subwindow content, so screenshots are illustrative and test assertions verify the underlying model separately.

```sh
make -j2 check
make gui-test                    # requires a graphical display
xvfb-run -a make gui-test        # headless Linux
make sanitize                   # Linux/compatible sanitizer toolchain
```

The two skipped local cases cover POSIX ownership/modes and real symlink behavior. The included GitHub Actions workflow runs the full CLI suite, GTK startup and workflow tests, and AddressSanitizer/UndefinedBehaviorSanitizer tests on Linux. Check the pull request's CI status for those results; native Windows results do not establish Linux permission or sanitizer correctness. MSYS POSIX emulation with `noacl` mounts was not treated as Linux verification.

## Performance observations

The original `src/crypto.c` from commit `3b4b941dba5d4d6197b638be409f5ea1d409e190` and the updated implementation were compiled with the same GCC `-O2` settings and OpenSSL library, using the same small runner. These are medians of three subprocess wall-clock runs with a warm file cache on this Windows host, **not general performance guarantees**.

| Operation | Original | Updated |
| --- | ---: | ---: |
| SHA-256, 64 MiB | 78.3 ms | 54.1 ms |
| SHA-512, 64 MiB | 121.7 ms | 93.5 ms |
| Encrypt, 64 MiB | 171.7 ms | 151.9 ms |
| Decrypt, 64 MiB | 126.3 ms | 152.5 ms |
| Encrypt, empty file | 19.3 ms | 88.4 ms |

Streaming now uses bounded 64 KiB buffers rather than 1 KiB encryption/decryption and 4 KiB hashing chunks. Hashing was faster in this measurement. Authenticated encryption, stronger PBKDF2 derivation (600,000 versus 10,000 rounds), and checked durable output publication change the cost profile: small files and decryption can take longer. The desktop interface remains responsive because that work runs outside the GTK thread. No blanket speedup is claimed.

Raw measurements are in [benchmark-windows.json](benchmark-windows.json). To reproduce the comparison, compile `tests/benchmark_crypto.c` separately with the original and updated `crypto.c` and matching headers, then run:

```sh
python3 tests/benchmark.py /path/to/original-runner /path/to/updated-runner --mib 64 --trials 3
```

The script uses a disposable temporary directory and verifies every decrypted result against its input. Timing varies with CPU, storage, antivirus, operating-system caches, and OpenSSL hardware acceleration.
