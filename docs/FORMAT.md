# Encrypted file format

New encrypted files use the format below. All offsets and lengths are in bytes. Multi-byte integers are unsigned, big endian. The implementation is in `src/crypto.c`; the format does not depend on GTK.

| Offset | Length | Meaning |
| --- | --- | --- |
| 0 | 8 | Magic: ASCII `SFMENC` followed by CR LF |
| 8 | 1 | Version: `1` |
| 9 | 1 | Cipher: `1`, AES-256-GCM |
| 10 | 2 | Reserved: zero |
| 12 | 4 | PBKDF2-HMAC-SHA256 iterations: `600000` |
| 16 | 16 | Random salt |
| 32 | 12 | Random GCM nonce |
| 44 | N | Ciphertext, the same length as the plaintext |
| 44 + N | 16 | GCM authentication tag |

PBKDF2 derives a 32-byte key directly from the supplied password and salt. OpenSSL supplies random bytes and implements the EVP cryptographic primitives. Every encryption generates a new independent salt and nonce. All 44 header bytes are GCM additional authenticated data. The smallest valid encrypted file is 60 bytes, representing an empty plaintext.

Version 1 accepts exactly the parameters listed above. Unknown versions, cipher IDs, reserved values, or iteration counts are rejected before derivation. This prevents a malformed input from choosing unbounded derivation work. Version or parameter changes require an explicit format update.

Encryption and decryption stream 64 KiB chunks through EVP. Per-file plaintext is limited to `2^36 - 32` bytes, the AES-GCM bound for one key/nonce pair. The nonce is never reused deliberately; random salt also changes the derived key for each encryption.

## Output publication

The destination must not exist. A temporary file is created exclusively in the destination directory with mode `0600` on POSIX systems. Every read, write, flush, close, and cryptographic operation is checked. Only after successful finalization is it published using an atomic no-replace operation: a hard link on POSIX, or a move without replacement on native Windows. Failure removes the unpublished temporary file. Input and existing output files remain intact.

Decryption does write unverified plaintext to the private temporary file while streaming. It never publishes that file as the requested output until tag verification succeeds. A process crash may leave temporary material, and file deletion does not guarantee physical erasure. POSIX containing directories must be private if their contents are sensitive. Native Windows uses inherited directory ACLs.

`verify_encrypted_file()` uses the same decryption path with a discard sink. Password verification before vault removal does not write plaintext to disk. Password/key buffers owned by the backend and GUI worker are cleared after use; this does not promise removal of every operating-system or library copy.

## Original CBC format

Original encrypted files contain an 8-byte random salt followed by AES-256-CBC ciphertext with PKCS#7 padding. PBKDF2-HMAC-SHA256 at 10,000 iterations derives 48 bytes: 32 bytes for the key and 16 for the IV. There is no magic marker, version, or message authentication tag.

Default decryption and verification require exact modern magic and never fall back to CBC. This prevents damaged authenticated files from being interpreted as unauthenticated legacy input. CBC recovery requires `decrypt_legacy_file()` / `verify_legacy_encrypted_file()`, explicit CLI legacy commands, or GUI consent. The opt-in APIs still authenticate modern inputs if their magic matches. Near-matching magic and impossible legacy lengths are rejected.

Because legacy files have no marker or authenticator, even explicit recovery cannot provide an integrity guarantee. A padding check can accept an incorrect password by chance and cannot detect every ciphertext modification. The interface labels files without modern magic as legacy or unknown; the displayed format is detection only, not a password-verified integrity result.

To migrate, recover the plaintext to a new path, verify it independently, and encrypt it into a new file with the current implementation. Keep the original until the new copy is confirmed usable.
