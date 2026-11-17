`legacy-cbc.enc` is a public, deliberately non-secret compatibility fixture for
the original file format: 8 salt bytes followed by AES-256-CBC ciphertext.

Password: `legacy-password`

Plaintext (UTF-8): `Legacy vault compatibility` followed by one LF byte.

Salt (hex): `1234567890abcdef`

The key (32 bytes) and IV (16 bytes) are derived together with PBKDF2-HMAC-SHA256,
10,000 iterations, matching the original implementation. Ciphertext was produced
independently with OpenSSL 3.5 `enc -aes-256-cbc -pbkdf2 -iter 10000 -md sha256
-S 1234567890abcdef -saltlen 8`, then prefixed with the raw salt (no `Salted__`
marker). This fixture must remain readable after format changes.
