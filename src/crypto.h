#ifndef SFM_CRYPTO_H
#define SFM_CRYPTO_H

/* All operations return 1 on success and 0 on failure. Errors are local to the
 * calling thread until its next crypto operation. Input must be a regular,
 * non-symlink file. Outputs are private, published atomically only on success,
 * and NEVER replace an existing path. */
const char *crypto_last_error(void);

/* Versioned AES-256-GCM, PBKDF2-HMAC-SHA256 (600,000 rounds), random 128-bit salt,
 * 96-bit nonce, 128-bit authentication tag. */
int encrypt_file(const char *input_file, const char *output_file, const char *password);

/* Authenticated modern format only. Unknown headers never fall back to CBC. */
int decrypt_file(const char *input_file, const char *output_file, const char *password);

/* Decrypt and discard plaintext in bounded memory, without plaintext disk IO.
 * Only authenticated modern files are accepted. */
int verify_encrypted_file(const char *input_file, const char *password);

/* Explicit recovery/verification of the original salt + AES-256-CBC format
 * (10,000 PBKDF2 rounds). Successful padding cannot prove password or integrity.
 * Re-encrypt recovered content to obtain authenticated storage. These opt-in
 * functions also accept modern files, with full GCM authentication. */
int decrypt_legacy_file(const char *input_file, const char *output_file, const char *password);
int verify_legacy_encrypted_file(const char *input_file, const char *password);

/* algorithm is "sha256" or "sha512"; hash_output must hold at least 64 bytes. */
int hash_file(const char *algorithm, const char *input_file, unsigned char *hash_output,
              unsigned int *hash_len);

#endif
