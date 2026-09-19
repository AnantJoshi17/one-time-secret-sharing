"""
Encrypting the secret payloads with Fernet.

Fernet (from the `cryptography` library) is symmetric authenticated
encryption: the same key both encrypts and decrypts, and the ciphertext is
signed so it cannot be tampered with undetected. It is a good default because
it gives you no knobs to get wrong -- no choosing a cipher, no choosing an IV.

WHY ENCRYPT AT ALL, when we already delete the secret after one read?

Because the two protect against different things. Single-read protects the
secret from whoever gets the *link*. Encryption protects it from whoever gets
the *database* -- a leaked backup, a misconfigured managed instance, a
support engineer with read access to a table. With this, the database rows
are useless without SECRET_ENCRYPTION_KEY, which lives only in the
environment and is never written to disk by the application.

The honest limitation: the running app has to hold the key in memory to do
its job, so this is not end-to-end encryption. A full compromise of the
server still exposes secrets in flight. Real end-to-end would encrypt in the
browser and put the key in the URL fragment, where it never reaches us.
That is noted as future work in the README.
"""

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


class EncryptionKeyMissingError(RuntimeError):
    """Raised at startup when SECRET_ENCRYPTION_KEY is absent or malformed."""


def _build_cipher() -> Fernet:
    """
    Construct the Fernet object from the configured key.

    Fernet is strict about its key: exactly 32 random bytes, url-safe base64
    encoded. Generate one with:
        python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    """
    key = settings.secret_encryption_key.strip()
    if not key:
        raise EncryptionKeyMissingError(
            "SECRET_ENCRYPTION_KEY is not set. Generate one with:\n"
            '  python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"'
        )

    try:
        return Fernet(key.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise EncryptionKeyMissingError(
            "SECRET_ENCRYPTION_KEY is not a valid Fernet key. It must be 32 "
            "random bytes, url-safe base64 encoded (44 characters)."
        ) from exc


# Built once at import time. Fernet objects are cheap to reuse and safe to
# share between threads, so there is no reason to rebuild one per request.
_cipher: Fernet | None = None


def get_cipher() -> Fernet:
    """Return the shared Fernet instance, building it on first use."""
    global _cipher
    if _cipher is None:
        _cipher = _build_cipher()
    return _cipher


def reset_cipher() -> None:
    """Forget the cached cipher. Only used by tests that swap the key."""
    global _cipher
    _cipher = None


def encrypt(plaintext: str) -> str:
    """Encrypt a string. The result is url-safe ASCII, so it stores fine in a TEXT column."""
    token = get_cipher().encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


class DecryptionError(RuntimeError):
    """Raised when stored ciphertext cannot be decrypted."""


def decrypt(ciphertext: str) -> str:
    """
    Decrypt a string produced by encrypt().

    InvalidToken means one of: the key changed since this row was written,
    the row was corrupted, or somebody edited the ciphertext. All three are
    unrecoverable, so we convert it into a clear error instead of returning
    nonsense to the user.
    """
    try:
        plaintext = get_cipher().decrypt(ciphertext.encode("utf-8"))
    except InvalidToken as exc:
        raise DecryptionError(
            "Stored secret could not be decrypted. The encryption key has "
            "probably changed since this secret was created."
        ) from exc
    return plaintext.decode("utf-8")
