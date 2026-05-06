"""
token_utils.py
AES-128-CMAC verification for NTAG 424 DNA SDM.
Implements NXP application note AN12196.

How it works:
  - The chip computes: CMAC(AES_key, uid_bytes + ctr_bytes_little_endian)
  - It truncates the result to 8 bytes (16 hex chars)
  - This server recomputes the same operation and compares
  - If they match, the tap is cryptographically genuine
"""

import os
import binascii
from Crypto.Hash import CMAC
from Crypto.Cipher import AES


def _get_aes_key() -> bytes:
    """
    Read SDM_AES_KEY from environment.
    Must be exactly 32 hex characters (16 bytes = 128-bit AES key).
    """
    key_hex = os.environ.get("SDM_AES_KEY", "")
    if not key_hex:
        raise ValueError("SDM_AES_KEY is not set in your .env file")
    if len(key_hex) != 32:
        raise ValueError(
            f"SDM_AES_KEY must be exactly 32 hex characters (16 bytes). "
            f"Got {len(key_hex)} characters."
        )
    return binascii.unhexlify(key_hex)


def verify_sdm_cmac(uid: str, ctr: str, cmac: str) -> bool:
    """
    Verify the AES-128-CMAC from an NTAG 424 DNA tap.

    Args:
        uid:  Chip hardware UID as hex string   e.g. "04A1B2C3D4E5F6"  (14 hex chars = 7 bytes)
        ctr:  Scan counter as hex string        e.g. "0000AB"           (6 hex chars  = 3 bytes)
        cmac: Truncated CMAC as hex string      e.g. "1F3C9A2E4B7D0E51" (16 hex chars = 8 bytes)

    Returns:
        True  — tap is genuine, CMAC matches
        False — tap is invalid, forged, or AES key is wrong
    """
    try:
        key = _get_aes_key()

        # Decode UID (7 bytes, big-endian — just raw bytes)
        uid_bytes = binascii.unhexlify(uid)

        # Decode counter (3 bytes, little-endian as per NXP AN12196)
        ctr_int = int(ctr, 16)
        ctr_bytes = ctr_int.to_bytes(3, byteorder="little")

        # Build the message the chip signed: uid || counter
        message = uid_bytes + ctr_bytes

        # Compute AES-128-CMAC
        cobj = CMAC.new(key, ciphermod=AES)
        cobj.update(message)
        full_cmac_hex = cobj.hexdigest()  # 32 hex chars = 16 bytes

        # Chip truncates to first 8 bytes (16 hex chars)
        server_cmac = full_cmac_hex[:16].upper()
        chip_cmac   = cmac.upper()

        return server_cmac == chip_cmac

    except (ValueError, KeyError, binascii.Error):
        # Any decode error means the input is malformed — reject
        return False
