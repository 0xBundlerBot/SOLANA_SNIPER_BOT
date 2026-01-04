import re
import base58
from solders.keypair import Keypair
 

def _keypair_from_raw_bytes(raw: bytes) -> Keypair:
    """
    solders Keypair constructors typically accept:
    - 64 bytes: secret key (private + public) -> Keypair.from_bytes
    - 32 bytes: seed -> Keypair.from_seed
    """
    if len(raw) == 64:
        return Keypair.from_bytes(raw)
    if len(raw) == 32:
        return Keypair.from_seed(raw)
    raise ValueError(f"Invalid key length: {len(raw)} bytes (expected 32 or 64)")


def get_wallet_from_private_key_bs58(private_key_bs58: str) -> Keypair:
    raw = base58.b58decode(private_key_bs58.strip())
    return _keypair_from_raw_bytes(raw)


def get_wallet_from_private_key_numbers_csv(numbers_csv: str) -> Keypair:
    # Accept: "1,2,3" or with spaces/newlines
    parts = [p.strip() for p in numbers_csv.strip().split(",") if p.strip() != ""]
    if not parts:
        raise ValueError("Empty CSV")

    try:
        nums = [int(x) for x in parts]
    except ValueError:
        raise ValueError("CSV contains non-integer values")

    if any(n < 0 or n > 255 for n in nums):
        raise ValueError("CSV integers must be in [0,255]")

    raw = bytes(nums)
    return _keypair_from_raw_bytes(raw)


def get_wallet_from_private_key(private_key_input: str) -> Keypair:
    """
    Auto-detect:
    - If input looks like CSV numbers => parse as bytes
    - Else treat as base58
    """
    s = private_key_input.strip()

    # Heuristic: contains comma and only digits/commas/spaces/newlines
    if "," in s and re.fullmatch(r"[0-9,\s]+", s) is not None:
        return get_wallet_from_private_key_numbers_csv(s)

    # Otherwise assume base58
    return get_wallet_from_private_key_bs58(s)
