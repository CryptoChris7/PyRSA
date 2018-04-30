from typing import NamedTuple


class KeyInfo(NamedTuple):
    modulus: int = 0
    public_exponent: int = 0
    private_exponent: int = 0
    p: int = 0
    q: int = 0
