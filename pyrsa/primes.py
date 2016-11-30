import gmpy2
import os
import random
from typing import Tuple, Optional
from .keyinfo import KeyInfo

# M is the product of all odd primes which fits in 32 bits.
# It's used as a quick check for finding primes.
M = 3*5*7*11*13*17*19*23*29
# Use SystemRandom for finding bases for Miller-Rabin.
# random.SystemRandom uses os.urandom.
_sys_rand = random.SystemRandom()


def random_odd(bits: int) -> int:
    """Returns a random odd number with the specified amount of bits."""
    assert (bits % 8) == 0
    mask = 1 << (bits - 1) | 1
    return int.from_bytes(os.urandom(bits//8), 'big') | mask


def miller_rabin(n: int, iterations: int) -> bool:
    """Does Miller-Rabin checks on n with random bases."""
    for i in range(iterations):
        base = _sys_rand.randrange(n)
        # gmpy2.is_strong_prp is the Miller-Rabin test
        if not gmpy2.is_strong_prp(n, base):
            return False
    return True


def find_prime(bits: int) -> int:
    """Returns a prime number with the specified amount of bits."""
    p = random_odd(bits)
    while True:
        # if p is not coprime with M then it isn't prime.
        if gmpy2.gcd(p, M) != 1:
            p += 2
            continue
        if miller_rabin(p, 10):
            return p
        else:
            p += 2


def check_pair(p: int, q: int) -> Tuple[int, int]:
    """Returns the encryption modulus and totient for the given primes."""
    n = p*q
    k = gmpy2.ceil(gmpy2.log2(n))
    if abs(p - q) > 2**(k/2 - 100):
        return n, n - (p + q - 1)
    return 0, 0


def generate_key(bits: int) -> KeyInfo:
    """Finds parameters appropriate for RSA encryption."""
    public_exponent = 3
    # Note: if you don't use proper padding then 3 is way too small.
    # Even with random padding, 3 is too small. You have to use OAEP!
    primes = []
    while True:
        q = find_prime(bits/2)
        for p in primes:
            modulus, totient = check_pair(p, q)
            if modulus == 0:
                continue
            if gmpy2.gcd(public_exponent, totient) != 1:
                continue
            private_exponent = gmpy2.invert(public_exponent, totient)
            return KeyInfo(modulus,
                           public_exponent,
                           private_exponent,
                           p, q)
        primes.append(q)
