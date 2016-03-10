import gmpy2
import random
from typing import Tuple, List, Any, Iterator, Optional
from .keyinfo import KeyInfo

RANDOM = random.SystemRandom()


def randomOdd(bits: int) -> int:
    """Returns a random odd number in [2**(bits - 1), 2**bits].
    :param bits: number of bits for the odd.
    :type bits: int
    :returns: a random odd of the specified length.
    :rtype: int"""
    return RANDOM.randrange(1 << (bits - 1), (1 << bits) - 1)|1

def find_prime(bits: int) -> int:
    """Returns a prime number in [2**(bits - 1), 2**bits].
    :param bits: number of bits for the prime.
    :type bits: int
    :returns: A prime with the given amount of bits.
    :rtype: int"""
    p = randomOdd(bits)
    while not gmpy2.is_strong_bpsw_prp(p):
        p = randomOdd(bits)
    return p


def is_good_pair(p: int, q: int) -> Optional[Tuple[int, int]]:
    """Returns the encryption modulus and totient for the given primes.
    :param p: One of the two primes to be used for encryption.
    :type p: int
    :param q: The other prime used for encryption.
    :type q: int
    :returns: Either the encryption modulus and the totient, or None.
    :rtype: Optional[Tuple[int, int]]"""
    n = p*q
    k = gmpy2.ceil(gmpy2.log2(n))
    if abs(p - q) > 2**(k/2 - 100):
        return n, n - (p + q - 1)
    return None


def yield_pairs(a_list: List[Any]) -> Iterator[Tuple[Any,Any]]:
    """Yields every pair in the given list.
    :param a_list: a python list.
    :type a_list: List[Any]
    :returns: a generator which yields each pair as a tuple.
    :rtype: Iterator[Tuple[Any,Any]]"""
    for index, item in enumerate(a_list):
        for second_item in a_list[index+1:]:
            yield item, second_item


def get_key_info(bits: int, e: int = 3) -> KeyInfo:
    """Finds parameters appropriate for RSA encryption.
    :param bits: the number of bits in the encryption modulus.
    :type bits: int
    :param e: the public exponent, used for encrypting. Smaller is better (with padding!)
    :type e: int
    :return: all the RSA parameters for the public and private keys.
    :rtype: KeyInfo"""
    primes = [find_prime(bits), find_prime(bits)]
    bad_pairs = set()
    while True:
        for pair in yield_pairs(primes):
            if pair not in bad_pairs:
                p, q = pair
                if p < q:
                    p, q = q, p

                result = is_good_pair(p, q)
                if result is not None:
                    n, tot = result
                    if gmpy2.gcd(e, tot) == 1:
                        d = gmpy2.invert(e, tot)
                        return KeyInfo(n, e, d, p, q)

                bad_pairs.add(pair)
        primes.append(find_prime(bits))
