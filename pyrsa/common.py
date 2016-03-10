'''This module defines misc. objects and constants used throughout.'''

from collections import namedtuple
from random import SystemRandom
import os
import hashlib

__all__ = ['KeyInfo', 'Defaults', 'Random', 'Hash', 'HASH_BITLEN']

DefaultConstants = (
    'publicExponent',
    'keyBits',
    'modulusBits',
    'modulusBytes',
    'k0',
    'k1',
    'k0Bytes',
    'k1Bytes',
    'chunkLen',
)
Defaults = namedtuple('Defaults', DefaultConstants)(
    3,
    4096,
    8192,
    1024,
    32,
    32,
    4,
    4,
    1016,
)
Random = SystemRandom()
Random.urandom = os.urandom

