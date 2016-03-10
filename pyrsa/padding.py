import os
import math
import struct
import hashlib
import operator as op
from typing import Union

Bytey = Union[bytes,bytearray]

def mask_generating_function(seed: Bytey,
                             byte_length: int,
                             hash: str) -> bytearray:
    """Generates a mask that expands `seed` to be of length `byte_length`.
    :param seed: Initial value before hash loop.
    :type seed: Bytey
    :param byte_length: The required length in bytes of the mask.
    :type byte_length: int
    :param hash: The string for a hashlib algorithm.
    :type hash: str
    :returns: The generated mask.
    :rtype: bytearray
    """
    hasher = hashlib.new(hash)
    result = bytearray()
    for i in range(math.ceil(byte_length/hasher.digest_size)):
        h = hasher(seed)
        h.update(struct.pack('!I', i))
        result.extend(h.digest())

    return result[:byte_length]


def xor(b1: Bytey, b2: Bytey) -> bytearray:
    """XOR the contents of two bytes/bytearray objects.
    :param b1: One of two sequences of bytes to xor.
    :type b1: Bytey
    :param b2: One of two sequences of bytes to xor.
    :type b2: Bytey
    :returns: The sequence of bytes that is the xor of b1 and b2.
    :rtype: bytearray"""
    return bytearray(map(op.xor, b1, b2))

def pad(chunk: Bytey,
        nBytes: int,
        k0Bytes: int,
        k1Bytes: int,
        gHash: str,
        hHash: str) -> bytearray:
    """Adds OAEP padding to a message chunk.
    See the Wikipedia page on OAEP_.
    :param chunk: A chunk of data to prepare for encryption.
    :type chunk: Bytey
    :param nBytes: The number of bytes in the encryption modulus.
    :type nBytes: int
    :param k0Bytes: Length of the random seed to use for padding.
    :type k0Bytes: int
    :param k1Bytes: Length of zeros to add to `chunk`.
    :type k1Bytes: int
    :returns: The padded `chunk`.
    :rtype: bytearray

    .. _OAEP: https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
    """
    zero_padded = bytearray(chunk)
    zero_padded.extend(bytes(k1Bytes))
    random_chunk = os.urandom(k0Bytes)
    gMask = mask_generating_function(random_chunk, nBytes - k0Bytes, gHash)
    result = xor(zero_padded, gMask)
    hMask = mask_generating_function(result, k0Bytes, hHash)
    result.extend(xor(hMask, random_chunk))
    return result

def unpad(padded_chunk: Bytey,
          nBytes: int,
          k0Bytes: int,
          k1Bytes: int,
          gHash: str,
          hHash: str,
          ) -> bytearray:
    """
    Unpads a message that was padded with OAEP.
    See the Wikipedia page on OAEP_.
    :param padded_chunk:
    :type padded_chunk: Bytey
    :param nBytes:
    :type nBytes: int
    :param k0Bytes:
    :type k0Bytes: int
    :param k1Bytes:
    :type k1Bytes: int
    :param gHash:
    :type gHash: str
    :param hHash:
    :type hHash: str
    :return:
    :rtype: bytearray

    .. _OAEP: https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
    """
    y_chunk = padded_chunk[-k0Bytes:]
    hMask = mask_generating_function(padded_chunk[:k0Bytes], k0Bytes, hHash)
    random_chunk = xor(y_chunk, hMask)

    x_chunk = padded_chunk[:-k0Bytes]
    gMask = mask_generating_function(random_chunk, nBytes - k0Bytes, gHash)
    zero_padded = xor(x_chunk, gMask)
    return zero_padded[:-(k0Bytes + k1Bytes)]
