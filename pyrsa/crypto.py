from .keyinfo import KeyInfo
import hashlib
import os

HASH = hashlib.sha256
HASHLEN = 32


def mask_generating_function(seed: bytes, length: int) -> bytes:
    iterations = length//HASHLEN
    result = bytearray()
    for i in list(range(iterations)):
        result.extend(HASH(seed + i.to_bytes(4, 'big', signed=False)).digest())
    return bytes(result[:length])


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(a_i ^ b_i for a_i, b_i in zip(a, b))


def encrypt(public_key: KeyInfo,
            message: bytes,
            label: bytes=b'') -> bytes:
    """Encrypts a message using RSA-OAEP."""
    modulus_length = public_key.modulus.bit_length()//8
    message_length = len(message)

    if message_length > modulus_length - 2*HASHLEN - 2:
        raise ValueError('message too long')

    zero_pad = bytes(modulus_length - message_length - 2*HASHLEN - 2)
    data_block = HASH(label).digest() + zero_pad + b'\x01' + message
    seed = os.urandom(HASHLEN)
    data_mask = mask_generating_function(seed, modulus_length - HASHLEN - 1)
    masked_data = xor(data_block, data_mask)
    seed_mask = mask_generating_function(masked_data, HASHLEN)
    masked_seed = xor(seed, seed_mask)
    encoded_message = b'\x00' + masked_seed + masked_data

    m = int.from_bytes(encoded_message, 'big')
    c = pow(m, public_key.public_exponent, public_key.modulus)
    return c.to_bytes(modulus_length, 'big', signed=False)


def decrypt(private_key: KeyInfo,
            ciphertext: bytes,
            label: bytes=b'') -> bytes:
    """Decrypts a message using RSA-OAEP."""
    modulus_length = private_key.modulus.bit_length()//8
    if len(ciphertext) != modulus_length:
        raise ValueError('decryption failed')

    if modulus_length < 2*HASHLEN - 2:
        raise ValueError('decryption failed')

    c = int.from_bytes(ciphertext, 'big', signed=False)
    m = pow(c, private_key.private_exponent, private_key.modulus)

    encoded_message = m.to_bytes(modulus_length, 'big', signed=False)
    label_hash = HASH(label).digest()
    y = encoded_message[:1]

    if y != b'\x00':
        raise ValueError('decryption failed')

    masked_seed = encoded_message[1:1+HASHLEN]
    masked_data = encoded_message[1+HASHLEN:]
    seed_mask = mask_generating_function(masked_data, HASHLEN)
    seed = xor(masked_seed, seed_mask)
    data_mask = mask_generating_function(seed, modulus_length - HASHLEN - 1)
    data_block = xor(masked_data, data_mask)

    if not data_block.startswith(label_hash):
        raise ValueError('decryption failed')

    data_block = data_block[HASHLEN:].lstrip(b'\x00')

    if not data_block.startswith(b'\x01'):
        raise ValueError('decryption failed')

    return data_block[1:]
