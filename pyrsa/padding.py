import hashlib
import struct
import common
import operator as op

def mask_generating_function(seed, bits):
    '''Generates a mask that expands "seed" to be of length "bits."
    
    Only works when "bits" is a multiple of 8.
    '''
    result = bytearray()
    for i in range(bits/common.HASH_BITLEN):
        h = common.HASH(seed)
        h.update(struct.pack('!I', i))
        result.extend(h.digest())

    return result[:bits/8]

def xor(b1, b2):
    '''XOR the contents of two bytes/bytearray objects.'''
    return bytes(map(op.xor, b1, b2))

def pad(chunk, n, k0, k1):
    '''Adds OAEP padding to a message chunk.

    Only works when the length of "chunk" equals

    (DEFAULT_MODULUS_SIZE - DEFAULT_K0 - DEFAULT_K1)/8

    No runtime check of this constraint is done here.
    Also assumes that chunk is a bytes or bytearray type.
    '''
    # Assuming len(chunk) = n - k0 - k1
    chunk.extend(bytearray(common.DEFAULT_K1_BYTES))
    r = RANDOM.urandom(common.DEFAULT_K0_BYTES)
    mask1 = mask_generating_function(r, common.DEFAULT_