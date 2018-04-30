from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ, namedtype
from base64 import b64encode, b64decode
from gmpy2 import invert
from .keyinfo import KeyInfo
from typing import Union

PRIVATE = b'''\
-----BEGIN RSA PRIVATE KEY-----
%b
-----END RSA PRIVATE KEY-----
'''

PUBLIC = b'''\
-----BEGIN RSA PUBLIC KEY-----
%b
-----END RSA PUBLIC KEY-----
'''


# https://tools.ietf.org/html/rfc3447#appendix-A.1
class PublicKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('publicExponent', univ.Integer()))


class PrivateKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('publicExponent', univ.Integer()),
        namedtype.NamedType('privateExponent', univ.Integer()),
        namedtype.NamedType('prime1', univ.Integer()),
        namedtype.NamedType('prime2', univ.Integer()),
        namedtype.NamedType('exponent1', univ.Integer()),
        namedtype.NamedType('exponent2', univ.Integer()),
        namedtype.NamedType('coefficient', univ.Integer())
        )


def format_key(key: Union[PublicKey, PrivateKey]) -> bytes:
    data_lines = []
    b64_data = b64encode(encoder.encode(key))
    start, stop = 0, 64

    while start < len(b64_data):
        data_lines.append(b64_data[start:stop])
        start, stop = start + 64, stop + 64

    if isinstance(key, PublicKey):
        return PUBLIC % b'\n'.join(data_lines)
    else:
        return PRIVATE % b'\n'.join(data_lines)


def encode_public_key(key_info: KeyInfo) -> bytes:
    key = PublicKey()
    key.setComponentByName('modulus', key_info.modulus)
    key.setComponentByName('publicExponent', key_info.public_exponent)
    return format_key(key)


def encode_private_key(key_info: KeyInfo) -> bytes:
    key = PrivateKey()
    key.setComponentByName('version', 0)
    key.setComponentByName('modulus', key_info.modulus)
    key.setComponentByName('publicExponent', key_info.public_exponent)
    key.setComponentByName('privateExponent', key_info.private_exponent)
    key.setComponentByName('prime1', key_info.p)
    key.setComponentByName('prime2', key_info.q)
    key.setComponentByName('exponent1', key_info.private_exponent % (key_info.p - 1))
    key.setComponentByName('exponent2', key_info.private_exponent % (key_info.q - 1))
    key.setComponentByName('coefficient', invert(key_info.q, key_info.p))
    return format_key(key)


def decode_public_key(encoded_key: bytes) -> KeyInfo:
    b64_data = b''.join(encoded_key.split(b'\n')[1:-2])
    key_data = b64decode(b64_data)
    parsed_key = decoder.decode(key_data, asn1Spec=PublicKey())[0]
    modulus = parsed_key.getComponentByName('modulus')
    public_exponent = parsed_key.getComponentByName('publicExponent')
    return KeyInfo(modulus,
                   public_exponent,
                   0, 0, 0)


def decode_private_key(encoded_key: bytes) -> KeyInfo:
    b64_data = b''.join(encoded_key.split(b'\n')[1:-2])
    key_data = b64decode(b64_data)
    parsed_key = decoder.decode(key_data, asn1Spec=PublicKey())[0]
    modulus = parsed_key.getComponentByName('modulus')
    public_exponent = parsed_key.getComponentByName('publicExponent')
    private_exponent = parsed_key.getComponentByName('privateExponent')
    p = parsed_key.getComponentByName('prime1')
    q = parsed_key.getComponentByName('prime2')
    return KeyInfo(modulus,
                   public_exponent,
                   private_exponent,
                   p, q)
