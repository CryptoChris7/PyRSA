from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ, namedtype
from base64 import b64encode, b64decode
import gmpy2
from .keyinfo import KeyInfo

FIRST_LINE_PRIVATE = '-----BEGIN RSA PRIVATE KEY-----'
LAST_LINE_PRIVATE = '-----END RSA PRIVATE KEY-----'

FIRST_LINE_PUBLIC = '-----BEGIN RSA PUBLIC KEY-----'
LAST_LINE_PUBLIC = '-----END RSA PUBLIC KEY-----'

#https://tools.ietf.org/html/rfc3447#appendix-A.1
class RSAPublicKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('publicExponent', univ.Integer())
        )

class RSAPrivateKey(univ.Sequence):
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

def format_key(encoded: str, priv: bool) -> str:
    if priv:
        first_line = FIRST_LINE_PRIVATE
        last_line = LAST_LINE_PRIVATE
    else:
        first_line = FIRST_LINE_PUBLIC
        last_line = LAST_LINE_PUBLIC

    formatted = [first_line]
    b64_data = b64encode(encoded)
    view = memoryview(b64_data)
    while view:
        chunk, view = view[:64].tobytes(), view[64:]
        formatted.append(chunk)
    formatted.append(last_line)
    return '\n'.join(formatted)

def encode_public_key(key_info: KeyInfo) -> str:
    public_key = RSAPublicKey()
    public_key.setComponentByName('modulus', key_info.n)
    public_key.setComponentByName('publicExponent', key_info.e)
    return format_key(encoder.encode(public_key), False)

def encode_private_key(key_info: KeyInfo) -> str:
    private_key = RSAPrivateKey()
    private_key.setComponentByName('version', 0)
    private_key.setComponentByName('modulus', key_info.n)
    private_key.setComponentByName('publicExponent', key_info.e)
    private_key.setComponentByName('privateExponent', key_info.d)
    private_key.setComponentByName('prime1', key_info.p)
    private_key.setComponentByName('prime2', key_info.q)
    private_key.setComponentByName('exponent1', key_info.d % (key_info.p - 1))
    private_key.setComponentByName('exponent2', key_info.d % (key_info.q - 1))
    private_key.setComponentByName('coefficient', gmpy2.invert(key_info.q, key_info.p))
    return format_key(encoder.encode(private_key), True)

def decode_key(encoded_key: str) -> KeyInfo:
    n, e, d, p, q = None, None, None, None, None
    b64_data = ''.join(key.split('\n')[1:-1])
    key_data = b64decode(b64_data)

    private = 'PRIVATE' in key

    if private:
        spec = RSAPrivateKey
    else:
        spec = RSAPublicKey

    parsed_key = decoder.decode(key_data, asn1Spec=spec())[0]

    n = parsed_key.getComponentByName('modulus')
    e = parsed_key.getComponentByName('publicExponent')

    if private:
        d = parsed_key.getComponentByName('privateExponent')
        p = parsed_key.getComponentByName('prime1')
        q = parsed_key.getComponentByName('prime2')

    return KeyInfo(n, e, d, p, q)

if __name__ == '__main__':
    from . import primes
    key_info = primes.get_key_info()
    print(encode_private_key(key_info))
    print(encode_public_key(key_info))
    print(decode_key(encode_private_key(key_info)))
