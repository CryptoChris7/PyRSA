from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ, namedtype
from base64 import b64encode, b64decode
import gmpy2

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

def format_key(encoded, priv):
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

def encode_public_key(key):
    public_key = RSAPublicKey()
    public_key.setComponentByName('modulus', key.n)
    public_key.setComponentByName('publicExponent', key.e)
    return format_key(encoder.encode(public_key), False)

def encode_private_key(key_info):
    private_key = RSAPrivateKey()
    private_key.setComponentByName('version', 0)
    private_key.setComponentByName('modulus', key.n)
    private_key.setComponentByName('publicExponent', key.e)
    private_key.setComponentByName('privateExponent', key.d)
    private_key.setComponentByName('prime1', key.p)
    private_key.setComponentByName('prime2', key.q)
    private_key.setComponentByName('exponent1', key.d % (key.p - 1))
    private_key.setComponentByName('exponent2', key.d % (key.q - 1))
    private_key.setComponentByName('coefficient', gmpy2.invert(key.q, key.p))
    return format_key(encoder.encode(private_key), True)

def decode_key(key):
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
        return PrivateKey(*asn1_Ints_to_mpzs(n, e, d, p, q))
    else:
        return PublicKey(*asn1_Ints_to_mpzs(n, e))

if __name__ == '__main__':
    import primes
    priv, pub = primes.get_keys()
    print encode_private_key(priv)
    print encode_public_key(pub)
    x = decode_key(encode_private_key(priv))
    print x
