

class KeyInfo:
    __slots__ = ()
    modulus = 0  # type: int
    public_exponent = 0  # type: int
    private_exponent = 0  # type: int
    p = 0  # type: int
    q = 0  # type: int

    def __init__(self,
                 modulus: int,
                 public_exponent: int,
                 private_exponent: int,
                 p: int,
                 q: int):
        for key, val in locals().items():
            if key != 'self':
                setattr(self, key, val)
