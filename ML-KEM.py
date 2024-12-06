import os
from MLKEM_internal import MLKEM_INTERNAL

class MLKEM:
    def __init__(self):
        self.internal = MLKEM_INTERNAL()

    def KeyGen(self):
        d = os.urandom(32)
        z = os.urandom(32)

        if d is None or z is None:
            return None

        ek, dk = self.internal.KeyGen_internal(d, z)
        return ek, dk

    def Encaps(self, ek):
        m = os.urandom(32)

        if m is None:
            return None

        K, c = self.internal.Encaps_internal(ek, m)
        return K, c

    def Decaps(self, dk, c):
        K_prime = self.internal.Decaps_internal(dk, c)
        return K_prime