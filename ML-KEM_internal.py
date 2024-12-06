import hashlib
from K_PKE import KPKE

class MLKEM_INTERNAL:
    def __init__(self, kpke: KPKE):
        self.kpke = kpke 
    
    def KeyGen_internal(self, d, z):
        ekPKE, dkPKE = self.kpke.keygen(d)
        ek = ekPKE
        dk = dkPKE + ek + hashlib.sha3_256(ek).digest() + z
        return ek, dk

    def Encaps_internal(self, ek, m):
        K, r = G(m + hashlib.sha3_256(ek).digest())
        c = self.kpke.encrypt(ek, m, r)
        return K, c

    def Decaps_internal(self, dk, c):
        dkPKE = dk[:384 * self.kpke.k]
        ekPKE = dk[384 * self.kpke.k:768 * self.kpke.k + 32]
        h = dk[768 * self.kpke.k + 32:768 * self.kpke.k + 64]
        z = dk[768 * self.kpke.k + 64:768 * self.kpke.k + 96]

        m_prime = self.kpke.decrypt(dkPKE, c)
        K_prime, r_prime = G(m_prime + h)
        K = hashlib.sha3_256(z + c).digest()

        c_prime = self.kpke.encrypt(ekPKE, m_prime, r_prime)

        if c != c_prime:
            K_prime = K

        return K_prime