import k_pke
import auxiliary_algorithms as aux
import parameter_sets as params

def keygen_internal(d, z):
    ekPKE, dkPKE = k_pke.keygen(d)
    ek = ekPKE
    dk = dkPKE + ek + aux.H(ek) + z
    return ek, dk

def encaps_internal(ek, m):
    K, r = aux.G(m + aux.H(ek))
    c = k_pke.encrypt(ek, m, r)
    return K, c

def decaps_internal(dk, c):
    dkPKE = dk[0:384 * params.k]
    ekPKE = dk[384 * params.k: 768 * params.k + 32]
    h = dk[768 * params.k + 32: 768 * params.k + 64]
    z = dk[768 * params.k + 64: 768 * params.k + 96]
    m_prime = k_pke.decrypt(dkPKE, c)
    K_prime, r_prime = aux.G(m_prime + h)
    K_hat = aux.J(z + c)
    c_prime = k_pke.encrypt(ekPKE, m_prime, r_prime)

    if c != c_prime:
        K_prime = K_hat

    return K_prime