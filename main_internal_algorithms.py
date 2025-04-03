import parameter_sets as params
import auxiliary_algorithms as aux
import k_pke

def keygen_internal(d, z):
    """
    This is algorithm 16 from the FIPS 203 document.
    
    Uses randomness to generate an encapsulation key and a corresponding decapsulation key.
    
    Input:
    - randomness d ∈ B^32.
    - randomness z ∈ B^32.
    
    Output:
    - encapsulation key ek ∈ B^(384k + 32).
    - decapsulation key dk ∈ B^(768 + 96).
    """
    
    ekPKE, dkPKE = k_pke.keygen(d) # run key generation for K-PKE
    ek = ekPKE # KEM encaps key is just the PKE encryption key
    dk = dkPKE + ek + aux.H(ek) + z # KEM decaps key includes PKE decryption key
    return ek, dk

def encaps_internal(ek, m):
    """
    This is algorithm 17 from the FIPS 203 document.
    
    Uses the encapsulation key and randomness to generate a key and an associated ciphertext.
    
    Input:
    - encapsulation key ek ∈ B^(384k + 32).
    - randomness m ∈ B^32.
    
    Output:
    - shared secret K ∈ B^32.
    - ciphertext c ∈ B^(32(d_u * k + d_v)).
    """
    
    K, r = aux.G(m + aux.H(ek)) # derive shared secret key 𝐾 and randomness r
    c = k_pke.encrypt(ek, m, r) # encrypt 𝑚 using K-PKE with randomness r
    return K, c

def decaps_internal(dk, c):
    """
    This is algorithm 18 from the FIPS 203 document.
    
    Uses the decapsulation key to produce a shared secret key from a ciphertext.
    
    Input:
    - decapsulation key dk ∈ B^(768 + 96).
    - ciphertext c ∈ B^(32(d_u * k + d_v)).
    
    Output:
    - shared secret K ∈ B^32.
    """
    
    dkPKE = dk[0:384 * params.k] # extract (from KEM decaps key) the PKE decryption key
    ekPKE = dk[384 * params.k: 768 * params.k + 32] # extract PKE encryption key
    h = dk[768 * params.k + 32: 768 * params.k + 64] # extract hash of PKE encryption key
    z = dk[768 * params.k + 64: 768 * params.k + 96] # extract implicit rejection value
    m_prime = k_pke.decrypt(dkPKE, c) # decrypt ciphertext
    K_prime, r_prime = aux.G(m_prime + h)
    K_hat = aux.J(z + c)
    c_prime = k_pke.encrypt(ekPKE, m_prime, r_prime) # re-encrypt using the derived randomness r'

    if c != c_prime:
        K_prime = K_hat # if ciphertexts do not match, “implicitly reject”

    return K_prime