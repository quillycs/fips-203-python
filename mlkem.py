import main_internal_algorithms as internal
from aes_drbg import AES_DRBG
from ssl import RAND_bytes as rand

"""
IMPORTANT: Your installation of OpenSSL must be FIPS-enabled for compliance with FIPS 203. If your OpenSSL installation does not have FIPS enabled, entropy generation will still work, but it will not be compliant with FIPS 203.
"""

def keygen():
    """
    This is algorithm 19 from the FIPS 203 document.
    
    Generates an encapsulation key and a corresponding decapsulation key.
    
    Output:
    - encapsulation key ek ∈ B^(384k + 32).
    - decapsulation key dk ∈ B^(768 + 96).
    """
    
    drbg = AES_DRBG(keylen = 256) # initialises a FIPS-203 compliant deterministic random bit generator (drbg)
    entropy = rand(48) # generates entropy using OpenSSL
    drbg.instantiate(entropy_in = entropy) # feeds the entropy into the drbg
    
    d = drbg.generate(32)
    z = drbg.generate(32)
    
    if d is None or z is None:
        return "ERROR: Random bit generation failed" # return an error indication if random bit generation failed
    
    ek, dk = internal.keygen_internal(d, z) # run internal key generation algorithm
    return ek, dk

def encaps(ek):
    """
    This is algorithm 20 from the FIPS 203 document.
    
    Uses the encapsulation key to generate a shared secret key and an associated ciphertext.
    
    Checked input:
    - encapsulation key ek ∈ B^(384k + 32).
    
    Output:
    - shared secret K ∈ B^32.
    - ciphertext c ∈ B^(32(d_u * k + d_v)).
    """
    drbg = AES_DRBG(keylen = 256) # initialises a FIPS-203 compliant deterministic random bit generator (drbg)
    entropy = rand(48) # generates entropy using OpenSSL
    drbg.instantiate(entropy_in = entropy) # feeds the entropy into the drbg
    
    m = drbg.generate(32)
    
    if m is None:
        return "ERROR: Random bit generation failed" # return an error indication if random bit generation failed
    
    K, c = internal.encaps_internal(ek, m) # run internal encapsulation algorithm
    return K, c

def decaps(dk, c):
    """
    This is algorithm 21 from the FIPS 203 document.
    
    Uses the decapsulation key to produce a shared secret key from a ciphertext.
    
    Checked input:
    - decapsulation key dk ∈ B^(768 + 96).
    - ciphertext c ∈ B^(32(d_u * k + d_v)).
    
    Output:
    - shared secret K ∈ B^32.
    """
    
    K_prime = internal.decaps_internal(dk, c) # run internal decapsulation algorithm
    return K_prime

"""
The following two functions have modified parameters (to consume the static test vectors) for testing purposes.
"""

def keygen_for_testing(d, z):
    if d is None or z is None:
        return None
    
    ek, dk = internal.keygen_internal(d, z)
    return ek, dk

def encaps_for_testing(ek, m):
    if m is None:
        return None
    
    K, c = internal.encaps_internal(ek, m)
    return K, c