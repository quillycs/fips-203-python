import k_pke
import main_internal_algorithms as internal
import auxiliary_algorithms as aux
import parameter_sets as params
import os

def keygen():
    """
    This is algorithm 19 from the FIPS 203 document.
    
    Output:
    - encapsulation key ek ∈ B^(384k + 32).
    - decapsulation key dk ∈ B^(768 + 96).
    """
    
    d = os.urandom(32)
    z = os.urandom(32)
    
    if d is None or z is None:
        return None # return an error indication if random bit generation failed
    
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
    m = os.urandom(32)
    
    if m is None:
        return None # return an error indication if random bit generation failed
    
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
The following three functions are identical to the above three functions but have modified parameters (to consume the static test vectors) for testing purposes.
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

def decaps_for_testing(dk, c):
    K_prime = internal.decaps_internal(dk, c)
    return K_prime