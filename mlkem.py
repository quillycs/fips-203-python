import k_pke
import main_internal_algorithms as internal
import auxiliary_algorithms as aux
import parameter_sets as params
import os

def keygen():
    d = os.urandom(32)
    z = os.urandom(32)
    
    if d is None or z is None:
        return None
    
    ek, dk = internal.keygen_internal(d, z)
    return ek, dk

def encaps(ek):
    m = os.urandom(32)
    
    if m is None:
        return None
    
    K, c = internal.encaps_internal(ek, m)
    return K, c

def decaps(dk, c):
    K_prime = internal.decaps_internal(dk, c)
    return K_prime

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