import K_PKE
import MLKEM_INTERNAL as mlkem
import AUXILIARY_ALGORITHMS as aux
import PARAMETER_SETS as params
import os

def keygen():
    d = os.urandom(32)
    z = os.urandom(32)
    
    if d is None or z is None:
        return None
    
    ek, dk = mlkem.keygen_internal(d, z)
    return ek, dk

def encaps(ek):
    m = os.urandom(32)
    
    if m is None:
        return None
    
    K, c = mlkem.encaps_internal(ek, m)
    return K, c

def decaps(dk, c):
    K_prime = mlkem.decaps_internal(dk, c)
    return K_prime