This repository contains an implementation of FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism Standard) in Python. 

# How to test the correctness of the implementation
This implementation makes use of static test vectors made available by NIST in [this](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files) GitHub repository. To test the correctness of the implementation for yourself, follow these steps:
- Clone the repository.
- Install the project's dependencies using `pip3 install -r requirements.txt`.
- Go to `parameter_sets.py` and choose the parameter set you want to test by commenting out the other two parameter sets. For example, if you want to test the ML-KEM-768 parameter set, your `parameter_sets.py` file should look as follows:

```python
'''
    COMMENT OUT THE TWO PARAMETER SETS THAT YOU ARE NOT TESTING.
    UNCOMMENT THE PARAMETER SET THAT YOU ARE TESTING.
'''

# Constants
n = 256
q = 3329
zeta = 17

'''# ML-KEM-512
k = 2
eta1 = 3
eta2 = 2
du = 10
dv = 4'''

# ML-KEM-768
k = 3
eta1 = 2
eta2 = 2
du = 10
dv = 4

'''# ML-KEM-1024
k = 4
eta1 = 2
eta2 = 2
du = 11
dv = 5'''
```
- To test key generation, run `python3 test_keygen_{parameter set number goes here (e.g. 768)}.py` in the console.
- To test encapsulation, run `python3 test_encaps_{parameter set number goes here (e.g. 768)}.py` in the console.
- To test decapsulation, run `python3 test_decaps_{parameter set number goes here (e.g. 768)}.py` in the console.

This implementation passes all tests.

# Using the implementation without the static test vectors
```ML-KEM.KeyGen()``` and ```ML-KEM.Encaps(ek)``` use a deterministic random bit generator (RBG) whose code can be found in ```aes_drbg.py``` (sourced from https://github.com/popcornell/pyAES_DRBG/tree/master). Feel free to clone the source repository and test the deterministic RBG using NIST's static test vectors to independently confirm that it is compliant with FIPS 203. 

**The deterministic RBG takes in "entropy" as a parameter for generation. The creation of said "entropy" must also be compliant with FIPS 203. My implementation uses ```RAND_bytes``` from ```ssl``` to create the "entropy". This is only compliant with FIPS 203 if the OpenSSL installation on your computer is FIPS-enabled.**

If you want to use any of the functions in the codebase, simply call them. For example, if you want to try out `ML-KEM.KeyGen()` to observe its output, you could go to `mlkem.py` and write `print(keygen())` at the bottom of the page, and then run the file with `python3 mlkem.py` in the console. 
