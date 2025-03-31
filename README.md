This repository contains an implementation of FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism Standard) in Python. 

# The need for standards like FIPS 203

Advancements in quantum computing have made it clear that a large-scale quantum computer would have the capability to break many cryptographic schemes in wide use today, jeopardising the security of all digital information. Post-quantum cryptography focuses on developing algorithms that are resistant to attacks from both quantum and classical adversaries. Once standardised and widely adopted, these algorithms would ensure digital security regardless of whether operational quantum computers exist.

Since cryptography encompasses many fields, post-quantum algorithms must be developed for each. In this project, I will focus on a structure called a Key Encapsulation Mechanism (KEM), which is used in public-key cryptography to establish a shared secret key between two parties over an insecure channel. The National Institute of Standards and Technology (NIST) has standardised the Module-Lattice-Based Key-Encapsulation Mechanism Standard (FIPS 203), which provides a detailed framework for a quantum-resistant KEM. I have implemented this standard in Python.

# How to test the correctness of the implementation
This implementation makes use of static test vectors made available by NIST in [this](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files) GitHub repository. To test the correctness of the implementation for yourself, follow these steps:
- Clone the repository.
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
