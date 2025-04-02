This repository contains an implementation of FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism Standard) in Python. 

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

# Using the implementation without the static test vectors
```ML-KEM.KeyGen()``` and ```ML-KEM.Encaps(ek)``` use a deterministic random bit generator (RBG) whose code can be found in ```aes_drbg.py``` (sourced from https://github.com/popcornell/pyAES_DRBG/tree/master). Feel free to clone the source repository and test the deterministic RBG using NIST's static test vectors to independently confirm that it is compliant with FIPS 203. 

The deterministic RBG takes in "entropy" as a parameter for generation. The creation of said "entropy" must also be compliant with FIPS 203. My implementation uses ```get_random_bytes``` from ```Crypto.Random``` to create the "entropy". This is only compliant with FIPS 203 if the machine the program is being used on is running in FIPS mode. I have a Windows machine so I can provide the steps to ensure one's Windows machine is in FIPS mode. If you are using Linux or MacOS, you will need to do the research yourself.

## Windows
1) Press ```Windows + r``` and enter ```gpedit.msc```.
2) In the ```Local Group Policy Editor```, navigate to ```Computer Configuration``` > ```Windows Settings``` > ```Security Settings``` > ```Local Policies``` > ```Security Options```.
3) Find the setting named ```System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing``` and double-click on it.
4) Select the ```Enabled``` option and click ```OK```.
5) Close the ```Local Group Policy Editor``` and restart your computer for the changes to take effect.

Note: Enabling FIPS mode may impact the functionality of some applications that do not support FIPS-compliant algorithms.
