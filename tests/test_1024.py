import unittest
import json
import sys
import os
# Adjust the Python path to include the parent directory where mlkem is located
sys.path.append(os.path.abspath(".."))
from mlkem import keygen_for_testing as keygen
from mlkem import encaps_for_testing as encaps
from mlkem import decaps

'''
    Tests cover:
    - Key generation (`keygen`)
    - Encapsulation (`encaps`)
    - Decapsulation (`decaps`)

    This test suite validates the ML-KEM implementation against NIST-provided test vectors. The process is as follows:
        - Test vectors are loaded from NIST-supplied JSON files.
        - These inputs are passed through the three ML-KEM functions: keygen, encaps and decaps.
        - The outputs are compared byte-for-byte against the expected outputs from NIST’s test vectors to ensure correctness.

    NOTE: YOU MUST ENSURE THAT YOU HAVE SET THE CORRECT PARAMETER SET (ML-KEM-1024) IN THE PARAMETER_SETS.py FILE BEFORE RUNNING THESE TESTS.
    THE TESTS WILL FAIL IF THE PARAMETER SET IS INCORRECT.
'''

class TestMLKEM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Load test vectors from JSON files before running tests."""

        # Load key generation test vectors
        with open("keygen_test_vectors/prompt.json", "r") as f:
            cls.keygen_prompt_data = json.load(f)
            
        with open("keygen_test_vectors/expectedResults.json", "r") as f:
            cls.keygen_expected_data = json.load(f)
            
        # Create a lookup dictionary for expected keygen results
        cls.keygen_expected_lookup = {
            test["tcId"]: (bytes.fromhex(test["ek"]), bytes.fromhex(test["dk"]))
            for group in cls.keygen_expected_data["testGroups"]
            for test in group["tests"]
        }
        
        # Load encapsulation and decapsulation test vectors
        with open("encaps_decaps_test_vectors/prompt.json", "r") as f:
            cls.encaps_decaps_prompt_data = json.load(f)
            
        with open("encaps_decaps_test_vectors/expectedResults.json", "r") as f:
            cls.encaps_decaps_expected_data = json.load(f)
            
        # Create a lookup dictionary for expected encapsulation results
        cls.encaps_expected_lookup = {
            test["tcId"]: (bytes.fromhex(test["c"]), bytes.fromhex(test["k"]))
            for test in cls.encaps_decaps_expected_data["testGroups"][2]["tests"]
        }
        
        # Create a lookup dictionary for expected decapsulation results
        cls.decaps_expected_lookup = {
            test["tcId"]: bytes.fromhex(test["k"])
            for test in cls.encaps_decaps_expected_data["testGroups"][5]["tests"]
        }
        
    def test_keygen(self):
        """Test key generation (keygen) function using test vectors."""

        print("\nRunning key generation tests...")

        # Loop through each test case in the keygen test vectors
        for test in self.keygen_prompt_data["testGroups"][2]["tests"]:
            tc_id = test["tcId"]
            # Extract input values (seed values for key generation)
            d = bytes.fromhex(test["d"])
            z = bytes.fromhex(test["z"])
            # Call key generation function
            ek, dk = keygen(d, z)
            # Retrieve expected results
            expected_ek, expected_dk = self.keygen_expected_lookup[tc_id]
            # Validate that generated keys match expected outputs
            self.assertEqual(ek, expected_ek, f"ek (encapsulation key) mismatch for tcId {tc_id}!")
            self.assertEqual(dk, expected_dk, f"dk (decapsulation key) mismatch for tcId {tc_id}!")
    
    def test_encaps(self):
        """Test encapsulation (encaps) function using test vectors."""

        print("\nRunning encapsulation tests...")

        # Loop through each test case in the encapsulation test vectors
        for test in self.encaps_decaps_prompt_data["testGroups"][2]["tests"]:
            tc_id = test["tcId"]
            # Extract input values (public key and message)
            ek = bytes.fromhex(test["ek"])
            m = bytes.fromhex(test["m"])
            # Call encapsulation function
            k, c = encaps(ek, m)
            # Retrieve expected ciphertext and shared key
            expected_c, expected_k = self.encaps_expected_lookup[tc_id]
            # Validate that encapsulated results match expected outputs
            self.assertEqual(c, expected_c, f"c (ciphertext) mismatch for tcId {tc_id}!")
            self.assertEqual(k, expected_k, f"k (shared key) mismatch for tcId {tc_id}!")
    
    def test_decaps(self):
        """Test decapsulation (decaps) function using test vectors."""

        print("Running decapsulation tests...")

        # Extract the private key for decapsulation
        dk = bytes.fromhex(self.encaps_decaps_prompt_data["testGroups"][5]["dk"])
        
        # Loop through each test case in the decapsulation test vectors
        for test in self.encaps_decaps_prompt_data["testGroups"][5]["tests"]:
            # Test case ID for reference
            tc_id = test["tcId"]
            # Extract input ciphertext
            c = bytes.fromhex(test["c"])
            # Call decapsulation function
            k = decaps(dk, c)
            # Retrieve expected shared key
            expected_k = self.decaps_expected_lookup[tc_id]
            # Validate that decapsulated key matches expected output
            self.assertEqual(k, expected_k, f"k (decapsulated key) mismatch for tcId {tc_id}!")
                
if __name__ == "__main__":
    unittest.main()