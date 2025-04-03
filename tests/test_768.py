import unittest
import json
import sys
import os
sys.path.append(os.path.abspath(".."))
from mlkem import keygen_for_testing as keygen
from mlkem import encaps_for_testing as encaps
from mlkem import decaps

'''
    Unit tests for ML-KEM implementation.

    Tests cover:
    - Key generation (`keygen`)
    - Encapsulation (`encaps`)
    - Decapsulation (`decaps`)

    NIST-provided test vectors are loaded from JSON files for validation.
    
    NOTE: YOU MUST ENSURE THAT YOU HAVE SET THE CORRECT PARAMETER SET (ML-KEM-768) IN THE PARAMETER_SETS.py FILE BEFORE RUNNING THESE TESTS.
    THE TESTS WILL FAIL IF THE PARAMETER SET IS INCORRECT.
'''

class TestMLKEM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load test vectors for key generation
        with open("keygen_test_vectors/prompt.json", "r") as f:
            cls.keygen_prompt_data = json.load(f)
            
        with open("keygen_test_vectors/expectedResults.json", "r") as f:
            cls.keygen_expected_data = json.load(f)
            
        cls.keygen_expected_lookup = {
            test["tcId"]: (bytes.fromhex(test["ek"]), bytes.fromhex(test["dk"]))
            for group in cls.keygen_expected_data["testGroups"]
            for test in group["tests"]
        }
        
        # Load test vectors for encapsulation and decapsulation
        with open("encaps_decaps_test_vectors/prompt.json", "r") as f:
            cls.encaps_decaps_prompt_data = json.load(f)
            
        with open("encaps_decaps_test_vectors/expectedResults.json", "r") as f:
            cls.encaps_decaps_expected_data = json.load(f)
            
        # Create lookup for encapsulation test data
        cls.encaps_expected_lookup = {
            test["tcId"]: (bytes.fromhex(test["c"]), bytes.fromhex(test["k"]))
            for test in cls.encaps_decaps_expected_data["testGroups"][1]["tests"]
        }
        
        # Create lookup for decapsulation test data
        cls.decaps_expected_lookup = {
            test["tcId"]: bytes.fromhex(test["k"])
            for test in cls.encaps_decaps_expected_data["testGroups"][4]["tests"]
        }
        
    def test_keygen(self):
        print("\nRunning key generation tests...")
        for test in self.keygen_prompt_data["testGroups"][1]["tests"]:
            tc_id = test["tcId"]
            d = bytes.fromhex(test["d"])
            z = bytes.fromhex(test["z"])
            ek, dk = keygen(d, z)
            expected_ek, expected_dk = self.keygen_expected_lookup[tc_id]
            self.assertEqual(ek, expected_ek, f"ek (encapsulation key) mismatch for tcId {tc_id}!")
            self.assertEqual(dk, expected_dk, f"dk (decapsulation key) mismatch for tcId {tc_id}!")
    
    def test_encaps(self):
        print("\nRunning encapsulation tests...")
        for test in self.encaps_decaps_prompt_data["testGroups"][1]["tests"]:
            tc_id = test["tcId"]
            ek = bytes.fromhex(test["ek"])
            m = bytes.fromhex(test["m"])
            k, c = encaps(ek, m)
            expected_c, expected_k = self.encaps_expected_lookup[tc_id]
            self.assertEqual(c, expected_c, f"c (ciphertext) mismatch for tcId {tc_id}!")
            self.assertEqual(k, expected_k, f"k (shared key) mismatch for tcId {tc_id}!")
    
    def test_decaps(self):
        print("Running decapsulation tests...")
        dk = bytes.fromhex(self.encaps_decaps_prompt_data["testGroups"][4]["dk"])
        
        for test in self.encaps_decaps_prompt_data["testGroups"][4]["tests"]:
            tc_id = test["tcId"]
            c = bytes.fromhex(test["c"])
            k = decaps(dk, c)
            expected_k = self.decaps_expected_lookup[tc_id]
            self.assertEqual(k, expected_k, f"k (decapsulated key) mismatch for tcId {tc_id}!")
                
if __name__ == "__main__":
    unittest.main()