import unittest
import json
from mlkem import keygen_for_testing as keygen

'''
    NOTE: YOU MUST ENSURE THAT YOU HAVE THE CORRECT PARAMETER SET (ML-KEM-1024) IN THE PARAMETER_SETS.py FILE BEFORE RUNNING THESE TESTS.
    THE TESTS WILL FAIL IF THE PARAMETER SET IS INCORRECT.
'''

class TestMLKEMKeygen(unittest.TestCase):
    @classmethod
    
    def setUpClass(cls):
        with open("test_vectors_keygen/prompt.json", "r") as f:
            cls.prompt_data = json.load(f)
            
        with open("test_vectors_keygen/expectedResults.json", "r") as f:
            cls.expected_data = json.load(f)
            
        cls.expected_lookup = {
            test["tcId"]: (bytes.fromhex(test["ek"]), bytes.fromhex(test["dk"]))
            for group in cls.expected_data["testGroups"]
            for test in group["tests"]
        }
        
    def test_keygen(self):
        for test in self.prompt_data["testGroups"][2]["tests"]:
            tc_id = test["tcId"]
            d = bytes.fromhex(test["d"])
            z = bytes.fromhex(test["z"])
            ek, dk = keygen(d, z)
            expected_ek, expected_dk = self.expected_lookup[tc_id]
            self.assertEqual(ek, expected_ek, f"Encapsulation Key mismatch for tcId {tc_id}!")
            self.assertEqual(dk, expected_dk, f"Decapsulation Key mismatch for tcId {tc_id}!")
                
if __name__ == "__main__":
    unittest.main()