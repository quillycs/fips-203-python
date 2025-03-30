import unittest
import json
import sys
import os
sys.path.append(os.path.abspath(".."))
from mlkem import decaps_for_testing as decaps

'''
    NOTE: YOU MUST ENSURE THAT YOU HAVE SET THE CORRECT PARAMETER SET (ML-KEM-512) IN THE PARAMETER_SETS.py FILE BEFORE RUNNING THESE TESTS.
    THE TESTS WILL FAIL IF THE PARAMETER SET IS INCORRECT.
'''

class TestMLKEMDecaps(unittest.TestCase):
    @classmethod
    
    def setUpClass(cls):
        with open("../test_vectors_encaps_decaps/prompt.json", "r") as f:
            cls.prompt_data = json.load(f)
            
        with open("../test_vectors_encaps_decaps/expectedResults.json", "r") as f:
            cls.expected_data = json.load(f)
            
        cls.expected_lookup = {
            test["tcId"]: (bytes.fromhex(test["k"]))
            for test in cls.expected_data["testGroups"][3]["tests"]
        }
        
    def test_decaps(self):
        dk = bytes.fromhex(self.prompt_data["testGroups"][3]["dk"])
        
        for test in self.prompt_data["testGroups"][3]["tests"]:
            tc_id = test["tcId"]
            c = bytes.fromhex(test["c"])
            k = decaps(dk, c)
            expected_k = self.expected_lookup[tc_id]
            self.assertEqual(k, expected_k, f"Decapsulation Key mismatch for tcId {tc_id}!")
                
if __name__ == "__main__":
    unittest.main()