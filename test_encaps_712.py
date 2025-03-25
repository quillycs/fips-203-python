import unittest
import json
from mlkem import encaps_for_testing as encaps, decaps_for_testing as decaps

'''
    NOTE: YOU MUST ENSURE THAT YOU HAVE THE CORRECT PARAMETER SET (ML-KEM-512) IN THE PARAMETER_SETS.py FILE BEFORE RUNNING THESE TESTS.
    THE TESTS WILL FAIL IF THE PARAMETER SET IS INCORRECT.
'''

class TestMLKEMEncaps(unittest.TestCase):
    @classmethod
    
    def setUpClass(cls):
        with open("test_vectors_encaps_decaps/prompt.json", "r") as f:
            cls.prompt_data = json.load(f)
            
        with open("test_vectors_encaps_decaps/expectedResults.json", "r") as f:
            cls.expected_data = json.load(f)
            
        cls.expected_lookup = {
            test["tcId"]: (bytes.fromhex(test["c"]), bytes.fromhex(test["k"]))
            for test in cls.expected_data["testGroups"][1]["tests"]
        }
        
    def test_encaps(self):
        for test in self.prompt_data["testGroups"][1]["tests"]:
            tc_id = test["tcId"]
            ek = bytes.fromhex(test["ek"])
            m = bytes.fromhex(test["m"])
            k, c = encaps(ek, m)
            expected_c, expected_k = self.expected_lookup[tc_id]
            self.assertEqual(c, expected_c, f"Encapsulation Key mismatch for tcId {tc_id}!")
            self.assertEqual(k, expected_k, f"Decapsulation Key mismatch for tcId {tc_id}!")
                
if __name__ == "__main__":
    unittest.main()