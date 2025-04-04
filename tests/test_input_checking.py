import os
import sys
import unittest
from unittest.mock import patch
# Adjust the Python path to include the parent directory where mlkem is located
sys.path.append(os.path.abspath(".."))

from mlkem import keygen, encaps

class TestMLKEMInputChecking(unittest.TestCase):
    @patch('mlkem.rand')
    @patch('mlkem.AES_DRBG')
    def test_keygen_with_failed_random_generation(self, mock_drbg_class, mock_rand):
        # Setup mocks
        mock_rand.return_value = b'0' * 48
        
        # Mock the DRBG instance
        mock_drbg_instance = mock_drbg_class.return_value
        mock_drbg_instance.instantiate.return_value = None
        
        # First generate call returns None (d)
        mock_drbg_instance.generate.side_effect = [None, b'0' * 32]
        
        # Test keygen should detect the failed random bit generation for 'd'
        result = keygen()
        self.assertEqual(result, "ERROR: Random bit generation failed")
        
        # Reset side effect to test 'z' being None
        mock_drbg_instance.generate.side_effect = [b'0' * 32, None]
        
        # Test keygen should detect the failed random bit generation for 'z'
        result = keygen()
        self.assertEqual(result, "ERROR: Random bit generation failed")
    
    @patch('mlkem.rand')
    @patch('mlkem.AES_DRBG')
    def test_encaps_with_failed_random_generation(self, mock_drbg_class, mock_rand):
        # Setup mocks
        mock_rand.return_value = b'0' * 48
        
        # Mock the DRBG instance
        mock_drbg_instance = mock_drbg_class.return_value
        mock_drbg_instance.instantiate.return_value = None
        
        # The generate call returns None (m)
        mock_drbg_instance.generate.return_value = None
        
        # Test encaps should detect the failed random bit generation
        ek = b'dummy_encapsulation_key' * 10  # Dummy encapsulation key
        result = encaps(ek)
        self.assertEqual(result, "ERROR: Random bit generation failed")

if __name__ == '__main__':
    unittest.main()