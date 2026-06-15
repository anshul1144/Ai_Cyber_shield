import unittest
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.backup.data_scanner import DataScanner
from core.backup.encryptor import Encryptor

class TestBackup(unittest.TestCase):
    def test_scanner_empty(self):
        scanner = DataScanner()
        res = scanner.find_critical_files()
        self.assertEqual(len(res), 0)

    def test_encryptor_empty(self):
        encryptor = Encryptor()
        res = encryptor.encrypt_file("temp.txt")
        self.assertEqual(res, b"")

if __name__ == "__main__":
    unittest.main()
