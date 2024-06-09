import unittest
from aes import AES

class AES_TEST(unittest.TestCase):
    def setUp(self):
        # 定义密钥
        master_key = 0x2b7e151628aed2a6abf7158809cf4f3c
        self.AES = AES(master_key)

    def test_encryption(self):
        plaintext = 0x3243f6a8885a308d313198a2e0370734
        encrypted = self.AES.encrypt(plaintext)
        print(f"AES加密\n明文:0x{plaintext:X}\n密文:0x{encrypted:X}")
        self.assertEqual(encrypted, 0x3925841d02dc09fbdc118597196a0b32)

    def test_decryption(self):
        ciphertext = 0x3925841d02dc09fbdc118597196a0b32
        decrypted = self.AES.decrypt(ciphertext)
        print(f"AES加密\n密文:0x{ciphertext:X}\n明文:0x{decrypted:X}")
        self.assertEqual(decrypted, 0x3243f6a8885a308d313198a2e0370734)

if __name__ == '__main__':
    unittest.main()
