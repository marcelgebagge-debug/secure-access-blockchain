from ecdsa import SigningKey, SECP256k1


class KeyManager:
    @staticmethod
    def generate_keys():
        """Membuat pasangan kunci baru.
        Private Key: Disimpan user (RAHASIA)
        Public Key: Disimpan server (UMUM)
        """
        # Menggunakan kurva SECP256k1 (standar Bitcoin/Ethereum)
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key = private_key.verifying_key

        return private_key, public_key

    @staticmethod
    def get_public_key_string(public_key):
        """Mengubah object key menjadi string hex agar mudah dibaca"""
        return public_key.to_string().hex()
