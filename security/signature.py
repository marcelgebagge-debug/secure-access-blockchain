from ecdsa import BadSignatureError


class DigitalSignature:
    @staticmethod
    def sign_data(private_key, message):
        """User menandatangani pesan dengan Private Key mereka.
        Input: private_key (object), message (string)
        Output: signature (bytes)
        """
        # Pesan harus di-encode ke bytes sebelum di-sign
        message_bytes = message.encode("utf-8")
        signature = private_key.sign(message_bytes)
        return signature

    @staticmethod
    def verify_signature(public_key, message, signature):
        """Sistem mengecek apakah tanda tangan valid untuk pesan tersebut.
        Return: True jika valid, False jika tidak.
        """
        try:
            message_bytes = message.encode("utf-8")
            return public_key.verify(signature, message_bytes)
        except BadSignatureError:
            return False
