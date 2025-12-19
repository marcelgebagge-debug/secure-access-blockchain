import hashlib
import json
from datetime import datetime


class Block:
    def __init__(self, index, data, previous_hash):
        self.index = index
        self.timestamp = str(datetime.now())
        self.data = data  # Berisi detail akses (Siapa, Kapan, Status)
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Menghitung hash blok berdasarkan isinya"""
        # Menggabungkan seluruh isi blok menjadi satu string
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
        }, sort_keys=True)

        # Hash string tersebut menggunakan SHA-256
        return hashlib.sha256(block_string.encode()).hexdigest()
