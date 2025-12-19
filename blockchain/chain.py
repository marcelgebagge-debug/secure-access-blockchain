import hashlib
import json
import firebase_admin
from firebase_admin import credentials, db
from datetime import datetime
from blockchain.block import Block


class Blockchain:
    def __init__(self):
        # 1. Koneksi ke Firebase (Hanya sekali init)
        if not firebase_admin._apps:
            # Pastikan file ini ada di folder proyek
            cred = credentials.Certificate("serviceAccountKey.json")

            # GANTI DENGAN URL DATABASE ANDA SENDIRI
            firebase_admin.initialize_app(
                cred,
                {
                    "databaseURL": "https://accessblockchain-21e53-default-rtdb.firebaseio.com/",
                },
            )

        # Referensi Data Utama (Blockchain)
        self.ref = db.reference("blockchain_data")

        # Referensi BARU: Dashboard Monitoring
        self.monitor_ref = db.reference("system_health")

        self.chain = []
        # Load data lama saat pertama kali jalan
        self.load_chain()

    def load_chain(self):
        """Mengambil data blockchain dari Firebase.
        Mampu menangani format List (Array) maupun Dictionary (Map).
        """
        data = self.ref.get()

        if data:
            print("[INFO] Mengunduh Blockchain dari Firebase...")
            chain_data = []

            # CASE A: Firebase mengembalikan List
            if isinstance(data, list):
                chain_data = [x for x in data if x is not None]

            # CASE B: Firebase mengembalikan Dictionary
            elif isinstance(data, dict):
                sorted_keys = sorted(data.keys(), key=lambda x: int(x))
                for key in sorted_keys:
                    chain_data.append(data[key])

            # Re-construct Object Block
            for item in chain_data:
                if "data" in item and "previous_hash" in item:
                    loaded_block = Block(item["index"], item["data"], item["previous_hash"])
                    loaded_block.timestamp = item.get("timestamp")
                    loaded_block.hash = item.get("hash")
                    self.chain.append(loaded_block)

            print(f"[INFO] {len(self.chain)} Blok berhasil dimuat dari Cloud.")

            # Validasi integritas data yang baru didownload
            if not self.is_chain_valid(verbose=False):
                print("[WARNING] Data cloud terdeteksi KORUP saat dimuat!")
                self.report_security_status(False, "Cloud Data Corrupted on Load")
            else:
                self.report_security_status(True, "System Loaded & Secure")

        else:
            print("[INFO] Database kosong. Membuat Genesis Block...")
            self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, "Genesis Log - Cloud System Start", "0")
        self.chain.append(genesis_block)
        self.ref.child("0").set(self.block_to_dict(genesis_block))
        self.report_security_status(True, "Genesis Block Created")

    def add_log(self, user_id, action, status):
        # Auto-validasi sebelum menambah
        if not self.is_chain_valid(verbose=False):
            print("[ERROR] Rantai rusak! Blok baru ditolak.")
            return False

        previous_block = self.chain[-1]

        log_data = {
            "user": user_id,
            "action": action,
            "status": status,
        }

        new_block = Block(
            index=len(self.chain),
            data=log_data,
            previous_hash=previous_block.hash,
        )

        self.chain.append(new_block)

        # Upload ke Firebase
        self.ref.child(str(new_block.index)).set(self.block_to_dict(new_block))
        print(f"[CLOUD] Blok #{new_block.index} berhasil di-upload ke Firebase!")
        return True

    def block_to_dict(self, block):
        return {
            "index": block.index,
            "timestamp": block.timestamp,
            "data": block.data,
            "hash": block.hash,
            "previous_hash": block.previous_hash,
        }

    def print_chain(self):
        """Menampilkan ringkasan blockchain di terminal"""
        print("\n=== CLOUD BLOCKCHAIN DATA ===")
        for block in self.chain:
            print(f"Index: {block.index} | Hash: {block.hash[:15]}...")

    def is_chain_valid(self, verbose=True):
        """Cek Integritas Rantai"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                if verbose:
                    print(f"[ALERT] Manipulasi Data pada Blok #{current_block.index}!")
                return False

            if current_block.previous_hash != previous_block.hash:
                if verbose:
                    print(f"[ALERT] Rantai Putus di Blok #{current_block.index}!")
                return False

        return True

    def report_security_status(self, is_secure, message="System Normal"):
        """FITUR BARU: Lapor status ke Dashboard Firebase"""
        timestamp = str(datetime.now())
        status_data = {
            "status": "SECURE" if is_secure else "CRITICAL_COMPROMISED",
            "last_check": timestamp,
            "message": message,
        }
        # Update node 'system_health'
        self.monitor_ref.set(status_data)
