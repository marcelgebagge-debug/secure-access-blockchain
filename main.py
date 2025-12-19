from security.keys import KeyManager
from security.signature import DigitalSignature
from blockchain.chain import Blockchain


def run_simulation():
    # --- SETUP SISTEM ---
    print("1. Menghubungkan ke Cloud Database & Monitoring...")
    access_log = Blockchain()

    # --- STEP 1: REGISTRASI USER ---
    print("\n2. User 'Andi' mendaftar (Generate Keys)...")
    andi_private, andi_public = KeyManager.generate_keys()
    andi_id = KeyManager.get_public_key_string(andi_public)[:20] + "..."
    print(f"   -> ID Andi: {andi_id}")

    # --- STEP 2: SIMULASI AKSES RESMI ---
    print("\n3. Skenario 1: Andi Request Akses")
    msg = "Buka Pintu Server"
    sig = DigitalSignature.sign_data(andi_private, msg)

    if DigitalSignature.verify_signature(andi_public, msg, sig):
        print("   -> [SYSTEM] Verifikasi SUKSES.")
        access_log.add_log(andi_id, "Access Request", "GRANTED")
    else:
        print("   -> [SYSTEM] GAGAL.")

    # --- STEP 3: SIMULASI HACKER ---
    print("\n4. Skenario 2: Hacker Request Akses")
    hacker_priv, _ = KeyManager.generate_keys()
    hack_sig = DigitalSignature.sign_data(hacker_priv, msg)  # Sign pakai kunci hacker

    if DigitalSignature.verify_signature(andi_public, msg, hack_sig):  # Cek pakai kunci Andi
        print("   -> [SYSTEM] BAHAYA! Hacker lolos.")
    else:
        print("   -> [SYSTEM] DITOLAK! Signature invalid.")
        access_log.add_log("Unknown/Hacker", "Access Request", "DENIED")

    access_log.print_chain()

    # --- STEP 4: MONITORING & TAMPERING ---
    print("\n5. Skenario 3: Admin Nakal & Cloud Monitoring")

    # Lapor kondisi aman dulu
    access_log.report_security_status(True, "Routine Check - All Good")

    # Lakukan Tampering
    target_block = access_log.chain[-1]
    print(f"   -> Mengubah paksa data Blok #{target_block.index}...")
    target_block.data["status"] = "GRANTED_FORCED"

    # Cek & Lapor Otomatis
    print("   -> Validasi Integritas berjalan...")
    is_secure = access_log.is_chain_valid()

    if not is_secure:
        print("   -> [SYSTEM] ALARM! Melaporkan insiden ke Cloud Dashboard...")
        # Kirim status MERAH ke Firebase
        access_log.report_security_status(
            False, f"Tampering detected at Block #{target_block.index}"
        )
    else:
        print("   -> [SYSTEM] Aman.")

    # --- Selesai ---
    print("\n[INFO] Simulasi Selesai. Cek Firebase Console sekarang!")


if __name__ == "__main__":
    run_simulation()
