import streamlit as st
import pandas as pd
import cv2
import numpy as np
import qrcode
import requests  # <--- Library baru untuk kirim pesan
from io import BytesIO
from security.keys import KeyManager
from security.signature import DigitalSignature
from blockchain.chain import Blockchain

# ==========================================
# KONFIGURASI TELEGRAM (WAJIB DIISI!)
# ==========================================
# Ganti dengan Token dari BotFather sebelum dipakai (jangan commit token asli)
TELEGRAM_BOT_TOKEN = "MASUKKAN_TOKEN_ANDA_DISINI"
# Ganti dengan angka ID dari userinfobot sebelum dipakai (jangan commit ID asli)
TELEGRAM_CHAT_ID = "MASUKKAN_ID_ANDA_DISINI"


def send_telegram_alert(message):
    """Fungsi untuk mengirim notifikasi ke HP"""
    # Cek apakah user sudah mengisi token atau belum
    if "MASUKKAN" in TELEGRAM_BOT_TOKEN:
        print("[WARNING] Token Telegram belum diisi di app.py!")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown",
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print("[TELEGRAM] Pesan terkirim!")
        else:
            print(f"[TELEGRAM] Gagal kirim: {response.text}")
    except Exception as e:
        print(f"[TELEGRAM] Error koneksi: {e}")


# ==========================================
# KODE APLIKASI UTAMA
# ==========================================

st.set_page_config(
    page_title="Secure Access + IoT Alert", page_icon="🚨", layout="wide"
)


@st.cache_resource
def get_blockchain():
    return Blockchain()


# --- HELPER FUNCTIONS ---
def generate_qr_image(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")
    buf = BytesIO()
    img.save(buf)
    return buf.getvalue()


def read_qr_from_image(uploaded_file):
    file_bytes = np.asarray(bytearray(uploaded_file.read()), dtype=np.uint8)
    opencv_image = cv2.imdecode(file_bytes, 1)
    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(opencv_image)
    return data


# --- STATE MANAGEMENT ---
if "andi_keys" not in st.session_state:
    st.session_state.andi_keys = None

bc = get_blockchain()

# --- UI ---
st.title("🚨 Secure Access System: Blockchain & Real-time Alert")

tab1, tab2, tab3 = st.tabs([
    "📱 Registrasi (QR)",
    "📷 Scan Akses",
    "🛡️ Admin & Monitoring",
])

# === TAB 1: REGISTRASI ===
with tab1:
    st.header("1. Buat Identitas Digital")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Generate ID Baru (Andi)"):
            priv, pub = KeyManager.generate_keys()
            st.session_state.andi_keys = (priv, pub)
            priv_hex = priv.to_string().hex()
            qr_bytes = generate_qr_image(priv_hex)
            st.session_state.qr_download = qr_bytes
            st.success("Identitas Berhasil Dibuat!")

    with col2:
        if st.session_state.andi_keys:
            st.image(
                st.session_state.qr_download, caption="Kartu Akses QR", width=200
            )
            st.download_button(
                "⬇️ Download QR Code",
                st.session_state.qr_download,
                "andi_access_key.png",
                "image/png",
            )

# === TAB 2: LOGIN & SCAN ===
with tab2:
    st.header("2. Simulasi Masuk (Scan QR)")
    request_msg = st.text_input("Tujuan Akses", "Buka Pintu Server")
    uploaded_file = st.file_uploader("Upload Kartu QR", type=["png", "jpg", "jpeg"])

    if uploaded_file is not None:
        try:
            extracted_priv_hex = read_qr_from_image(uploaded_file)
            if extracted_priv_hex:
                st.info("QR Code Terbaca... Memproses Otorisasi.")

                # Tombol simulasi
                col_ok, col_hack = st.columns(2)

                # Simulasi Valid
                with col_ok:
                    if st.button("🚀 Proses Login (Resmi)"):
                        from ecdsa import SigningKey, SECP256k1

                        priv = SigningKey.from_string(
                            bytes.fromhex(extracted_priv_hex), curve=SECP256k1
                        )
                        pub = priv.verifying_key
                        user_id = (
                            KeyManager.get_public_key_string(pub)[:20] + "..."
                        )

                        sig = DigitalSignature.sign_data(priv, request_msg)
                        if DigitalSignature.verify_signature(pub, request_msg, sig):
                            st.balloons()
                            st.success(
                                f"AKSES DITERIMA! Selamat datang, {user_id}"
                            )
                            bc.add_log(user_id, request_msg, "GRANTED_QR_AUTH")

                            # Kirim Notif Sukses ke Telegram
                            send_telegram_alert(
                                f"✅ *ACCESS GRANTED*\nUser: `{user_id}`\nPintu Terbuka."
                            )
                        else:
                            st.error("Signature Invalid.")

                # Simulasi Hacker
                with col_hack:
                    if st.button("🔴 Simulasi Serangan Hacker"):
                        st.error("AKSES DITOLAK! Tanda tangan digital tidak valid.")
                        bc.add_log("Unknown/Hacker", request_msg, "DENIED")

                        # KIRIM ALERT KE TELEGRAM
                        st.toast("Alert dikirim ke Telegram!", icon="🚨")
                        send_telegram_alert(
                            "⚠️ *INTRUSION ALERT*\nUpaya masuk paksa terdeteksi!\nStatus: DENIED\nIP: Unknown"
                        )

            else:
                st.error("QR Code kosong/rusak.")
        except Exception as e:
            st.error(f"Error: {e}")

# === TAB 3: MONITORING ===
with tab3:
    st.header("3. Security Dashboard (Real-time)")

    if st.button("🔄 Refresh Data"):
        bc.load_chain()

    if len(bc.chain) > 0:
        chain_data = []
        for block in bc.chain:
            chain_data.append(
                {
                    "Index": block.index,
                    "Status": block.data.get("status", "-"),
                    "Hash": block.hash[:15] + "...",
                }
            )
        st.dataframe(pd.DataFrame(chain_data))

        if bc.is_chain_valid(verbose=False):
            st.success("Status Sistem: AMAN ✅")
        else:
            st.error("Status Sistem: BAHAYA / PERETASAN ❌")

    # FITUR TAMPERING DENGAN NOTIFIKASI
    st.divider()
    st.subheader("⚠️ Zona Bahaya (Admin Only)")

    if st.button("🚨 Lakukan Serangan Tampering Data!"):
        if len(bc.chain) > 1:
            target = bc.chain[-1]
            target.data["status"] = "GRANTED_FORCED"  # Ubah paksa

            # Cek Validitas
            if not bc.is_chain_valid():
                msg = (
                    "🚨 *CRITICAL SECURITY ALERT* 🚨\n\nIntegritas Blockchain RUSAK!"
                    f"\nLokasi: Block #{target.index}\nStatus: DATA MANIPULATION DETECTED"
                )

                # Lapor ke Firebase
                bc.report_security_status(
                    False, f"Tampering at Block #{target.index}"
                )

                # Lapor ke Telegram
                send_telegram_alert(msg)

                st.error("TAMPERING DETECTED! Alarm dikirim ke HP Admin.")
        else:
            st.warning("Data belum cukup.")
