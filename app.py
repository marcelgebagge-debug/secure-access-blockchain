import streamlit as st
import pandas as pd
import cv2
import numpy as np
import qrcode
import requests
import json
import os
from io import BytesIO
from security.keys import KeyManager
from security.signature import DigitalSignature
from blockchain.chain import Blockchain

# ==========================================
# KONFIGURASI KHUSUS CLOUD (SECRETS)
# ==========================================
# 1. Buat file serviceAccountKey.json dari Secrets (jika di Cloud)
try:
    if "firebase" in st.secrets:
        # Kita tulis isi secrets ke file sementara agar bisa dibaca Firebase
        with open("serviceAccountKey.json", "w") as f:
            f.write(st.secrets["firebase"]["textkey"])
except Exception:
    pass  # Jika tidak ada secrets (lokal), skip

# 2. Ambil Token Telegram dari Secrets (Prioritas) atau Fallback (Lokal)
try:
    if "TELEGRAM_BOT_TOKEN" in st.secrets:
        TELEGRAM_BOT_TOKEN = st.secrets["TELEGRAM_BOT_TOKEN"]
        TELEGRAM_CHAT_ID = st.secrets["TELEGRAM_CHAT_ID"]
    else:
        # Fallback untuk testing lokal
        TELEGRAM_BOT_TOKEN = "8239544189:AAGDctUZ7CF3b1fhVMcqEYGwRebo0mp5lJI"
        TELEGRAM_CHAT_ID = "1839441766"
except Exception:
    # Fallback untuk testing lokal
    TELEGRAM_BOT_TOKEN = "8239544189:AAGDctUZ7CF3b1fhVMcqEYGwRebo0mp5lJI"
    TELEGRAM_CHAT_ID = "1839441766"

# ==========================================
# SETUP HALAMAN
# ==========================================
st.set_page_config(page_title="Secure Access Dashboard", page_icon="🛡️", layout="wide")

# Hilangkan elemen bawaan Streamlit
st.markdown(
    """<style>#MainMenu {visibility: hidden;} footer {visibility: hidden;}</style>""",
    unsafe_allow_html=True,
)

# ==========================================
# FUNGSI BANTUAN
# ==========================================


@st.cache_resource
def get_blockchain():
    # Blockchain akan otomatis mencari serviceAccountKey.json yang sudah kita buat di atas
    return Blockchain()


def send_telegram_alert(message):
    if "MASUKKAN" in TELEGRAM_BOT_TOKEN:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
    try:
        requests.post(url, json=payload)
    except Exception:
        pass


def generate_qr_image(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    buf = BytesIO()
    qr.make_image(fill="black", back_color="white").save(buf)
    return buf.getvalue()


def read_qr_from_image(uploaded_file):
    file_bytes = np.asarray(bytearray(uploaded_file.read()), dtype=np.uint8)
    opencv_image = cv2.imdecode(file_bytes, 1)
    if opencv_image is None:
        return None
    data, _, _ = cv2.QRCodeDetector().detectAndDecode(opencv_image)
    return data


# ==========================================
# UI & LOGIC
# ==========================================
if "andi_keys" not in st.session_state:
    st.session_state.andi_keys = None

# Init Blockchain
try:
    bc = get_blockchain()
    db_status = "🟢 Cloud Database: Connected"
except Exception as e:
    bc = None
    db_status = "🔴 Cloud Database: Error"
    st.error(f"Koneksi Database Gagal: {e}")

# Sidebar
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=100)
    st.title("🛡️ SecureAccess")
    st.markdown("**Sistem Kontrol Akses Terdesentralisasi**")
    st.divider()
    st.success(db_status)
    st.caption("© 2025 Marcel Gebagge")

st.title("🔐 Secure Access System Dashboard")
tab1, tab2, tab3 = st.tabs([
    "📱 Registrasi (QR)",
    "📷 Scan Akses",
    "📊 Monitoring & Log",
])

# TAB 1: REGISTRASI
with tab1:
    st.header("1. Buat Identitas Digital")
    if st.button("Generate ID Baru", type="primary"):
        priv, pub = KeyManager.generate_keys()
        st.session_state.andi_keys = (priv, pub)
        st.session_state.qr_download = generate_qr_image(priv.to_string().hex())
        st.toast("Identitas berhasil dibuat!", icon="✅")

    if st.session_state.andi_keys:
        st.image(st.session_state.qr_download, width=200)
        st.download_button(
            "⬇️ Download QR",
            st.session_state.qr_download,
            "andi_access_key.png",
            "image/png",
        )

# TAB 2: LOGIN
with tab2:
    st.header("2. Simulasi Pintu Masuk")
    req_msg = st.text_input("Tujuan Akses", "Buka Pintu Server")
    up_file = st.file_uploader("Upload Kartu QR", type=["png", "jpg"])

    if up_file and bc:
        try:
            hex_key = read_qr_from_image(up_file)
            if hex_key:
                st.success("QR Terbaca.")
                c1, c2 = st.columns(2)
                with c1:
                    if st.button("🚀 Proses Login"):
                        from ecdsa import SigningKey, SECP256k1

                        priv = SigningKey.from_string(
                            bytes.fromhex(hex_key), curve=SECP256k1
                        )
                        pub = priv.verifying_key
                        uid = KeyManager.get_public_key_string(pub)[:20] + "..."
                        sig = DigitalSignature.sign_data(priv, req_msg)

                        if DigitalSignature.verify_signature(pub, req_msg, sig):
                            st.balloons()
                            st.success(f"AKSES DITERIMA! User: {uid}")
                            bc.add_log(uid, req_msg, "GRANTED_QR_AUTH")
                            send_telegram_alert(f"✅ *ACCESS GRANTED*\nUser: `{uid}`")
                        else:
                            st.error("Signature Invalid.")
                with c2:
                    if st.button("🔴 Serangan Hacker"):
                        st.error("AKSES DITOLAK!")
                        bc.add_log("Unknown", req_msg, "DENIED")
                        send_telegram_alert("⚠️ *INTRUSION ALERT*\nStatus: DENIED")
            else:
                st.warning("QR Invalid.")
        except Exception as e:
            st.error(f"Error: {e}")

# TAB 3: MONITORING (SAFE LOOP)
with tab3:
    st.header("3. Blockchain Ledger")
    if st.button("🔄 Refresh Data") and bc:
        bc.load_chain()

    if bc:
        # Loop aman untuk menghindari Crash pada Genesis Block
        total_blok = len(bc.chain)
        sukses = 0
        gagal = 0
        data_list = []

        for b in bc.chain:
            # Logic aman: Cek tipe data sebelum akses key
            if isinstance(b.data, dict):
                status_str = str(b.data.get("status", ""))
                user_val = b.data.get("user", "System")
                action_val = b.data.get("action", "N/A")
                status_val = b.data.get("status", "-")
            else:
                # Fallback untuk Genesis Block (yang datanya string)
                status_str = ""
                user_val = "SYSTEM (Genesis)"
                action_val = "Init"
                status_val = str(b.data)

            if "GRANTED" in status_str:
                sukses += 1
            if "DENIED" in status_str:
                gagal += 1

            data_list.append(
                {
                    "No": b.index,
                    "Waktu": b.timestamp,
                    "User": user_val,
                    "Aktivitas": action_val,
                    "Status": status_val,
                    "Hash": b.hash,
                }
            )

        m1, m2, m3 = st.columns(3)
        m1.metric("Total Blok", total_blok)
        m2.metric("Akses Sukses", sukses)
        m3.metric("Percobaan Ilegal", gagal)

        st.dataframe(pd.DataFrame(data_list), use_container_width=True, hide_index=True)

        if bc.is_chain_valid(verbose=False):
            st.success("✅ SYSTEM INTEGRITY: SECURE")
        else:
            st.error("❌ SYSTEM INTEGRITY: COMPROMISED")

        with st.expander("⚠️ Zona Admin"):
            if st.button("🚨 Lakukan Tampering"):
                if len(bc.chain) > 1:
                    target = bc.chain[-1]
                    if isinstance(target.data, dict):
                        target.data["status"] = "GRANTED_FORCED"
                    else:
                        target.data = "CORRUPTED"
                    if not bc.is_chain_valid():
                        bc.report_security_status(
                            False, f"Tampering Block #{target.index}"
                        )
                        send_telegram_alert("🚨 *CRITICAL ALERT*\nTampering Detected!")
                        st.error("Tampering Berhasil.")
