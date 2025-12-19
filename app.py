import streamlit as st
import pandas as pd
import cv2
import numpy as np
import qrcode
import requests
from io import BytesIO
from security.keys import KeyManager
from security.signature import DigitalSignature
from blockchain.chain import Blockchain

# ==========================================
# KONFIGURASI TELEGRAM (SUDAH TERISI)
# ==========================================
TELEGRAM_BOT_TOKEN = "8239544189:AAGDctUZ7CF3b1fhVMcqEYGwRebo0mp5lJI"
TELEGRAM_CHAT_ID = "1839441766"

# ==========================================
# KONFIGURASI HALAMAN
# ==========================================
st.set_page_config(
    page_title="Secure Access Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Hilangkan Menu Bawaan
st.markdown("""
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            header {visibility: hidden;}
            </style>
            """, unsafe_allow_html=True)

# ==========================================
# FUNGSI BANTUAN
# ==========================================

@st.cache_resource
def get_blockchain():
    return Blockchain()

def send_telegram_alert(message):
    if "MASUKKAN" in TELEGRAM_BOT_TOKEN: return 
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
    try: requests.post(url, json=payload)
    except Exception: pass

def generate_qr_image(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    buf = BytesIO()
    qr.make_image(fill='black', back_color='white').save(buf)
    return buf.getvalue()

def read_qr_from_image(uploaded_file):
    file_bytes = np.asarray(bytearray(uploaded_file.read()), dtype=np.uint8)
    opencv_image = cv2.imdecode(file_bytes, 1)
    data, _, _ = cv2.QRCodeDetector().detectAndDecode(opencv_image)
    return data

# ==========================================
# SIDEBAR
# ==========================================
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=100)
    st.title("🛡️ SecureAccess")
    st.markdown("**Sistem Kontrol Akses Terdesentralisasi**\nBlockchain & IoT Notifikasi.")
    st.divider()
    st.success("🟢 Cloud Database: Connected")
    st.success("🟢 Bot Telegram: Active")
    st.caption("© 2025 Marcel Gebagge - Skripsi Teknik")

# ==========================================
# LOGIKA UTAMA
# ==========================================

if 'andi_keys' not in st.session_state:
    st.session_state.andi_keys = None

bc = get_blockchain()

st.title("🔐 Secure Access System Dashboard")
tab1, tab2, tab3 = st.tabs(["📱 Registrasi (QR)", "📷 Scan Akses", "📊 Monitoring & Log"])

# === TAB 1: REGISTRASI ===
with tab1:
    st.header("1. Buat Identitas Digital")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Generate ID Baru (Andi)", type="primary"):
            priv, pub = KeyManager.generate_keys()
            st.session_state.andi_keys = (priv, pub)
            st.session_state.qr_download = generate_qr_image(priv.to_string().hex())
            st.toast("Identitas berhasil dibuat!", icon="✅")
    with c2:
        if st.session_state.andi_keys:
            st.image(st.session_state.qr_download, width=200)
            st.download_button("⬇️ Download QR", st.session_state.qr_download, "andi_access_key.png", "image/png")

# === TAB 2: LOGIN ===
with tab2:
    st.header("2. Simulasi Pintu Masuk")
    c_in, c_act = st.columns([1, 2])
    with c_in:
        req_msg = st.text_input("Tujuan Akses", "Buka Pintu Server")
        up_file = st.file_uploader("Upload Kartu QR", type=['png', 'jpg'])

    with c_act:
        if up_file:
            try:
                hex_key = read_qr_from_image(up_file)
                if hex_key:
                    st.success("QR Terbaca.")
                    b1, b2 = st.columns(2)
                    with b1:
                        if st.button("🚀 Proses Login"):
                            from ecdsa import SigningKey, SECP256k1
                            priv = SigningKey.from_string(bytes.fromhex(hex_key), curve=SECP256k1)
                            pub = priv.verifying_key
                            uid = KeyManager.get_public_key_string(pub)[:20] + "..."
                            sig = DigitalSignature.sign_data(priv, req_msg)
                            
                            if DigitalSignature.verify_signature(pub, req_msg, sig):
                                st.balloons()
                                st.success(f"AKSES DITERIMA!\nUser: {uid}")
                                bc.add_log(uid, req_msg, "GRANTED_QR_AUTH")
                                send_telegram_alert(f"✅ *ACCESS GRANTED*\nUser: `{uid}`")
                            else: st.error("Signature Invalid.")
                    with b2:
                        if st.button("🔴 Serangan Hacker"):
                            st.error("AKSES DITOLAK!")
                            bc.add_log("Unknown", req_msg, "DENIED")
                            send_telegram_alert(f"⚠️ *INTRUSION ALERT*\nStatus: DENIED")
                else: st.warning("QR Invalid.")
            except Exception as e: st.error(f"Error: {e}")

# === TAB 3: MONITORING (FIXED CRASH) ===
with tab3:
    st.header("3. Blockchain Ledger")
    
    if st.button("🔄 Refresh Data"):
        bc.load_chain()
        st.toast("Data diperbarui")

    # --- PERBAIKAN LOGIKA METRICS (SAFE LOOP) ---
    # Kita tidak pakai sum() generator lagi, tapi pakai loop biasa agar aman
    total_blok = len(bc.chain)
    sukses = 0
    gagal = 0
    
    for b in bc.chain:
        # Cek apakah data berupa Dictionary?
        if isinstance(b.data, dict):
            status = str(b.data.get('status', ''))
            if "GRANTED" in status:
                sukses += 1
            elif "DENIED" in status:
                gagal += 1
        # Jika bukan dict (misal Genesis Block string), kita abaikan penghitungan statusnya
    
    m1, m2, m3 = st.columns(3)
    m1.metric("Total Blok", total_blok)
    m2.metric("Akses Sukses", sukses)
    m3.metric("Percobaan Ilegal", gagal, delta_color="inverse")
    st.divider()

    # --- TABEL DATA (SAFE RENDERING) ---
    if len(bc.chain) > 0:
        data_list = []
        for b in bc.chain:
            # Cek tipe data lagi untuk tabel
            if isinstance(b.data, dict):
                u_val = b.data.get('user', 'System')
                a_val = b.data.get('action', 'N/A')
                s_val = b.data.get('status', '-')
            else:
                # Fallback jika data cuma string (Genesis Block)
                u_val = "SYSTEM (Genesis)"
                a_val = "Init"
                s_val = str(b.data)

            data_list.append({
                "No": b.index,
                "Waktu": b.timestamp,
                "User": u_val,
                "Aktivitas": a_val,
                "Status": s_val,
                "Hash": b.hash
            })
        
        df = pd.DataFrame(data_list)
        st.dataframe(df, use_container_width=True, hide_index=True)

        st.divider()
        if bc.is_chain_valid(verbose=False):
            st.success("✅ SYSTEM INTEGRITY: SECURE")
        else:
            st.error("❌ SYSTEM INTEGRITY: COMPROMISED")

    # --- TAMPERING ---
    with st.expander("⚠️ Zona Admin"):
        if st.button("🚨 Lakukan Tampering"):
            if len(bc.chain) > 1:
                target = bc.chain[-1]
                if isinstance(target.data, dict): target.data['status'] = "GRANTED_FORCED"
                else: target.data = "CORRUPTED"
                
                if not bc.is_chain_valid():
                    bc.report_security_status(False, f"Tampering Block #{target.index}")
                    send_telegram_alert(f"🚨 *CRITICAL ALERT*\nTampering Detected!")
                    st.error("Tampering Berhasil.")
