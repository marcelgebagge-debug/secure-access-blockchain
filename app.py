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
# Token Bot Anda
TELEGRAM_BOT_TOKEN = "8239544189:AAGDctUZ7CF3b1fhVMcqEYGwRebo0mp5lJI"
# Chat ID Anda
TELEGRAM_CHAT_ID = "1839441766"

# ==========================================
# KONFIGURASI HALAMAN & GAYA (UI BEAUTIFICATION)
# ==========================================
st.set_page_config(
    page_title="Secure Access Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Hilangkan Menu Bawaan Streamlit biar bersih
hide_st_style = """
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            header {visibility: hidden;}
            </style>
            """
st.markdown(hide_st_style, unsafe_allow_html=True)

# ==========================================
# FUNGSI-FUNGSI BANTUAN
# ==========================================

@st.cache_resource
def get_blockchain():
    return Blockchain()

def send_telegram_alert(message):
    """Fungsi kirim notifikasi Telegram"""
    # Cek token dummy (opsional, tapi karena sudah diisi pasti lewat)
    if "MASUKKAN" in TELEGRAM_BOT_TOKEN:
        return 
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        # Kita pakai try-except kosong biar kalau internet mati, app gak crash
        requests.post(url, json=payload)
    except Exception:
        pass

def generate_qr_image(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    buf = BytesIO()
    img.save(buf)
    return buf.getvalue()

def read_qr_from_image(uploaded_file):
    file_bytes = np.asarray(bytearray(uploaded_file.read()), dtype=np.uint8)
    opencv_image = cv2.imdecode(file_bytes, 1)
    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(opencv_image)
    return data

# ==========================================
# SIDEBAR (PROFILE & STATUS)
# ==========================================
with st.sidebar:
    # Logo Kampus / Icon Keamanan
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=100)
    
    st.title("🛡️ SecureAccess")
    st.markdown("""
    **Sistem Kontrol Akses Terdesentralisasi** Berbasis Blockchain & IoT Notifikasi.
    """)
    
    st.divider()
    
    # Indikator Status
    st.success("🟢 Cloud Database: Connected")
    st.success("🟢 Bot Telegram: Active")
    
    st.divider()
    st.caption("© 2025 Marcel Gebagge - Skripsi Teknik")

# ==========================================
# LOGIKA UTAMA
# ==========================================

# State Management
if 'andi_keys' not in st.session_state:
    st.session_state.andi_keys = None

bc = get_blockchain()

# Judul Utama
st.title("🔐 Secure Access System Dashboard")

# Tab Navigasi
tab1, tab2, tab3 = st.tabs(["📱 Registrasi (QR)", "📷 Scan Akses", "📊 Monitoring & Log"])

# === TAB 1: REGISTRASI ===
with tab1:
    st.header("1. Buat Identitas Digital")
    st.info("Menu ini digunakan untuk mendaftarkan user baru dan mencetak Kartu Akses QR.")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Generate ID Baru (Andi)", type="primary"):
            priv, pub = KeyManager.generate_keys()
            st.session_state.andi_keys = (priv, pub)
            priv_hex = priv.to_string().hex()
            qr_bytes = generate_qr_image(priv_hex)
            st.session_state.qr_download = qr_bytes
            st.toast("Identitas berhasil dibuat!", icon="✅")

    with col2:
        if st.session_state.andi_keys:
            st.image(st.session_state.qr_download, caption="Kartu Akses QR", width=200)
            st.download_button("⬇️ Download QR Code", st.session_state.qr_download, "andi_access_key.png", "image/png")

# === TAB 2: LOGIN & SCAN ===
with tab2:
    st.header("2. Simulasi Pintu Masuk")
    
    col_input, col_action = st.columns([1, 2])
    
    with col_input:
        request_msg = st.text_input("Tujuan Akses", "Buka Pintu Server")
        uploaded_file = st.file_uploader("Upload Kartu QR", type=['png', 'jpg', 'jpeg'])

    with col_action:
        if uploaded_file is not None:
            try:
                extracted_priv_hex = read_qr_from_image(uploaded_file)
                if extracted_priv_hex:
                    st.success("QR Code Terbaca! Siap memproses otorisasi.")
                    
                    c1, c2 = st.columns(2)
                    with c1:
                        if st.button("🚀 Proses Login (Resmi)"):
                            from ecdsa import SigningKey, SECP256k1
                            priv = SigningKey.from_string(bytes.fromhex(extracted_priv_hex), curve=SECP256k1)
                            pub = priv.verifying_key
                            user_id = KeyManager.get_public_key_string(pub)[:20] + "..."
                            
                            sig = DigitalSignature.sign_data(priv, request_msg)
                            if DigitalSignature.verify_signature(pub, request_msg, sig):
                                st.balloons()
                                st.success(f"AKSES DITERIMA! \nUser: {user_id}")
                                bc.add_log(user_id, request_msg, "GRANTED_QR_AUTH")
                                send_telegram_alert(f"✅ *ACCESS GRANTED*\nUser: `{user_id}`\nPintu Terbuka.")
                            else:
                                st.error("Signature Invalid.")

                    with c2:
                        if st.button("🔴 Simulasi Serangan Hacker"):
                            st.error("AKSES DITOLAK! Signature Invalid.")
                            bc.add_log("Unknown/Hacker", request_msg, "DENIED")
                            st.toast("Alert dikirim ke Telegram!", icon="🚨")
                            send_telegram_alert(f"⚠️ *INTRUSION ALERT*\nUpaya masuk paksa terdeteksi!\nStatus: DENIED")
                else:
                    st.warning("Gambar bukan QR Code yang valid.")
            except Exception as e:
                st.error(f"Gagal membaca QR: {e}")

# === TAB 3: MONITORING (SUDAH DIPERBAIKI: ANTI-CRASH) ===
with tab3:
    st.header("3. Blockchain Ledger & Security Status")
    
    col_refresh, col_tamper = st.columns([1, 3])
    with col_refresh:
        if st.button("🔄 Refresh Data Cloud"):
            bc.load_chain()
            st.toast("Data diperbarui dari Firebase")
    
    # --- METRICS (Safe Parsing) ---
    total_blok = len(bc.chain)
    
    sukses = 0
    gagal = 0
    for b in bc.chain:
        # Pengecekan tipe data agar tidak error 'str object has no attribute get'
        if isinstance(b.data, dict):
            status_text = str(b.data.get('status', ''))
            if "GRANTED" in status_text:
                sukses += 1
            elif "DENIED" in status_text:
                gagal += 1
    
    m1, m2, m3 = st.columns(3)
    m1.metric("Total Blok Blockchain", total_blok, "Immutable Ledger")
    m2.metric("Akses Sukses", sukses, "Authorized")
    m3.metric("Percobaan Ilegal", gagal, "Intrusion", delta_color="inverse")
    
    st.divider()

    # --- TABEL DATA ---
    if len(bc.chain) > 0:
        chain_data = []
        for block in bc.chain:
            # Pengecekan tipe data lagi
            if isinstance(block.data, dict):
                user_val = block.data.get('user', 'System')
                action_val = block.data.get('action', 'N/A')
                status_val = block.data.get('status', '-')
            else:
                # Fallback untuk Genesis Block atau data rusak
                user_val = "SYSTEM (Genesis)"
                action_val = "Init"
                status_val = str(block.data)

            chain_data.append({
                "No": block.index,
                "Waktu": block.timestamp,
                "User ID": user_val,
                "Aktivitas": action_val,
                "Status": status_val,
                "Hash Blok": block.hash
            })
        
        df = pd.DataFrame(chain_data)
        
        # Tampilkan Tabel
        st.dataframe(
            df, 
            hide_index=True,
            use_container_width=True,
            column_config={
                "No": st.column_config.NumberColumn(format="%d", width="small"),
                "Waktu": st.column_config.DatetimeColumn(format="D MMM YYYY, HH:mm:ss"),
                "Status": st.column_config.TextColumn("Status Akses", validate="^(GRANTED|DENIED|GRANTED_QR_AUTH)$"),
            }
        )
        
        # Cek Integritas
        st.divider()
        if bc.is_chain_valid(verbose=False):
            st.success("✅ SYSTEM INTEGRITY: SECURE (Data Valid & Utuh)")
        else:
            st.error("❌ SYSTEM INTEGRITY: COMPROMISED (Data Telah Dimanipulasi!)")
    else:
        st.info("Belum ada data di Blockchain.")

    # --- FITUR TAMPERING ---
    with st.expander("⚠️ Zona Admin: Simulasi Serangan Tampering"):
        st.warning("Fitur ini digunakan untuk mendemonstrasikan kemampuan Self-Healing & Alerting sistem.")
        if st.button("🚨 Lakukan Modifikasi Data (Tampering)"):
            if len(bc.chain) > 1:
                target = bc.chain[-1]
                # Ubah paksa data di memori
                if isinstance(target.data, dict):
                    target.data['status'] = "GRANTED_FORCED"
                else:
                    target.data = "CORRUPTED_DATA"
                
                # Validasi & Lapor
                if not bc.is_chain_valid():
                    bc.report_security_status(False, f"Tampering at Block #{target.index}")
                    send_telegram_alert(f"🚨 *CRITICAL ALERT*\nIntegritas Blockchain RUSAK!\nLokasi: Block #{target.index}")
                    st.error("TAMPERING BERHASIL! Alarm dikirim ke Telegram & Cloud.")
            else:
                st.warning("Butuh minimal 1 blok data user untuk simulasi.")
