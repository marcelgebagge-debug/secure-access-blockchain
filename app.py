import streamlit as st
import pandas as pd
import cv2
import numpy as np
import qrcode
import requests  # <--- Library baru untuk kirim pesan
from io import BytesIO
import json
import os
from security.keys import KeyManager
from security.signature import DigitalSignature
from blockchain.chain import Blockchain

# ==========================================
# KONFIGURASI TELEGRAM & FIREBASE
# ==========================================
# Kode Tambahan untuk Cloud Deployment
# Jika ada secrets 'firebase', maka buat file serviceAccountKey.json secara otomatis
try:
    if "firebase" in st.secrets:
        with open("serviceAccountKey.json", "w") as f:
            f.write(st.secrets["firebase"]["textkey"])
except Exception:
    pass  # Jika tidak ada secrets, lanjutkan (untuk lokal)

# Kalau di cloud pakai Secrets, kalau di lokal pakai variabel biasa
try:
    if "TELEGRAM_BOT_TOKEN" in st.secrets:
        TELEGRAM_BOT_TOKEN = st.secrets["TELEGRAM_BOT_TOKEN"]
        TELEGRAM_CHAT_ID = st.secrets["TELEGRAM_CHAT_ID"]
    else:
        # Fallback untuk lokal: gunakan nilai hardcoded
        TELEGRAM_BOT_TOKEN = "8239544189:AAGDctUZ7CF3b1fhVMcqEYGwRebo0mp5lJI"
        TELEGRAM_CHAT_ID = "1839441766"
except Exception:
    # Jika secrets tidak ada atau error, gunakan nilai default (untuk lokal)
    TELEGRAM_BOT_TOKEN = "8239544189:AAGDctUZ7CF3b1fhVMcqEYGwRebo0mp5lJI"
    TELEGRAM_CHAT_ID = "1839441766"


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

# --- HIDE STREAMLIT STYLE & CUSTOM CSS ---
hide_st_style = """
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            header {visibility: hidden;}
            
            /* Custom Styling untuk tampilan lebih menarik */
            .main {
                padding-top: 2rem;
            }
            
            h1 {
                color: #1f77b4;
                padding-bottom: 0.5rem;
                border-bottom: 3px solid #1f77b4;
            }
            
            h2 {
                color: #2c3e50;
                margin-top: 2rem;
            }
            
            h3 {
                color: #34495e;
            }
            
            .stButton>button {
                background-color: #1f77b4;
                color: white;
                border-radius: 8px;
                border: none;
                padding: 0.5rem 1.5rem;
                font-weight: 600;
                transition: all 0.3s;
            }
            
            .stButton>button:hover {
                background-color: #1565a0;
                transform: translateY(-2px);
                box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            }
            
            .stSuccess {
                background-color: #d4edda;
                border-left: 4px solid #28a745;
            }
            
            .stError {
                background-color: #f8d7da;
                border-left: 4px solid #dc3545;
            }
            
            .stInfo {
                background-color: #d1ecf1;
                border-left: 4px solid #17a2b8;
            }
            
            .metric-container {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 1rem;
                border-radius: 10px;
                color: white;
            }
            </style>
            """
st.markdown(hide_st_style, unsafe_allow_html=True)


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

# --- UI SIDEBAR ---
with st.sidebar:
    # Logo/Header
    st.markdown(
        "<div style='text-align: center; padding: 1rem 0;'>",
        unsafe_allow_html=True,
    )
    st.image(
        "https://cdn-icons-png.flaticon.com/512/2092/2092663.png",
        width=120,
    )
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("### 🔐 SecureAccess")
    st.markdown(
        "<p style='color: #666; font-size: 0.9rem;'>Sistem Kontrol Akses berbasis <strong>Blockchain</strong> & <strong>IoT</strong></p>",
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # Status Koneksi
    st.markdown("### 📡 Status Sistem")
    st.markdown(
        "<div style='background: #d4edda; padding: 0.5rem; border-radius: 5px; margin-bottom: 0.5rem;'>"
        "🟢 <strong>Cloud Database:</strong> Connected</div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<div style='background: #d4edda; padding: 0.5rem; border-radius: 5px;'>"
        "🟢 <strong>Bot Telegram:</strong> Active</div>",
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # Footer
    st.markdown(
        "<div style='text-align: center; color: #999; font-size: 0.85rem; padding-top: 1rem;'>"
        "© 2025 Marcel Gebagge<br>Skripsi Teknik</div>",
        unsafe_allow_html=True,
    )

# --- UI MAIN ---
st.title("🚨 Secure Access System: Blockchain & Real-time Alert")

tab1, tab2, tab3 = st.tabs(
    [
        "📱 Registrasi (QR)",
        "📷 Scan Akses",
        "🛡️ Admin & Monitoring",
    ]
)

# === TAB 1: REGISTRASI ===
with tab1:
    st.markdown("### 📱 Registrasi Identitas Digital")
    st.markdown(
        "<p style='color: #666; margin-bottom: 2rem;'>Generate kunci kriptografi dan QR Code untuk identitas digital pengguna</p>",
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns([1, 1], gap="large")
    with col1:
        st.markdown("#### 🔑 Generate Kunci")
        if st.button("Generate ID Baru (Andi)", use_container_width=True):
            priv, pub = KeyManager.generate_keys()
            st.session_state.andi_keys = (priv, pub)
            priv_hex = priv.to_string().hex()
            qr_bytes = generate_qr_image(priv_hex)
            st.session_state.qr_download = qr_bytes
            st.success("✅ Identitas Berhasil Dibuat!")

    with col2:
        st.markdown("#### 🎫 Kartu Akses QR")
        if st.session_state.andi_keys:
            st.image(
                st.session_state.qr_download,
                caption="Kartu Akses Digital Anda",
                width=250,
            )
            st.download_button(
                "⬇️ Download QR Code",
                st.session_state.qr_download,
                "andi_access_key.png",
                "image/png",
                use_container_width=True,
            )
        else:
            st.info("👆 Klik tombol di sebelah kiri untuk generate kunci")

# === TAB 2: LOGIN & SCAN ===
with tab2:
    st.markdown("### 📷 Simulasi Masuk dengan QR Code")
    st.markdown(
        "<p style='color: #666; margin-bottom: 2rem;'>Upload QR Code untuk autentikasi akses</p>",
        unsafe_allow_html=True,
    )

    col_input, col_info = st.columns([2, 1])
    with col_input:
        request_msg = st.text_input(
            "📍 Tujuan Akses", "Buka Pintu Server", help="Masukkan tujuan akses"
        )
        uploaded_file = st.file_uploader(
            "📤 Upload Kartu QR Anda",
            type=["png", "jpg", "jpeg"],
            help="Pilih file gambar QR Code yang sudah didownload",
        )

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
    st.markdown("### 🛡️ Security Dashboard (Real-time)")
    st.markdown(
        "<p style='color: #666; margin-bottom: 1rem;'>Monitor aktivitas akses dan integritas blockchain</p>",
        unsafe_allow_html=True,
    )

    col_refresh, _ = st.columns([1, 4])
    with col_refresh:
        if st.button("🔄 Refresh Data", use_container_width=True):
            bc.load_chain()
            st.rerun()

    # Dashboard Metrics
    st.markdown("#### 📊 Statistik Sistem")
    col1, col2, col3 = st.columns(3, gap="medium")

    with col1:
        st.metric("📦 Total Blok", len(bc.chain), delta="+1 Baru", delta_color="normal")

    sukses = sum(
        1
        for b in bc.chain
        if isinstance(b.data, dict)
        and "GRANTED" in str(b.data.get("status", ""))
    )
    gagal = sum(
        1
        for b in bc.chain
        if isinstance(b.data, dict) and "DENIED" in str(b.data.get("status", ""))
    )

    with col2:
        st.metric("✅ Akses Diterima", sukses, delta="User Valid", delta_color="normal")
    with col3:
        st.metric(
            "🚫 Percobaan Ilegal",
            gagal,
            delta="Intrusion",
            delta_color="inverse",
        )

    st.markdown("<br>", unsafe_allow_html=True)

    if len(bc.chain) > 0:
        chain_data = []
        for block in bc.chain:
            if isinstance(block.data, dict):
                chain_data.append(
                    {
                        "No": block.index,
                        "Waktu": block.timestamp,
                        "User ID": block.data.get("user", "System"),
                        "Aktivitas": block.data.get("action", "N/A"),
                        "Status": block.data.get("status", "-"),
                        "Hash Blok": block.hash,
                    }
                )
            else:
                # Genesis block dengan data string
                chain_data.append(
                    {
                        "No": block.index,
                        "Waktu": block.timestamp,
                        "User ID": "System",
                        "Aktivitas": "Genesis",
                        "Status": str(block.data),
                        "Hash Blok": block.hash,
                    }
                )

        df = pd.DataFrame(chain_data)

        st.markdown("#### 📋 Ledger Blockchain")
        st.dataframe(
            df,
            hide_index=True,
            use_container_width=True,
            column_config={
                "No": st.column_config.NumberColumn(
                    format="%d", width="small", label="No"
                ),
                "Waktu": st.column_config.TextColumn(
                    "Waktu",
                    help="Timestamp transaksi",
                ),
                "User ID": st.column_config.TextColumn(
                    "User ID",
                    width="medium",
                ),
                "Aktivitas": st.column_config.TextColumn(
                    "Aktivitas",
                    width="medium",
                ),
                "Status": st.column_config.TextColumn(
                    "Status",
                    help="Status otorisasi akses",
                ),
                "Hash Blok": st.column_config.TextColumn(
                    "Hash Blok",
                    width="large",
                    help="SHA-256 hash dari blok",
                ),
            },
        )

        st.markdown("<br>", unsafe_allow_html=True)

        # Status Integritas
        col_status, _ = st.columns([1, 3])
        with col_status:
            if bc.is_chain_valid(verbose=False):
                st.success("🔒 Status Sistem: AMAN ✅")
            else:
                st.error("⚠️ Status Sistem: BAHAYA / PERETASAN ❌")
    else:
        st.info("Belum ada data.")

    # FITUR TAMPERING DENGAN NOTIFIKASI
    st.markdown("---")
    st.markdown("#### ⚠️ Zona Bahaya (Admin Only)")
    st.warning(
        "⚠️ Fitur ini untuk simulasi serangan. Jangan digunakan di production!"
    )

    if st.button(
        "🚨 Lakukan Serangan Tampering Data!",
        use_container_width=True,
        type="primary",
    ):
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
