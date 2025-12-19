# Secure Access Control System (Blockchain & IoT) 🔐

Sistem keamanan terdesentralisasi yang menggabungkan Blockchain, Kriptografi, dan Notifikasi Real-time.

## 🚀 Fitur Utama
* **Blockchain Ledger:** Pencatatan log akses yang transparan & immutable.
* **Digital Signature (ECDSA):** Autentikasi berbasis kriptografi kurva eliptik.
* **QR Code Auth:** Login menggunakan kartu akses digital (QR).
* **Cloud Database:** Terintegrasi dengan Google Firebase.
* **Intrusion Detection System (IDS):** Notifikasi serangan real-time via Telegram Bot.

## 🛠️ Teknologi
* Python 3.9+
* Streamlit (Web Dashboard)
* Firebase Realtime Database
* OpenCV & qrcode

## 📦 Cara Menjalankan
1. Clone repository ini.
2. Install library: `pip install -r requirements.txt`
3. Masukkan file `serviceAccountKey.json` dari Firebase ke folder root.
4. Isi Token dan Chat ID Telegram di `app.py`.
5. Jalankan: `streamlit run app.py`.
