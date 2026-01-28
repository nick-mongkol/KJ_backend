# OTP Server - Aplikasi Tukang PUPR Jogja

Server NodeJS untuk mengirim OTP via email menggunakan Gmail SMTP.

## Quick Start

1. Copy `.env.example` ke `.env` dan isi nilai-nilai yang diperlukan
2. Install dependencies:
   ```bash
   npm install
   ```
3. Jalankan server:
   ```bash
   npm start
   ```

## API Endpoints

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| GET | `/health` | - | Health check |
| POST | `/send-otp` | `{ "email": "user@example.com" }` | Kirim OTP ke email |
| POST | `/verify-otp` | `{ "email": "user@example.com", "otp": "123456" }` | Verifikasi OTP |

## Deploy ke Railway

1. Push folder ini ke GitHub repository
2. Login ke [Railway](https://railway.app)
3. New Project → Deploy from GitHub repo
4. Tambahkan Environment Variables:
   - `GMAIL_USER`
   - `GMAIL_APP_PASSWORD`
   - `SUPABASE_URL`
   - `SUPABASE_KEY`
5. Railway akan auto-deploy

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PORT` | Server port (Railway sets this automatically) |
| `GMAIL_USER` | Your Gmail address |
| `GMAIL_APP_PASSWORD` | Gmail App Password (16 characters) |
| `SUPABASE_URL` | Supabase project URL |
| `SUPABASE_KEY` | Supabase anon key |
