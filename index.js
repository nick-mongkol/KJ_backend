require('dotenv').config();
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Supabase client
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_KEY
);

// Gmail SMTP transporter with explicit settings
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // true for 465, false for 587
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD
    },
    tls: {
        rejectUnauthorized: false
    },
    connectionTimeout: 10000, // 10 seconds
    greetingTimeout: 10000,
    socketTimeout: 15000
});

// Generate 6-digit OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Send OTP endpoint
app.post('/send-otp', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ success: false, message: 'Email diperlukan' });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: 'Format email tidak valid' });
        }

        // Generate OTP and expiry (5 minutes from now)
        const otp = generateOTP();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

        // Invalidate any existing OTPs for this email
        await supabase
            .from('otp_codes')
            .update({ used: true })
            .eq('email', email)
            .eq('used', false);

        // Store OTP in database
        const { error: dbError } = await supabase
            .from('otp_codes')
            .insert({
                email: email,
                code: otp,
                expires_at: expiresAt.toISOString(),
                used: false
            });

        if (dbError) {
            console.error('Database error:', dbError);
            return res.status(500).json({ success: false, message: 'Gagal menyimpan OTP' });
        }

        // Send email
        const mailOptions = {
            from: `"Aplikasi Tukang PUPR" <${process.env.GMAIL_USER}>`,
            to: email,
            subject: 'Kode OTP Anda - Aplikasi Tukang PUPR Jogja',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #1976D2;">Aplikasi Tukang PUPR Jogja</h2>
          <p>Berikut adalah kode OTP Anda:</p>
          <div style="background-color: #f5f5f5; padding: 20px; text-align: center; border-radius: 8px;">
            <h1 style="font-size: 36px; letter-spacing: 8px; color: #333; margin: 0;">${otp}</h1>
          </div>
          <p style="color: #666; margin-top: 20px;">
            Kode ini berlaku selama <strong>5 menit</strong>.<br>
            Jangan bagikan kode ini kepada siapapun.
          </p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
          <p style="color: #999; font-size: 12px;">
            Jika Anda tidak meminta kode ini, abaikan email ini.
          </p>
        </div>
      `
        };

        await transporter.sendMail(mailOptions);

        console.log(`OTP sent to ${email}`);
        res.json({ success: true, message: 'Kode OTP telah dikirim ke email Anda' });

    } catch (error) {
        console.error('Error sending OTP:', error);
        res.status(500).json({ success: false, message: 'Gagal mengirim OTP: ' + error.message });
    }
});

// Verify OTP endpoint
app.post('/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({ success: false, message: 'Email dan OTP diperlukan' });
        }

        // Find valid OTP
        const { data: otpData, error: fetchError } = await supabase
            .from('otp_codes')
            .select('*')
            .eq('email', email)
            .eq('code', otp)
            .eq('used', false)
            .gte('expires_at', new Date().toISOString())
            .order('created_at', { ascending: false })
            .limit(1)
            .single();

        if (fetchError || !otpData) {
            return res.status(400).json({
                success: false,
                message: 'Kode OTP tidak valid atau sudah kadaluarsa'
            });
        }

        // Mark OTP as used
        await supabase
            .from('otp_codes')
            .update({ used: true })
            .eq('id', otpData.id);

        console.log(`OTP verified for ${email}`);
        res.json({ success: true, message: 'OTP berhasil diverifikasi' });

    } catch (error) {
        console.error('Error verifying OTP:', error);
        res.status(500).json({ success: false, message: 'Gagal memverifikasi OTP' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 OTP Server running on port ${PORT}`);
    console.log(`📧 Gmail: ${process.env.GMAIL_USER}`);
    console.log(`🔗 Supabase: ${process.env.SUPABASE_URL}`);
});
