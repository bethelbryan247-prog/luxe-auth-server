import { Router, type IRouter } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

const router: IRouter = Router();

const JWT_SECRET = "luxe_secret";

interface User {
  id: number;
  name: string;
  email: string;
  password: string;
  role: string;
}

const users: User[] = [];

// ===== OTP Storage (in memory) =====
const otpStore: Record<string, { code: string; expires: number }> = {};

// ===== Email Transporter =====
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER || "",
    pass: process.env.EMAIL_PASS || "",
  },
});

router.get("/", (_req, res) => {
  res.json({ message: "LUXE Auth Server Running" });
});

// ===== SEND OTP =====
router.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    res.status(400).json({ error: "Email is required" });
    return;
  }

  // Generate 6-digit code
  const code = Math.floor(100000 + Math.random() * 900000).toString();

  // Store code with 5-minute expiry
  otpStore[email] = {
    code,
    expires: Date.now() + 5 * 60 * 1000,
  };

  try {
    await transporter.sendMail({
      from: `"LUXE" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your LUXE Verification Code",
      html: `
        <div style="background:#0a0a0a;padding:40px 20px;font-family:'Montserrat',Arial,sans-serif;">
          <div style="max-width:400px;margin:0 auto;background:rgba(255,255,255,0.03);border:1px solid rgba(212,175,55,0.15);padding:40px 36px;">
            <h1 style="text-align:center;font-family:'Playfair Display',Georgia,serif;font-size:28px;color:#d4af37;letter-spacing:4px;margin-bottom:8px;">LUXE</h1>
            <div style="width:50px;height:1px;background:#d4af37;margin:0 auto 24px;"></div>
            <p style="color:#999;font-size:13px;text-align:center;letter-spacing:1px;margin-bottom:24px;">Verify your email address</p>
            <div style="text-align:center;margin:32px 0;">
              <p style="font-size:36px;color:#fff;letter-spacing:8px;font-weight:600;">${code}</p>
            </div>
            <p style="color:#555;font-size:12px;text-align:center;line-height:1.6;">Enter this code to complete your registration.<br>The code expires in 5 minutes.</p>
            <div style="margin-top:32px;padding-top:24px;border-top:1px solid rgba(255,255,255,0.06);">
              <p style="color:#333;font-size:11px;text-align:center;">© 2026 LUXE. All rights reserved.</p>
            </div>
          </div>
        </div>
      `,
    });

    res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("Email error:", err);
    res.status(500).json({ error: "Failed to send OTP email" });
  }
});

// ===== VERIFY OTP =====
router.post("/verify-otp", async (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    res.status(400).json({ error: "Email and code are required" });
    return;
  }

  const stored = otpStore[email];

  if (!stored) {
    res.status(400).json({ error: "No OTP was sent to this email" });
    return;
  }

  if (Date.now() > stored.expires) {
    delete otpStore[email];
    res.status(400).json({ error: "Code expired. Please request a new one." });
    return;
  }

  if (stored.code !== code) {
    res.status(400).json({ error: "Invalid verification code" });
    return;
  }

  // Code verified — clean up
  delete otpStore[email];

  res.json({ message: "Email verified successfully" });
});

// ===== REGISTER =====
router.post("/register", async (req, res) => {
  const { name, email, password, role } = req.body;
  const existing = users.find((u) => u.email === email);
  if (existing) {
    res.status(400).json({ error: "Email already registered" });
    return;
  }
  const hashed = await bcrypt.hash(password, 10);
  const user: User = {
    id: users.length + 1,
    name,
    email,
    password: hashed,
    role: role || "customer",
  };
  users.push(user);
  res.status(201).json({
    message: "User registered",
    user: { id: user.id, name, email, role: user.role },
  });
});

// ===== LOGIN =====
router.post("/login", async (req, res) => {
  const { email, password, remember } = req.body;
  const user = users.find((u) => u.email === email);
  if (!user) {
    res.status(400).json({ error: "Invalid credentials" });
    return;
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    res.status(400).json({ error: "Invalid credentials" });
    return;
  }
  const expiry = remember ? "7d" : "24h";
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
    expiresIn: expiry,
  });
  res.json({
    message: "Login successful",
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role },
  });
});

export default router;
