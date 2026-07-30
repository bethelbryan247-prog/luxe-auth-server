  import express from 'express';
  import bcrypt from 'bcryptjs';
  import jwt from 'jsonwebtoken';
  import cors from 'cors';
  import nodemailer from 'nodemailer';
  import mongoose from 'mongoose';

  const app = express();
  app.use(cors());
  const PORT = process.env.PORT || 3000;

  app.use(express.json());

  // Connect to MongoDB
  mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

  // User model
  const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    role: { type: String, default: 'customer' }
  });
  const User = mongoose.model('User', UserSchema);

  // Seed admin on startup
  const adminExists = await User.findOne({ email: 'bethelbryan1937@gmail.com' });
  if (!adminExists) {
    const hashed = await bcrypt.hash('LuxeAdmin2026', 10);
    await User.create({
      name: 'Admin',
      email: 'bethelbryan1937@gmail.com',
      password: hashed,
      role: 'admin'
    });
    console.log('Admin user created');
  }

  app.get('/', (req, res) => {
    res.json({ message: 'LUXE Auth Server Running' });
  });

  app.post('/api/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already registered' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashed, role: role || 'customer' });
    res.status(201).json({ message: 'User registered', user: { id: user._id, name, email, role: user.role } });
  });

  app.post('/api/login', async (req, res) => {
    const { email, password, remember } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });
    const expiry = remember ? '7d' : '24h';
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET || 'luxe_secret', { expiresIn: expiry });
    res.json({ message: 'Login successful', token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  });

    // ===== OTP System =====
  const otpStore = new Map();

  const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
    }
  });

  // Send OTP
app.post('/api/send-otp', async (req, res) => {
  console.log('SEND OTP route hit');
  const { email } = req.body;
  console.log('Email received:', email);

  if (!email) {
    console.log('No email provided');
    return res.status(400).json({ error: 'Email is required' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore.set(email, { otp, expires: Date.now() + 5 * 60 * 1000 });
  console.log('OTP generated');

  try {
    console.log('About to send email...');
    const info = await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'LUXE – Your OTP Code',
      html: `<h2>Welcome to LUXE</h2><p>Your verification code is:</p><h1 style="letter-spacing:5px;">${otp}</h1><p>This code expires in 5 minutes.</p>`
    });

    console.log('Email sent successfully:', info.response);
    res.json({ message: 'OTP sent' });
  } catch (err) {
    console.error('Email error full:', err);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Verify OTP
app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  const stored = otpStore.get(email);

  if (!stored) return res.status(400).json({ error: 'No OTP found. Request a new one.' });
  if (Date.now() > stored.expires) {
    otpStore.delete(email);
    return res.status(400).json({ error: 'OTP expired. Request a new one.' });
  }
  if (stored.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

  otpStore.delete(email);
  res.json({ message: 'OTP verified' });
});

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`LUXE Auth Server running on port ${PORT}`);
  }); 
