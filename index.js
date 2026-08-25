import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import { Resend } from 'resend';
import mongoose from 'mongoose';

const app = express();
app.use(cors());
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// ===== USER MODEL =====
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: 'customer' }
});
const User = mongoose.model('User', UserSchema);

// ===== PRODUCT MODEL =====
const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, default: 0 },
  world: { type: String, required: true },
  category: { type: String, default: 'uncategorized' },

  badge: { type: String, default: '—' },
  badgeType: { type: String, default: 'default' },
  description: { type: String, default: '—' },
  detail: { type: String, default: '' },
  type: { type: String, default: '' },

  images: { type: [String], default: [] },
  video: { type: [String], default: [] },

  sizes: { type: [mongoose.Schema.Types.Mixed], default: [] },
  colours: { type: [mongoose.Schema.Types.Mixed], default: [] },

  flavours: { type: [String], default: [] },
  shades: { type: [String], default: [] },
  specs: { type: [String], default: [] },
  options: { type: [String], default: [] },
  concentration: { type: [String], default: [] },

  sizePrices: { type: mongoose.Schema.Types.Mixed, default: null },
  notes: { type: mongoose.Schema.Types.Mixed, default: null },

  path: { type: String, default: '' },
  character: { type: String, default: '' },
  isNewArrival: { type: Boolean, default: false },

  createdAt: { type: Date, default: Date.now }
});
const Product = mongoose.model('Product', ProductSchema);

// ===== SEED ADMIN =====
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

// ===== AUTH MIDDLEWARE =====
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'luxe_secret');
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  if (req.userRole !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

// ===== BASIC ROUTE =====
app.get('/', (req, res) => {
  res.json({ message: 'LUXE Auth Server Running' });
});

// ===== AUTH ROUTES =====
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

// ===== OTP SYSTEM =====
const otpStore = new Map();
const resend = new Resend(process.env.RESEND_API_KEY);

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
    console.log('About to send email via Resend...');
    const info = await resend.emails.send({
      from: 'LUXE <onboarding@resend.dev>',
      to: email,
      subject: 'LUXE – Your OTP Code',
      html: `<h2>Welcome to LUXE</h2><p>Your verification code is:</p><h1 style="letter-spacing:5px;">${otp}</h1><p>This code expires in 5 minutes.</p>`
    });

    console.log('Email sent successfully:', JSON.stringify(info));
    res.json({ message: 'OTP sent' });
  } catch (err) {
    console.error('Email error full:', err);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

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

// ===== PRODUCT ENDPOINTS =====

// Get all products (optionally filter by world)
app.get('/api/products', async (req, res) => {
  try {
    const { world } = req.query;
    const filter = world ? { world } : {};
    const products = await Product.find(filter);
    res.json({ products });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json({ product });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch product' });
  }
});

// Create product (admin only)
app.post('/api/products', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const product = await Product.create(req.body);
    res.status(201).json({ message: 'Product created', product });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create product' });
  }
});

// Update product (admin only)
app.put('/api/products/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json({ message: 'Product updated', product });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update product' });
  }
});

// Delete product (admin only)
app.delete('/api/products/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json({ message: 'Product deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

// ===== ADMIN ENDPOINTS =====
app.post('/api/admin/promote', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOneAndUpdate(
      { email },
      { role: 'admin' },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User promoted to admin', user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: 'Failed to promote user' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`LUXE Auth Server running on port ${PORT}`);
});