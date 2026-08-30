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

// ===== SUPER ADMIN CONFIG =====
const SUPER_ADMIN_EMAIL = 'bethelbryan247@gmail.com';
const SUPER_ADMIN_NAME = 'bethelbryan';
const SUPER_ADMIN_PASSWORD = '193720469780';

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// ===== USER MODEL =====
const UserSchema = new mongoose.Schema({
  name: String,
  firstName: { type: String, default: '' },
  lastName: { type: String, default: '' },
  username: { type: String, default: '' },
  email: { type: String, unique: true },
  password: String,
  phone: { type: String, default: '' },
  address: { type: String, default: '' },
  state: { type: String, default: '' },
  role: { type: String, default: 'customer' },
  isVip: { type: Boolean, default: false },
  isSuperAdmin: { type: Boolean, default: false },
  delivery: {
    phone: { type: String, default: '' },
    address: { type: String, default: '' },
    city: { type: String, default: '' },
    state: { type: String, default: '' },
    notes: { type: String, default: '' }
  },
  cart: { type: [mongoose.Schema.Types.Mixed], default: [] },
  orders: { type: [mongoose.Schema.Types.Mixed], default: [] },
  joinDate: { type: String, default: '' }
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
  isFeatured: { type: Boolean, default: false },
  status: { type: String, default: 'published' },
  createdAt: { type: Date, default: Date.now }
});
const Product = mongoose.model('Product', ProductSchema);

// ===== SEED SUPER ADMIN =====
const existingNewAdmin = await User.findOne({ email: SUPER_ADMIN_EMAIL });
const existingOldAdmin = await User.findOne({ email: 'bethelbryan1937@gmail.com' });

if (existingNewAdmin) {
  existingNewAdmin.name = SUPER_ADMIN_NAME;
  existingNewAdmin.role = 'admin';
  existingNewAdmin.isSuperAdmin = true;
  existingNewAdmin.password = await bcrypt.hash(SUPER_ADMIN_PASSWORD, 10);
  await existingNewAdmin.save();
  console.log('Super admin updated');
} else if (existingOldAdmin) {
  existingOldAdmin.name = SUPER_ADMIN_NAME;
  existingOldAdmin.email = SUPER_ADMIN_EMAIL;
  existingOldAdmin.role = 'admin';
  existingOldAdmin.isSuperAdmin = true;
  existingOldAdmin.password = await bcrypt.hash(SUPER_ADMIN_PASSWORD, 10);
  await existingOldAdmin.save();
  console.log('Old admin converted to super admin');
} else {
  const hashed = await bcrypt.hash(SUPER_ADMIN_PASSWORD, 10);
  await User.create({ name: SUPER_ADMIN_NAME, email: SUPER_ADMIN_EMAIL, password: hashed, role: 'admin', isSuperAdmin: true });
  console.log('Super admin created');
}

// ===== AUTH MIDDLEWARE =====
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'luxe_secret');
    req.userId = decoded.id;
    req.userRole = decoded.role;
    req.userEmail = decoded.email;
    req.isSuperAdmin = decoded.email === SUPER_ADMIN_EMAIL || decoded.isSuperAdmin === true;
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

// ===== CHECK EMAIL (for login/register email indicator) =====
app.post('/api/check-email', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    res.json({ exists: !!user });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password, remember } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: 'Invalid credentials' });
  const expiry = remember ? '7d' : '24h';
  const token = jwt.sign(
    { id: user._id, role: user.role, email: user.email, isSuperAdmin: user.isSuperAdmin || user.email === SUPER_ADMIN_EMAIL },
    process.env.JWT_SECRET || 'luxe_secret',
    { expiresIn: expiry }
  );
  res.json({
    message: 'Login successful',
    token,
    user: {
      id: user._id, name: user.name,
      firstName: user.firstName || '', lastName: user.lastName || '',
      username: user.username || user.name || '',
      email: user.email, phone: user.phone || '',
      address: user.address || '', state: user.state || '',
      role: user.role,
      isSuperAdmin: user.isSuperAdmin || user.email === SUPER_ADMIN_EMAIL,
      isVip: user.isVip
    }
  });
});

// ===== OTP SYSTEM =====
const otpStore = new Map();
const resend = new Resend(process.env.RESEND_API_KEY);

app.post('/api/send-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore.set(email, { otp, expires: Date.now() + 5 * 60 * 1000 });
  try {
    const info = await resend.emails.send({
      from: 'LUXE <onboarding@resend.dev>',
      to: email,
      subject: 'LUXE – Your OTP Code',
      html: `<h2>Welcome to LUXE</h2><p>Your verification code is:</p><h1 style="letter-spacing:5px;">${otp}</h1><p>This code expires in 5 minutes.</p>`
    });
    res.json({ message: 'OTP sent' });
  } catch (err) {
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
app.get('/api/products', async (req, res) => {
  try {
    const { world, showAll } = req.query;
    const filter = {};
    if (world) filter.world = world;

    if (showAll === 'true') {
      let isSuperAdmin = false;
      const token = req.headers.authorization?.split(' ')[1];
      if (token) {
        try {
          const decoded = jwt.verify(token, process.env.JWT_SECRET || 'luxe_secret');
          isSuperAdmin = decoded.email === SUPER_ADMIN_EMAIL || decoded.isSuperAdmin === true;
        } catch (e) {}
      }
      if (!isSuperAdmin) filter.status = { $ne: 'hidden' };
    } else {
      let isVip = false;
      const token = req.headers.authorization?.split(' ')[1];
      if (token) {
        try {
          const decoded = jwt.verify(token, process.env.JWT_SECRET || 'luxe_secret');
          const user = await User.findById(decoded.id);
          isVip = user && user.isVip;
        } catch (e) {}
      }
      if (isVip) {
        filter.status = { $in: ['published', 'out_of_stock', 'hidden'] };
      } else {
        filter.status = { $in: ['published', 'out_of_stock'] };
      }
    }

    const products = await Product.find(filter);
    res.json({ products });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json({ product });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch product' });
  }
});

app.post('/api/products', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    if (req.body.status === 'hidden' && !req.isSuperAdmin) {
      return res.status(403).json({ error: 'Only the super admin can set products to hidden' });
    }
    const product = await Product.create(req.body);
    res.status(201).json({ message: 'Product created', product });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create product' });
  }
});

app.put('/api/products/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    if (req.body.status === 'hidden' && !req.isSuperAdmin) {
      return res.status(403).json({ error: 'Only the super admin can set products to hidden' });
    }
    const product = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json({ message: 'Product updated', product });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update product' });
  }
});

app.delete('/api/products/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json({ message: 'Product deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

// ===== CUSTOMER ENDPOINTS =====
app.get('/api/customers', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    if (req.isSuperAdmin) {
      const users = await User.find({}, { password: 0 });
      res.json({ customers: users });
    } else {
      const users = await User.find({ role: 'customer' }, { password: 0 });
      res.json({ customers: users });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

app.get('/api/customers/:email', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.params.email }, { password: 0 });
    if (!user) return res.status(404).json({ error: 'Customer not found' });
    if (!req.isSuperAdmin && user.role === 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    res.json({ customer: user });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch customer' });
  }
});

// ===== ORDER ENDPOINTS =====
app.get('/api/orders', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await User.find({ 'orders.0': { $exists: true } }, { password: 0 });
    const orders = [];
    users.forEach(u => {
      (u.orders || []).forEach(o => {
        orders.push({ ...o, customerName: u.name, customerEmail: u.email });
      });
    });
    res.json({ orders });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

app.put('/api/orders/:orderId/status', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { orderId } = req.params;
    const { status, email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });
    const order = user.orders.find(o => o.id === orderId);
    if (!order) return res.status(404).json({ error: 'Order not found' });
    order.status = status;
    await user.save();
    res.json({ message: 'Order status updated', order });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

// ===== ADMIN ENDPOINTS =====
app.post('/api/admin/promote', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    if (!req.isSuperAdmin) {
      return res.status(403).json({ error: 'Only the super admin can promote users' });
    }
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });
    if (email === SUPER_ADMIN_EMAIL) return res.status(400).json({ error: 'This user is already the super admin' });
    const user = await User.findOneAndUpdate({ email }, { role: 'admin' }, { new: true });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User promoted to admin', user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: 'Failed to promote user' });
  }
});

app.post('/api/admin/demote', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    if (!req.isSuperAdmin) {
      return res.status(403).json({ error: 'Only the super admin can demote users' });
    }
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });
    if (email === SUPER_ADMIN_EMAIL) return res.status(400).json({ error: 'Cannot demote the original super admin' });
    const user = await User.findOneAndUpdate({ email }, { role: 'customer', isSuperAdmin: false }, { new: true });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'Admin demoted to customer', user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: 'Failed to demote user' });
  }
});

// ===== VIP MANAGEMENT (super admin only) =====
app.put('/api/customers/:email/vip', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    if (!req.isSuperAdmin) {
      return res.status(403).json({ error: 'Only the super admin can manage VIP status' });
    }
    const { isVip } = req.body;
    const user = await User.findOneAndUpdate(
      { email: req.params.email },
      { isVip: isVip },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'VIP status updated', customer: { email: user.email, isVip: user.isVip } });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update VIP status' });
  }
});

// ===== SUPER ADMIN PROMOTION (super admin only) =====
app.post('/api/admin/promote-super', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    if (!req.isSuperAdmin) {
      return res.status(403).json({ error: 'Only the super admin can promote to super admin' });
    }
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });
    if (email === SUPER_ADMIN_EMAIL) return res.status(400).json({ error: 'This user is already the super admin' });
    const user = await User.findOneAndUpdate(
      { email },
      { isSuperAdmin: true, role: 'admin' },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User promoted to super admin', user: { id: user._id, name: user.name, email: user.email, isSuperAdmin: user.isSuperAdmin } });
  } catch (err) {
    res.status(500).json({ error: 'Failed to promote to super admin' });
  }
});

app.post('/api/admin/demote-super', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    if (!req.isSuperAdmin) {
      return res.status(403).json({ error: 'Only the super admin can demote super admins' });
    }
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });
    if (email === SUPER_ADMIN_EMAIL) return res.status(400).json({ error: 'Cannot demote the original super admin' });
    const user = await User.findOneAndUpdate(
      { email },
      { isSuperAdmin: false },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'Super admin demoted to admin', user: { id: user._id, name: user.name, email: user.email, isSuperAdmin: user.isSuperAdmin } });
  } catch (err) {
    res.status(500).json({ error: 'Failed to demote super admin' });
  }
});

// ===== PROFILE ENDPOINTS =====
app.get('/api/auth/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId, { password: 0 });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      user: {
        id: user._id, name: user.name,
        firstName: user.firstName || '', lastName: user.lastName || '',
        username: user.username || user.name || '',
        email: user.email, phone: user.phone || '',
        address: user.address || '', state: user.state || '',
        role: user.role,
        isSuperAdmin: user.isSuperAdmin || user.email === SUPER_ADMIN_EMAIL,
        isVip: user.isVip
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

app.put('/api/auth/update-profile', authMiddleware, async (req, res) => {
  try {
    const { firstName, lastName, username, phone, address, state } = req.body;
    if (!firstName?.trim()) return res.status(400).json({ error: 'First name is required' });
    if (!lastName?.trim()) return res.status(400).json({ error: 'Last name is required' });
    if (!username?.trim()) return res.status(400).json({ error: 'Username is required' });
    if (!phone?.trim()) return res.status(400).json({ error: 'Phone number is required' });
    if (!address?.trim()) return res.status(400).json({ error: 'Address is required' });
    if (!state?.trim()) return res.status(400).json({ error: 'State is required' });

    const existing = await User.findOne({ username: username.trim(), _id: { $ne: req.userId } });
    if (existing) return res.status(400).json({ error: 'Username is already taken' });

    const fullName = firstName.trim() + ' ' + lastName.trim();
    const user = await User.findByIdAndUpdate(
      req.userId,
      {
        firstName: firstName.trim(),
        lastName: lastName.trim(),
        username: username.trim(),
        name: fullName,
        phone: phone.trim(),
        address: address.trim(),
        state: state.trim()
      },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        username: user.username,
        name: user.name,
        email: user.email,
        phone: user.phone,
        address: user.address,
        state: user.state,
        role: user.role,
        isSuperAdmin: user.isSuperAdmin || user.email === SUPER_ADMIN_EMAIL
      }
    });
  } catch (err)