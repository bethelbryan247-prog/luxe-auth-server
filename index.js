import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

const users = [];

app.get('/', (req, res) => {
  res.json({ message: 'LUXE Auth Server Running' });
});

app.post('/api/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  const existing = users.find(u => u.email === email);
  if (existing) return res.status(400).json({ error: 'Email already registered' });
  const hashed = await bcrypt.hash(password, 10);
  const user = { id: users.length + 1, name, email, password: hashed, role: role || 'customer' };
  users.push(user);
  res.status(201).json({ message: 'User registered', user: { id: user.id, name, email, role: user.role } });
});

app.post('/api/login', async (req, res) => {
  const { email, password, remember } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: 'Invalid credentials' });
  const expiry = remember ? '7d' : '24h';
  const token = jwt.sign({ id: user.id, role: user.role }, 'luxe_secret', { expiresIn: expiry });
  res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`LUXE Auth Server running on port ${PORT}`);
});
