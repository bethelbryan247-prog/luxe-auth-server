import { Router, type IRouter } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

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

router.get("/", (_req, res) => {
  res.json({ message: "LUXE Auth Server Running" });
});

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
