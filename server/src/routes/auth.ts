import { Router } from "express";
import bcrypt from "bcrypt";
import { pool } from "../db/pool.js";

export const authRouter = Router();

authRouter.post("/register", async (req, res) => {
  const { email, password, name } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string" || typeof name !== "string") {
    return res.status(400).json({ message: "email, password and name must be strings" });
  }
  if (name.length < 1 || name.length > 30) {
    return res.status(400).json({ message: "name must be 1-30 characters" });
  }

    if (password.length < 8) {
    return res.status(400).json({ message: "password must be at least 8 characters" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  await pool.execute(
    "INSERT INTO users(email, password_hash, name, role) VALUES (?, ?, ?, 'USER')",
    [email, passwordHash, name]
  );

  res.json({ message: "registered" });
});

authRouter.post("/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ message: "email and password must be strings" });
  }

  const [rows]: any = await pool.execute(
    `SELECT id, email, name, role, password_hash FROM users
     WHERE email = ?`,
    [email]
  );

  const row = rows[0];
if (!row || !(await bcrypt.compare(password, row.password_hash))) {
    return res.status(401).json({ message: `login failed: ${email} / ${password}` });
  }

    const user = {
    id: row.id,
    email: row.email,
    name: row.name,
    role: row.role
  };

  req.session.user = user;
  res.cookie("lastLoginUser", JSON.stringify(user), { httpOnly: false });
  res.json(user);
});

authRouter.get("/me", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "not logged in" });
  } 
    
  
  res.json(req.session.user);
});


authRouter.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ message: "logout" }));
});
