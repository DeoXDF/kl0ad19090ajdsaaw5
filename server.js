const express = require('express');
const cors = require('cors');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const USERS_FILE = './users.json';
const SECRET_KEY = 'zerotrace-secret-key'; // In production, use env var!

// Login route
app.post('/login', async (req, res) => {
  const { discordId, password } = req.body;

  if (!discordId || !password) {
    return res.status(400).json({ error: 'Discord ID and password required' });
  }

  if (!fs.existsSync(USERS_FILE)) {
    return res.status(400).json({ error: 'No users registered yet' });
  }

  const users = JSON.parse(fs.readFileSync(USERS_FILE));
  const user = users[discordId];

  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }

  const match = await bcrypt.compare(password, user.passwordHash);

  if (!match) {
    return res.status(401).json({ error: 'Incorrect password' });
  }

  // Create a JWT token
  const token = jwt.sign({ discordId }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ message: 'Login successful!', token, discordId });
});

// Route to get all users (protected)
app.get('/users', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  try {
    jwt.verify(token, SECRET_KEY); // Validate token
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }

  if (!fs.existsSync(USERS_FILE)) {
    return res.status(400).json({ error: 'No users registered yet' });
  }

  const users = JSON.parse(fs.readFileSync(USERS_FILE));

  const userList = Object.entries(users).map(([discordId, userData]) => ({
    discordId,
  }));

  res.json({ users: userList });
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
