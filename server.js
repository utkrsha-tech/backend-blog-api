const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = 'utkrsha_local_dev_secret';

app.use(cors());
app.use(express.json());

const users = [];
const blogs = [
  {
    id: 'blg_101',
    title: 'Setting Up My First Express.js Server & REST Routes',
    category: 'Backend',
    tags: ['nodejs', 'express', 'rest-api'],
    content: 'Testing out my REST API endpoints for user authentication and creating blog posts.',
    author: 'Utkrsha',
    createdAt: new Date().toISOString()
  }
];

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function createToken(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64');
  const signature = crypto.createHmac('sha256', SECRET_KEY).update(encoded).digest('hex');
  return `${encoded}.${signature}`;
}

function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Please log in first.' });

  const [encoded, signature] = token.split('.');
  const validSig = crypto.createHmac('sha256', SECRET_KEY).update(encoded).digest('hex');
  if (signature !== validSig) return res.status(403).json({ success: false, message: 'Invalid session token.' });

  req.user = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
  next();
}

app.post('/api/auth/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ success: false, message: 'All fields are required.' });

  if (users.find(u => u.email === email.toLowerCase())) {
    return res.status(409).json({ success: false, message: 'Email already registered.' });
  }

  const newUser = { id: 'usr_' + Date.now(), name, email: email.toLowerCase(), passwordHash: hashPassword(password) };
  users.push(newUser);
  const token = createToken({ id: newUser.id, name: newUser.name, email: newUser.email });

  res.status(201).json({ success: true, token, user: { id: newUser.id, name: newUser.name, email: newUser.email } });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email?.toLowerCase());
  if (!user || user.passwordHash !== hashPassword(password)) {
    return res.status(401).json({ success: false, message: 'Invalid email or password.' });
  }

  const token = createToken({ id: user.id, name: user.name, email: user.email });
  res.status(200).json({ success: true, token, user: { id: user.id, name: user.name, email: user.email } });
});

app.get('/api/blogs', (req, res) => {
  res.status(200).json({ success: true, count: blogs.length, blogs });
});

app.post('/api/blogs', requireAuth, (req, res) => {
  const { title, category, tags, content } = req.body;
  if (!title || !content) return res.status(400).json({ success: false, message: 'Title and content required.' });

  const post = {
    id: 'blg_' + Date.now(),
    title,
    category: category || 'Backend',
    tags: Array.isArray(tags) ? tags : [],
    content,
    author: req.user.name,
    createdAt: new Date().toISOString()
  };
  blogs.unshift(post);
  res.status(201).json({ success: true, post });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
