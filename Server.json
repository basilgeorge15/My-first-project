const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-change-this-in-production';
const PORT = process.env.PORT || 5000;

// ==========================================
// IN-MEMORY DATABASE (DEMO/TESTING)
// ==========================================
const users = [];   // { id, name, email, passwordHash, role }
const tickets = []; // { id, title, description, priority, status, createdBy }

// ==========================================
// AUTHENTICATION & ROLE MIDDLEWARE
// ==========================================

// Verify JWT Bearer Token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access denied. Token missing.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // Contains { id, email, role }
    next();
  } catch (err) {
    return res.status(403).json({ success: false, message: 'Invalid or expired token.' });
  }
};

// Role-Based Access Control
const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `Forbidden. Role '${req.user?.role}' is unauthorized.`
      });
    }
    next();
  };
};

// ==========================================
// AUTHENTICATION ROUTES
// ==========================================

// 1. User Registration
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ success: false, message: 'Name, email, and password required.' });
  }

  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    return res.status(400).json({ success: false, message: 'User already exists.' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const newUser = {
    id: users.length + 1,
    name,
    email,
    passwordHash,
    role: role || 'user' // Default roles: 'user', 'tech', or 'admin'
  };

  users.push(newUser);

  res.status(201).json({
    success: true,
    message: 'User registered successfully.',
    user: { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role }
  });
});

// 2. User Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(401).json({ success: false, message: 'Invalid email or password.' });
  }

  const isValidPassword = await bcrypt.compare(password, user.passwordHash);
  if (!isValidPassword) {
    return res.status(401).json({ success: false, message: 'Invalid email or password.' });
  }

  // Generate JWT Token
  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '8h' }
  );

  res.status(200).json({
    success: true,
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role }
  });
});

// ==========================================
// TICKET ROUTES (PROTECTED)
// ==========================================

// 3. Create Ticket (Any logged-in user)
app.post('/api/tickets', authenticateToken, (req, res) => {
  const { title, description, priority } = req.body;

  if (!title || !description) {
    return res.status(400).json({ success: false, message: 'Title and description required.' });
  }

  const newTicket = {
    id: tickets.length + 1,
    title,
    description,
    priority: priority || 'Medium',
    status: 'Open',
    createdBy: req.user.id,
    createdAt: new Date()
  };

  tickets.push(newTicket);
  res.status(201).json({ success: true, data: newTicket });
});

// 4. Get All Tickets (Any logged-in user)
app.get('/api/tickets', authenticateToken, (req, res) => {
  res.status(200).json({ success: true, count: tickets.length, data: tickets });
});

// 5. Update Ticket Status (Only 'tech' or 'admin' roles)
app.patch('/api/tickets/:id/status', authenticateToken, authorizeRoles('tech', 'admin'), (req, res) => {
  const ticketId = parseInt(req.params.id);
  const { status } = req.body;

  const ticket = tickets.find(t => t.id === ticketId);
  if (!ticket) {
    return res.status(404).json({ success: false, message: 'Ticket not found.' });
  }

  if (!['Open', 'In Progress', 'Resolved'].includes(status)) {
    return res.status(400).json({ success: false, message: 'Invalid status value.' });
  }

  ticket.status = status;
  res.status(200).json({ success: true, message: 'Status updated.', data: ticket });
});

// Health check endpoint
app.get('/', (req, res) => {
  res.send('Service Desk Express API is running!');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

