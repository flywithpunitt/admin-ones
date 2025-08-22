import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import User from '../models/User.js';

const router = express.Router();

// Middleware to verify JWT and check if user is admin
function adminMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });
  
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  
  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    
    try {
      const user = await User.findById(decoded.id);
      if (!user) return res.status(401).json({ message: 'User not found' });
      if (user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
      
      req.user = decoded;
      next();
    } catch (error) {
      return res.status(500).json({ message: 'Server error' });
    }
  });
}

// Get all users (admin only)
router.get('/users', adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Create new user (admin only)
router.post('/create-user', adminMiddleware, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      role: role || 'user'
    });

    const savedUser = await newUser.save();
    
    // Return user without password
    const { password: _, ...userWithoutPassword } = savedUser.toObject();
    res.status(201).json(userWithoutPassword);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Delete user (admin only)
router.delete('/users/:id', adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Don't allow admin to delete themselves
    if (id === req.user.id) {
      return res.status(400).json({ message: 'Cannot delete your own account' });
    }

    const deletedUser = await User.findByIdAndDelete(id);
    if (!deletedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

export default router; 