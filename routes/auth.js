import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import ActiveSession from '../models/ActiveSession.js';
import { extractDeviceInfo, isSessionActive } from '../utils/sessionUtils.js';

const router = express.Router();

// Signup
router.post('/signup', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Email already registered' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, role: role || 'user' });
    await user.save();
    const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ access_token: token, token_type: 'bearer' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Login with one-device restriction
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    // Check if user already has an active session
    const existingSession = await ActiveSession.findOne({ userId: user._id });
    
    if (existingSession && isSessionActive(existingSession)) {
      // User is already logged in on another device
      const deviceInfo = existingSession.deviceInfo;
      return res.status(403).json({
        message: 'User is already logged in on another device',
        deviceInfo: {
          browser: deviceInfo.browser,
          os: deviceInfo.os,
          deviceType: deviceInfo.deviceType,
          loginTime: deviceInfo.loginTime,
          ipAddress: deviceInfo.ipAddress
        },
        alreadyLoggedIn: true
      });
    }

    // Extract device information
    const deviceInfo = extractDeviceInfo(req);
    
    // Create or update active session
    await ActiveSession.findOneAndUpdate(
      { userId: user._id },
      {
        userId: user._id,
        deviceInfo: {
          ...deviceInfo,
          loginTime: new Date()
        },
        lastActivity: new Date()
      },
      { upsert: true, new: true }
    );

    // Generate token
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    
    res.json({
      access_token: token,
      token_type: 'bearer',
      message: 'Login successful'
    });

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Logout - remove active session
router.post('/logout', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ message: 'No token provided' });
    
    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Remove active session
    await ActiveSession.findOneAndDelete({ userId: decoded.id });
    
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Force logout from all devices (admin only)
router.post('/force-logout/:userId', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ message: 'No token provided' });
    
    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if user is admin
    const adminUser = await User.findById(decoded.id);
    if (!adminUser || adminUser.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required' });
    }
    
    const { userId } = req.params;
    
    // Remove active session for the specified user
    await ActiveSession.findOneAndDelete({ userId });
    
    res.json({ message: 'User force logged out successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get active sessions (admin only)
router.get('/active-sessions', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ message: 'No token provided' });
    
    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if user is admin
    const adminUser = await User.findById(decoded.id);
    if (!adminUser || adminUser.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required' });
    }
    
    const activeSessions = await ActiveSession.find()
      .populate('userId', 'name email role')
      .sort({ lastActivity: -1 });
    
    res.json(activeSessions);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

export default router; 