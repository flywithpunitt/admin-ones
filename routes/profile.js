import express from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import bcryptjs from 'bcryptjs';
import crypto from 'crypto';

const router = express.Router();

// Middleware to verify JWT and attach user to req
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

// Ensure ENCRYPTION_KEY is always 32 bytes
function getEncryptionKey() {
  let key = process.env.ENCRYPTION_KEY || 'default-secret-key-32-chars-long!!';
  if (key.length < 32) {
    key = key.padEnd(32, '0');
  } else if (key.length > 32) {
    key = key.slice(0, 32);
  }
  return key;
}

const IV_LENGTH = 16; // AES block size
const ALGORITHM = 'aes-256-cbc';

function encrypt(text) {
  if (!text) return '';
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = Buffer.from(getEncryptionKey(), 'utf8');

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedData) {
  if (!encryptedData) return '';
  try {
    const [ivHex, encryptedText] = encryptedData.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const key = Buffer.from(getEncryptionKey(), 'utf8');

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    return '';
  }
}

// Get current user's profile
router.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    // Don't send encrypted TradingView password in regular profile
    const userProfile = user.toObject();
    if (userProfile.tradingView && userProfile.tradingView.password) {
      userProfile.tradingView.password = '***';
    }
    
    res.json(userProfile);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Update current user's profile
router.put('/me', authMiddleware, async (req, res) => {
  try {
    const { name, email, password, aadhar, pan, phone, address, dob, tradingView } = req.body;
    const update = {};
    if (name) update.name = name;
    if (email) update.email = email;
    if (password) update.password = password;
    if (aadhar) update.aadhar = aadhar;
    if (pan) update.pan = pan;
    if (phone) update.phone = phone;
    if (address) update.address = address;
    if (dob) update.dob = dob;
    if (tradingView) {
      update.tradingView = {
        email: tradingView.email || '',
        password: tradingView.password ? encrypt(tradingView.password) : ''
      };
    }
    update.updatedAt = Date.now();
    const user = await User.findByIdAndUpdate(req.user.id, update, { new: true }).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    // Don't send encrypted password back
    const userProfile = user.toObject();
    if (userProfile.tradingView && userProfile.tradingView.password) {
      userProfile.tradingView.password = '***';
    }
    
    res.json(userProfile);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get decrypted TradingView credentials (for automation script)
router.get('/tradingview-credentials/decrypt', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }

    if (!user.tradingView || !user.tradingView.email || !user.tradingView.password) {
      return res.status(400).json({ msg: 'TradingView credentials not set' });
    }

    const decryptedPassword = decrypt(user.tradingView.password);
    
    res.json({
      email: user.tradingView.email,
      password: decryptedPassword
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server Error');
  }
});

// Save TradingView credentials (for the modal in frontend)
router.post('/tradingview-credentials', authMiddleware, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    
    // Encrypt password before saving
    const encryptedPassword = encrypt(password);
    
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { 
        tradingView: {
          email: email,
          password: encryptedPassword
        },
        updatedAt: Date.now()
      },
      { new: true }
    ).select('-password');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({ 
      message: 'TradingView credentials saved successfully',
      email: user.tradingView.email 
    });
  } catch (err) {
    console.error('Error saving TradingView credentials:', err);
    res.status(500).json({ message: err.message });
  }
});

// Check if user has TradingView credentials (for the frontend to decide whether to show modal)
router.get('/tradingview-credentials', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ hasCredentials: false });
    }

    const hasCredentials = !!(user.tradingView && user.tradingView.email && user.tradingView.password);
    
    res.json({ 
      hasCredentials: hasCredentials,
      email: user.tradingView?.email || null
    });
  } catch (err) {
    console.error('Error checking TradingView credentials:', err);
    res.status(500).json({ hasCredentials: false });
  }
});

export default router; 