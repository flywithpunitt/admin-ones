import mongoose from 'mongoose';

const activeSessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true // Only one active session per user
  },
  deviceInfo: {
    userAgent: String,
    ipAddress: String,
    browser: String,
    os: String,
    deviceType: String,
    loginTime: { type: Date, default: Date.now }
  },
  lastActivity: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Index for quick lookups
activeSessionSchema.index({ userId: 1 });
activeSessionSchema.index({ lastActivity: 1 });

export default mongoose.model('ActiveSession', activeSessionSchema);
