import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  aadhar: { type: String, default: '' },
  pan: { type: String, default: '' },
  phone: { type: String, default: '' },
  address: { type: String, default: '' },
  dob: { type: String, default: '' },
  tradingView: {
    email: {
      type: String,
      default: ''
    },
    password: {
      type: String,
      default: ''
    }
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
}, {
  timestamps: true,
});

export default mongoose.model('User', userSchema); 