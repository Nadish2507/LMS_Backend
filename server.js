import 'dotenv/config';
import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

// ─── DB Connection ────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/leave_management')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('DB Error:', err));

// ─── Models ───────────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  name:         { type: String, required: true },
  email:        { type: String, required: true, unique: true },
  password:     { type: String, required: true },
  role:         { type: String, enum: ['employee', 'admin'], default: 'employee' },
  leaveBalance: { type: Number, default: 20 }
}, { timestamps: true });

userSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, 10);
});

const User = mongoose.model('User', userSchema);

const leaveSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type:      { type: String, enum: ['Sick', 'Casual', 'Annual', 'Unpaid'], required: true },
  startDate: { type: Date, required: true },
  endDate:   { type: Date, required: true },
  reason:    { type: String, required: true },
  status:    { type: String, enum: ['Pending', 'Approved', 'Rejected'], default: 'Pending' }
}, { timestamps: true });

const Leave = mongoose.model('Leave', leaveSchema);

// ─── Middleware ───────────────────────────────────────────────────────────────
const protect = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin only' });
  next();
};

const signToken = (user) =>
  jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });

// ─── Auth Routes ──────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (await User.findOne({ email })) return res.status(400).json({ message: 'Email already exists' });
    const user = await User.create({ name, email, password, role });
    res.status(201).json({
      token: signToken(user),
      user: { id: user._id, name: user.name, email: user.email, role: user.role, leaveBalance: user.leaveBalance }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!user || !isMatch)
      return res.status(400).json({ message: 'Invalid credentials' });
    res.json({
      token: signToken(user),
      user: { id: user._id, name: user.name, email: user.email, role: user.role, leaveBalance: user.leaveBalance }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/auth/me', protect, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  res.json(user);
});

// ─── Leave Routes ─────────────────────────────────────────────────────────────
app.post('/api/leaves', protect, async (req, res) => {
  try {
    const { type, startDate, endDate, reason } = req.body;
    const days = Math.ceil((new Date(endDate) - new Date(startDate)) / (1000 * 60 * 60 * 24)) + 1;
    const user = await User.findById(req.user.id);
    if (user.leaveBalance < days) return res.status(400).json({ message: 'Insufficient leave balance' });
    const leave = await Leave.create({ userId: req.user.id, type, startDate, endDate, reason });
    res.status(201).json(leave);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/leaves/my', protect, async (req, res) => {
  const leaves = await Leave.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json(leaves);
});

app.get('/api/leaves', protect, adminOnly, async (req, res) => {
  const leaves = await Leave.find().populate('userId', 'name email').sort({ createdAt: -1 });
  res.json(leaves);
});

app.patch('/api/leaves/:id', protect, adminOnly, async (req, res) => {
  try {
    const { status } = req.body;
    const leave = await Leave.findById(req.params.id);
    if (!leave) return res.status(404).json({ message: 'Leave not found' });
    if (leave.status !== 'Pending') return res.status(400).json({ message: 'Already processed' });
    leave.status = status;
    await leave.save();
    if (status === 'Approved') {
      const days = Math.ceil((new Date(leave.endDate) - new Date(leave.startDate)) / (1000 * 60 * 60 * 24)) + 1;
      await User.findByIdAndUpdate(leave.userId, { $inc: { leaveBalance: -days } });
    }
    res.json(leave);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/users', protect, adminOnly, async (req, res) => {
  const users = await User.find().select('-password');
  res.json(users);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
