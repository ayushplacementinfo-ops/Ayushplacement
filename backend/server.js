const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('frontend'));

// MongoDB Connection (Clean version - no deprecated options)
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ MongoDB Connected Successfully');
  } catch (error) {
    console.error('❌ MongoDB Connection Error:', error.message);
    process.exit(1);
  }
};

connectDB();

// Models
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['candidate', 'employer', 'admin'], default: 'candidate' },
  phone: String,
  company: String,
  createdAt: { type: Date, default: Date.now }
});

const JobSchema = new mongoose.Schema({
  title: { type: String, required: true },
  company: { type: String, required: true },
  location: { type: String, required: true },
  type: { type: String, enum: ['Full-time', 'Part-time', 'Remote', 'Contract', 'Walk-in'], default: 'Full-time' },
  salary: String,
  experience: String,
  description: { type: String, required: true },
  requirements: String,
  postedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  postedDate: { type: Date, default: Date.now },
  status: { type: String, enum: ['active', 'closed'], default: 'active' }
});

const ApplicationSchema = new mongoose.Schema({
  jobId: { type: mongoose.Schema.Types.ObjectId, ref: 'Job', required: true },
  candidateId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  candidateName: String,
  candidateEmail: String,
  resume: String,
  coverLetter: String,
  status: { type: String, enum: ['pending', 'reviewed', 'shortlisted', 'rejected'], default: 'pending' },
  appliedDate: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Job = mongoose.model('Job', JobSchema);
const Application = mongoose.model('Application', ApplicationSchema);

// Middleware to verify JWT
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const adminMiddleware = async (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// ============ AUTH ROUTES ============

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, role, phone, company } = req.body;
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role: role || 'candidate',
      phone,
      company
    });
    
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get current user
app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ JOB ROUTES ============

// Get all jobs (with filters)
app.get('/api/jobs', async (req, res) => {
  try {
    const { search, location, type } = req.query;
    let query = { status: 'active' };
    
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { company: { $regex: search, $options: 'i' } }
      ];
    }
    if (location) {
      query.location = { $regex: location, $options: 'i' };
    }
    if (type && type !== '') {
      query.type = type;
    }
    
    const jobs = await Job.find(query).sort({ postedDate: -1 }).limit(50);
    res.json(jobs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get single job
app.get('/api/jobs/:id', async (req, res) => {
  try {
    const job = await Job.findById(req.params.id).populate('postedBy', 'name email company');
    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }
    res.json(job);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create job (employer or admin only)
app.post('/api/jobs', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'employer' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only employers can post jobs' });
    }
    
    const job = new Job({
      ...req.body,
      postedBy: req.user.id
    });
    
    await job.save();
    res.status(201).json(job);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update job
app.put('/api/jobs/:id', authMiddleware, async (req, res) => {
  try {
    const job = await Job.findById(req.params.id);
    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }
    
    if (job.postedBy.toString() !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    Object.assign(job, req.body);
    await job.save();
    res.json(job);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete job
app.delete('/api/jobs/:id', authMiddleware, async (req, res) => {
  try {
    const job = await Job.findById(req.params.id);
    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }
    
    if (job.postedBy.toString() !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    await job.deleteOne();
    res.json({ message: 'Job deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ APPLICATION ROUTES ============

// Apply for job
app.post('/api/applications', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'candidate') {
      return res.status(403).json({ error: 'Only candidates can apply' });
    }
    
    const existing = await Application.findOne({
      jobId: req.body.jobId,
      candidateId: req.user.id
    });
    
    if (existing) {
      return res.status(400).json({ error: 'Already applied for this job' });
    }
    
    const user = await User.findById(req.user.id);
    
    const application = new Application({
      jobId: req.body.jobId,
      candidateId: req.user.id,
      candidateName: user.name,
      candidateEmail: user.email,
      coverLetter: req.body.coverLetter || ''
    });
    
    await application.save();
    res.status(201).json(application);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get my applications (candidate)
app.get('/api/applications/my', authMiddleware, async (req, res) => {
  try {
    const applications = await Application.find({ candidateId: req.user.id })
      .populate('jobId')
      .sort({ appliedDate: -1 });
    res.json(applications);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get applications for a job (employer)
app.get('/api/applications/job/:jobId', authMiddleware, async (req, res) => {
  try {
    const job = await Job.findById(req.params.jobId);
    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }
    
    if (job.postedBy.toString() !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const applications = await Application.find({ jobId: req.params.jobId });
    res.json(applications);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ ADMIN ROUTES ============

// Get stats
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const totalJobs = await Job.countDocuments();
    const activeJobs = await Job.countDocuments({ status: 'active' });
    const totalUsers = await User.countDocuments();
    const totalApplications = await Application.countDocuments();
    
    res.json({
      totalJobs,
      activeJobs,
      totalUsers,
      totalApplications
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all users
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ CREATE DEFAULT ADMIN ============
const createDefaultAdmin = async () => {
  try {
    const adminExists = await User.findOne({ role: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'Admin@123456', 10);
      const admin = new User({
        name: 'Super Admin',
        email: process.env.ADMIN_EMAIL || 'admin@ayushplacement.com',
        password: hashedPassword,
        role: 'admin',
        phone: '9999999999'
      });
      await admin.save();
      console.log('✅ Default admin created');
      console.log(`   Email: ${admin.email}`);
    }
  } catch (error) {
    console.log('⚠️ Admin creation skipped:', error.message);
  }
};

// ============ SEED INITIAL JOBS (if empty) ============
const seedInitialJobs = async () => {
  try {
    const jobCount = await Job.countDocuments();
    if (jobCount === 0) {
      const sampleJobs = [
        {
          title: "QA Chemist / Officer",
          company: "Pharma Ltd",
          location: "Palghar",
          type: "Walk-in",
          salary: "1-5 Lakhs",
          experience: "1-4 Years",
          description: "Looking for experienced QA Chemist for pharmaceutical company. Male candidates preferred.",
          status: "active"
        },
        {
          title: "QC-HPLC Officer",
          company: "Biotech Corp",
          location: "Palghar MIDC",
          type: "Full-time",
          salary: "3-4 Lakhs",
          experience: "1-3 Years",
          description: "HPLC/lab instrument experience required. Must have knowledge of all QC activities.",
          status: "active"
        },
        {
          title: "Microbiologist",
          company: "Bioscience Ltd",
          location: "Boisar",
          type: "Full-time",
          salary: "2-4 Lakhs",
          experience: "0-2 Years",
          description: "Perform microbiological analysis, environmental monitoring, GMP knowledge required.",
          status: "active"
        },
        {
          title: "Mechanical Engineer",
          company: "Injactble Plant",
          location: "Palghar",
          type: "Full-time",
          salary: "2-5 Lakhs",
          experience: "3-4 Years",
          description: "BE/B.TECH Mechanical background for maintenance department.",
          status: "active"
        },
        {
          title: "Electrical Engineer",
          company: "API Plant",
          location: "Boisar",
          type: "Full-time",
          salary: "2-3 Lakhs",
          experience: "1-4 Years",
          description: "Pharma background must for electrical engineering position.",
          status: "active"
        },
        {
          title: "Production Officer",
          company: "MNC Pharma",
          location: "Boisar",
          type: "Full-time",
          salary: "3-5 Lakhs",
          experience: "2-5 Years",
          description: "Tablet production experience required. MNC group company.",
          status: "active"
        }
      ];
      
      await Job.insertMany(sampleJobs);
      console.log('✅ Sample jobs seeded to database');
    }
  } catch (error) {
    console.log('⚠️ Job seeding skipped:', error.message);
  }
};

// ============ START SERVER ============
const PORT = process.env.PORT || 5000;

app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  await createDefaultAdmin();
  await seedInitialJobs();
});
