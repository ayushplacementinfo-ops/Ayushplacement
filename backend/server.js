const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('frontend'));

// Create uploads directory if it doesn't exist
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure multer for resume upload
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'resume-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['.pdf', '.doc', '.docx'];
  const ext = path.extname(file.originalname).toLowerCase();
  if (allowedTypes.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error('Only PDF, DOC, DOCX files are allowed'), false);
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// MongoDB Connection
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

// ============ ENHANCED CANDIDATE SCHEMA ============
const CandidateSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'candidate' },
  
  // Personal Details
  dob: String,
  phone: String,
  alternatePhone: String,
  gender: String,
  maritalStatus: String,
  
  // Address Details
  currentLocation: String,
  permanentAddress: String,
  city: String,
  state: String,
  pincode: String,
  
  // Professional Details
  qualification: String,
  totalExperience: String,
  relevantExperience: String,
  currentSalary: String,
  expectedSalary: String,
  noticePeriod: String,
  currentCompany: String,
  previousCompanies: String,
  keySkills: String,
  certification: String,
  
  // Resume
  resumePath: String,
  resumeOriginalName: String,
  
  // Additional Info
  linkedinProfile: String,
  portfolio: String,
  languages: String,
  
  createdAt: { type: Date, default: Date.now }
});

const EmployerSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'employer' },
  companyName: String,
  companyWebsite: String,
  companySize: String,
  industry: String,
  phone: String,
  designation: String,
  createdAt: { type: Date, default: Date.now }
});

const AdminSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'admin' },
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
  candidateId: { type: mongoose.Schema.Types.ObjectId, ref: 'Candidate', required: true },
  candidateName: String,
  candidateEmail: String,
  coverLetter: String,
  status: { type: String, enum: ['pending', 'reviewed', 'shortlisted', 'rejected'], default: 'pending' },
  appliedDate: { type: Date, default: Date.now }
});

const Candidate = mongoose.model('Candidate', CandidateSchema);
const Employer = mongoose.model('Employer', EmployerSchema);
const Admin = mongoose.model('Admin', AdminSchema);
const Job = mongoose.model('Job', JobSchema);
const Application = mongoose.model('Application', ApplicationSchema);

// ============ AUTH MIDDLEWARE ============
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

// ============ CANDIDATE REGISTRATION WITH RESUME ============
app.post('/api/candidate/register', upload.single('resume'), async (req, res) => {
  try {
    const { 
      name, email, password, dob, phone, alternatePhone, gender, maritalStatus,
      currentLocation, permanentAddress, city, state, pincode,
      qualification, totalExperience, relevantExperience, currentSalary, 
      expectedSalary, noticePeriod, currentCompany, previousCompanies,
      keySkills, certification, linkedinProfile, portfolio, languages
    } = req.body;
    
    // Check if email already exists
    const existingCandidate = await Candidate.findOne({ email });
    if (existingCandidate) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const candidate = new Candidate({
      name, email, password: hashedPassword,
      dob, phone, alternatePhone, gender, maritalStatus,
      currentLocation, permanentAddress, city, state, pincode,
      qualification, totalExperience, relevantExperience, currentSalary,
      expectedSalary, noticePeriod, currentCompany, previousCompanies,
      keySkills, certification, linkedinProfile, portfolio, languages,
      resumePath: req.file ? req.file.path : null,
      resumeOriginalName: req.file ? req.file.originalname : null
    });
    
    await candidate.save();
    res.status(201).json({ message: 'Candidate registered successfully!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// ============ EMPLOYER REGISTRATION ============
app.post('/api/employer/register', async (req, res) => {
  try {
    const { name, email, password, companyName, companyWebsite, companySize, industry, phone, designation } = req.body;
    
    const existingEmployer = await Employer.findOne({ email });
    if (existingEmployer) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const employer = new Employer({
      name, email, password: hashedPassword,
      companyName, companyWebsite, companySize, industry, phone, designation
    });
    
    await employer.save();
    res.status(201).json({ message: 'Employer registered successfully!' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ LOGIN (Working Fix) ============
app.post('/api/login', async (req, res) => {
  try {
    const { email, password, role } = req.body;
    
    let user = null;
    let userModel = null;
    
    // Find user based on role
    if (role === 'candidate') {
      user = await Candidate.findOne({ email });
      userModel = 'candidate';
    } else if (role === 'employer') {
      user = await Employer.findOne({ email });
      userModel = 'employer';
    } else if (role === 'admin') {
      user = await Admin.findOne({ email });
      userModel = 'admin';
    }
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: user._id, email: user.email, role: userModel },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: userModel
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============ GET CANDIDATE PROFILE ============
app.get('/api/candidate/profile', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'candidate') {
      return res.status(403).json({ error: 'Access denied' });
    }
    const candidate = await Candidate.findById(req.user.id).select('-password');
    res.json(candidate);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ JOB ROUTES ============
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

app.post('/api/jobs', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'employer' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only employers can post jobs' });
    }
    
    const job = new Job({ ...req.body, postedBy: req.user.id });
    await job.save();
    res.status(201).json(job);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ APPLY FOR JOB ============
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
    
    const candidate = await Candidate.findById(req.user.id);
    
    const application = new Application({
      jobId: req.body.jobId,
      candidateId: req.user.id,
      candidateName: candidate.name,
      candidateEmail: candidate.email,
      coverLetter: req.body.coverLetter || ''
    });
    
    await application.save();
    res.status(201).json(application);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ GET MY APPLICATIONS ============
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

// ============ ADMIN LOGIN CHECK ============
app.get('/api/admin/check', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    res.json({ success: true, message: 'Admin authenticated' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ CREATE DEFAULT ADMIN ============
const createDefaultAdmin = async () => {
  try {
    const adminExists = await Admin.findOne({ email: 'admin@ayushplacement.com' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('Admin@123', 10);
      const admin = new Admin({
        name: 'Super Admin',
        email: 'admin@ayushplacement.com',
        password: hashedPassword,
        role: 'admin'
      });
      await admin.save();
      console.log('✅ Default admin created');
      console.log('   Email: admin@ayushplacement.com');
      console.log('   Password: Admin@123');
    }
  } catch (error) {
    console.log('⚠️ Admin creation skipped:', error.message);
  }
};

// ============ SEED INITIAL JOBS ============
const seedInitialJobs = async () => {
  try {
    const jobCount = await Job.countDocuments();
    if (jobCount === 0) {
      const sampleJobs = [
        { title: "QA Chemist / Officer", company: "Pharma Ltd", location: "Palghar", type: "Walk-in", salary: "1-5 Lakhs", experience: "1-4 Years", description: "Looking for experienced QA Chemist for pharmaceutical company.", status: "active" },
        { title: "QC-HPLC Officer", company: "Biotech Corp", location: "Palghar MIDC", type: "Full-time", salary: "3-4 Lakhs", experience: "1-3 Years", description: "HPLC/lab instrument experience required.", status: "active" },
        { title: "Microbiologist", company: "Bioscience Ltd", location: "Boisar", type: "Full-time", salary: "2-4 Lakhs", experience: "0-2 Years", description: "Perform microbiological analysis, GMP knowledge required.", status: "active" },
        { title: "Mechanical Engineer", company: "Injactble Plant", location: "Palghar", type: "Full-time", salary: "2-5 Lakhs", experience: "3-4 Years", description: "BE/B.TECH Mechanical background.", status: "active" }
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
