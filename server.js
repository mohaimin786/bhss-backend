
// server.js
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fetch = require('node-fetch');
const nodemailer = require('nodemailer');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const sgMail = require('@sendgrid/mail');

const app = express();

// Verify and set API key
const apiKey = process.env.SENDGRID_API_KEY?.trim();
if (!apiKey) {
  console.error('❌ SENDGRID_API_KEY is missing');
} else {
  console.log('API Key exists:', !!apiKey);
  console.log('API Key starts with SG:', apiKey.startsWith('SG.'));
  console.log('API Key length:', apiKey.length);
  console.log('First 10 chars:', apiKey.substring(0, 10));
  
  try {
    sgMail.setApiKey(apiKey);
    console.log('✅ SendGrid API key set successfully');
  } catch (err) {
    console.error('❌ Failed to set SendGrid API key:', err);
  }
}

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// Schemas & Models
const submissionSchema = new mongoose.Schema({
  _id: { type: String, required: true }, // string _id for NeDB compatibility
  fullName: String,
  email: String,
  countryCode: String,
  phone: String,
  dob: String,
  grade: String,
  isBhStudent: Boolean,
  bhBranch: String,
  section: String,
  city: String,
  school: String,
  country: String,
  subjects: [String],
  category: String,
  motivation: String,
  whyChosenSubjects: String,
  heardAbout: String,
  social: String,
  prevCompetitions: String,
  skills: String,
  ideas: String,
  role: String,
  status: { type: String, default: 'pending' },
  notes: { type: String, default: '' },
  timestamp: { type: Date, default: Date.now }
}, { versionKey: false });

const userSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  fullName: String,
  email: String,
  password: String,
  role: String,
  createdAt: { type: Date, default: Date.now }
}, { versionKey: false });

const Submission = mongoose.model('Submission', submissionSchema);
const User = mongoose.model('User', userSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(48).toString('hex');

// Admin credentials hashed password setup
const ADMIN_CREDENTIALS = {
  username: process.env.ADMIN_USER || 'BHSS_COUNCIL',
  password: process.env.ADMIN_PASS
    ? bcrypt.hashSync(process.env.ADMIN_PASS, 10)
    : bcrypt.hashSync('temporary1234', 10),
};

// Middlewares
app.use(cors({
  origin: 'https://stackblitz-starters-uogm5vlf.vercel.app',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  handler: (req, res) => {
    // Redirect to index.html with error query param
    res.redirect('https://stackblitz-starters-uogm5vlf.vercel.app/index.html?error=rateLimitReached');
  }
});

const submissionLimiter = rateLimit({
  windowMs: 24 * 60 * 60 * 1000, // 24 hours
  max: 3,
  keyGenerator: function (req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
      const ips = forwarded.split(',');
      return ips[0].trim();
    }
    return req.connection?.remoteAddress || req.ip;
  },
  skip: function (req, res) {
    try {
      const authHeader = req.headers['authorization'];
      if (!authHeader) return false;
      const token = authHeader.split(' ')[1];
      if (!token) return false;
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded && decoded.username === (process.env.ADMIN_USER || 'BHSS_COUNCIL')) {
        return true; // Skip rate limit for authenticated admin JWT
      }
      return false;
    } catch {
      return false;
    }
  },
  handler: function (req, res) {
    console.log('Rate limit exceeded for IP:', req.headers['x-forwarded-for'] || req.ip);
    // Redirect on limit reached instead of sending JSON
    res.redirect('https://stackblitz-starters-uogm5vlf.vercel.app/index.html?error=rateLimitReached');
  },
  onLimitReached: function (req) {
    console.log('Rate limit reached for', req.headers['x-forwarded-for'] || req.ip, 'at', new Date());
  }
});

const ipinfoLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 100,
  message: 'Too many IP info requests, please try again later',
});

// Security headers middleware
app.use(function (req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Helper functions
// Add this to your helper functions in server.js
function authenticateUser(req, res, next) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        message: 'Authentication required' 
      });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(403).json({ 
          success: false, 
          message: 'Invalid or expired token' 
        });
      }
      
      req.user = decoded;
      next();
    });
  } catch (err) {
    console.error('Authentication error:', err);
    return res.status(500).json({ 
      success: false, 
      message: 'Server error during authentication' 
    });
  }
}
function createAdminToken(username) {
  const payload = { username, iss: 'bhss-backend' };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' });
}

function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, error: 'Authentication required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ success: false, error: 'Invalid or expired token' });
      req.user = user;
      next();
    });
  } catch {
    return res.status(500).json({ success: false, error: 'Server error during authentication' });
  }
}

function checkToken(req) {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return null;
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// Routes
// User login route
app.post('/api/user/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and password are required' 
      });
    }

    // Check if user exists
    const user = await User.findOne({ email });
    
    if (!user) {
      // Check if there's a submission with this email
      const submission = await Submission.findOne({ email });
      
      if (!submission) {
        return res.status(401).json({ 
          success: false, 
          message: 'Email not registered. Please register first.',
          redirect: 'https://stackblitz-starters-uogm5vlf.vercel.app/register.html'
        });
      }
      
      if (submission.status === 'pending') {
        return res.status(401).json({ 
          success: false, 
          message: 'Your application is still under review. Please wait for approval.',
          redirect: 'https://stackblitz-starters-uogm5vlf.vercel.app/index.html' // Create this page
        });
      }
      
      if (submission.status === 'rejected') {
        return res.status(401).json({ 
          success: false, 
          message: 'Your application was rejected. Please contact admin if you believe this is an error.',
          redirect: 'https://stackblitz-starters-uogm5vlf.vercel.app/index.html' // Create this page
        });
      }
      
      // Shouldn't reach here, but just in case
      return res.status(401).json({ 
        success: false, 
        message: 'Account not found. Please register first.',
        redirect: 'https://stackblitz-starters-uogm5vlf.vercel.app/register.html'
      });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid password' 
      });
    }

    // Create JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '1d' }
    );

    res.json({ 
      success: true, 
      message: 'Login successful',
      token
    });

  } catch (err) {
    console.error('User login error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during login' 
    });
  }
});
// IP info route
app.get('/api/ipinfo', ipinfoLimiter, async (req, res) => {
  try {
    const forwardedHeader = req.headers['x-forwarded-for'];
    const clientIp = forwardedHeader ? forwardedHeader.split(',')[0].trim() : req.ip;
    const apiKey = process.env.IPAPI_KEY || '';
    const ipapiUrl = apiKey
      ? `https://ipapi.co/${clientIp}/json/?key=${apiKey}`
      : 'https://ipapi.co/json/';
    const fallbackUrl = 'https://ipwhois.app/json/';

    let response = await fetch(ipapiUrl);
    if (!response.ok) {
      response = await fetch(fallbackUrl);
    }
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error('Both IP API services failed: ' + errorText);
    }
    const data = await response.json();

    res.json({
      country: data.country || data.country_name,
      countryCode: data.country_code,
      ip: data.ip,
    });
  } catch (error) {
    console.error('IP detection error:', error);
    res.status(500).json({ success: false, error: 'Could not detect location', fallback: true });
  }
});

// Admin login
app.post('/api/admin/login', loginLimiter, (req, res) => {
  try {
    const { username, password } = req.body;
    if (
      username === ADMIN_CREDENTIALS.username &&
      bcrypt.compareSync(password, ADMIN_CREDENTIALS.password)
    ) {
      const token = createAdminToken(username);
      return res.json({ success: true, token });
    }
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ success: false, error: 'Server error during login' });
  }
});

// Admin logout (stateless JWT)
app.post('/api/admin/logout', (req, res) => {
  res.json({ success: true, message: 'Client should delete the stored token' });
});

// Admin status check
app.get('/api/admin/status', (req, res) => {
  const decoded = checkToken(req);
  if (decoded) return res.json({ authenticated: true, user: decoded });
  return res.json({ authenticated: false });
});

// Rate-test endpoint
app.get('/api/rate-test', submissionLimiter, (req, res) => {
  res.json({
    success: true,
    message: 'Rate test passed',
    ip: req.ip,
    forwardedFor: req.headers['x-forwarded-for'],
  });
});

// Export submissions CSV (protected)
app.get('/api/submissions/export-filtered', authenticateToken, async (req, res) => {
  try {
    const docs = await Submission.find({}).sort({ timestamp: -1 }).exec();

    let csv = 'Full Name,Email,Country Code,Phone Number,Date of Birth,Grade,Is BH Student,Country,School Name,Subjects,Role,Motivation\n';

    docs.forEach((sub) => {
      const escapeCsv = (str) => {
        if (!str) return '';
        return `"${String(str).replace(/"/g, '""')}"`;
      };

      const subjects = sub.subjects ? sub.subjects.join('; ') : '';

      csv += [
        escapeCsv(sub.fullName),
        escapeCsv(sub.email),
        escapeCsv(sub.countryCode),
        escapeCsv(sub.phone),
        escapeCsv(sub.dob),
        escapeCsv(sub.grade),
        escapeCsv(sub.isBhStudent ? 'Yes' : 'No'),
        escapeCsv(sub.country),
        escapeCsv(sub.school),
        escapeCsv(subjects),
        escapeCsv(sub.role),
        escapeCsv(sub.motivation)
      ].join(',') + '\n';
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader(
      'Content-Disposition',
      'attachment; filename=filtered-submissions-' + new Date().toISOString().slice(0, 10) + '.csv'
    );
    res.send(csv);
  } catch (err) {
    console.error('Export error:', err);
    res.status(500).json({ success: false, error: 'Export failed' });
  }
});

// Bulk delete submissions (protected)
app.delete('/api/submissions/bulk-delete', authenticateToken, async (req, res) => {
  try {
    const { ids } = req.body;
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ success: false, error: 'IDs must be a non-empty array' });
    }
    const validIds = ids.map(id => String(id).trim()).filter(id => id.length > 0);
    if (validIds.length === 0) {
      return res.status(400).json({ success: false, error: 'No valid IDs provided' });
    }
    const result = await Submission.deleteMany({ _id: { $in: validIds } });
    res.json({ success: true, deleted: result.deletedCount, message: `Deleted ${result.deletedCount} submissions` });
  } catch (err) {
    console.error('Bulk delete error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});
// Example protected route
app.get('/api/user/profile', authenticateUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    res.json({ 
      success: true, 
      user: {
        email: user.email,
        fullName: user.fullName,
        createdAt: user.createdAt
      }
    });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Server error fetching profile' 
    });
  }
});

// Bulk update submissions status (protected)
app.put('/api/submissions/bulk-update', authenticateToken, async (req, res) => {
  try {
    const { ids, status } = req.body;
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ success: false, error: 'Invalid submission IDs' });
    }
    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({ success: false, error: 'Invalid status' });
    }
    const result = await Submission.updateMany(
      { _id: { $in: ids } },
      { $set: { status } }
    );
    res.json({ success: true, updated: result.modifiedCount });
  } catch (err) {
    console.error('Bulk update error:', err);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// Update single submission (protected)
app.put('/api/submissions/:id', authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    const { status, notes } = req.body;
    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({ success: false, error: 'Invalid status' });
    }
    const result = await Submission.updateOne(
      { _id: id },
      { $set: { status, notes: notes || '' } }
    );
    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, error: 'Submission not found' });
    }
    res.json({ success: true, updated: result.modifiedCount });
  } catch (err) {
    console.error('Update submission error:', err);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// Delete single submission (protected)
app.delete('/api/submissions/:id', authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    const result = await Submission.deleteOne({ _id: id });
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, error: 'Submission not found' });
    }
    res.json({ success: true, deleted: result.deletedCount });
  } catch (err) {
    console.error('Delete submission error:', err);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// Create submission (public) with rate limiting except admin
app.post('/api/submit', submissionLimiter, async (req, res) => {
  try {
    const {
      fullName,
      email,
      countryCode,
      phone,
      dob,
      grade,
      role,
      isBhStudent,
      bhBranch,
      section,
      city,
      school,
      country,
      subjects,
      category,
      motivation,
      whyChosenSubjects,
     
      heardAbout,
      social,
      prevCompetitions,
      skills,
      ideas
    } = req.body;

    if (!fullName || !email || !phone || !dob || !grade || !isBhStudent) {
      return res.status(400).json({ success: false, error: 'All required fields must be filled' });
    }

    if (!Array.isArray(subjects) || subjects.length === 0) {
      return res.status(400).json({ success: false, error: 'Please select at least one subject' });
    }

    if (!motivation || motivation.length < 50) {
      return res.status(400).json({ success: false, error: 'Motivation must be at least 50 characters long' });
    }

    if (isBhStudent === 'yes' && !section) {
      return res.status(400).json({ success: false, error: 'Section is required for BH students' });
    }

    if (isBhStudent === 'no' && (!country || !school)) {
      return res.status(400).json({ success: false, error: 'Country and School are required for non-BH students' });
    }

    const submission = new Submission({
      _id: new mongoose.Types.ObjectId().toString(),
      fullName,
      email,
      countryCode,
      phone,
      dob,
      grade,
      role: role || null ,
      isBhStudent: isBhStudent === 'yes',
      bhBranch: bhBranch || null,
      section: section || null,
      city: city || null,
      school: school || null,
      country: country || null,
      subjects,
      category: category || null,
      motivation,
      whyChosenSubjects: whyChosenSubjects || null,
      heardAbout: heardAbout || null,
      social: social || null,
      prevCompetitions: prevCompetitions || null,
      skills: skills || null,
      ideas: ideas || null,
      status: 'pending',
      timestamp: new Date(),
    });
  console.log('Submission object before saving:', submission)
    await submission.save();
    res.redirect('https://stackblitz-starters-uogm5vlf.vercel.app/thank-you.html');

  } catch (err) {
    console.error('Submission error:', err);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// Get all submissions (protected)
app.get('/api/submissions', authenticateToken, async (req, res) => {
  try {
    const docs = await Submission.find({}).sort({ timestamp: -1 }).exec();
    res.json({ success: true, data: docs });
  } catch (err) {
    console.error('Fetch submissions error:', err);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// Approve submission (generate password, create user, send email)
app.post('/api/submissions/:id/approve', authenticateToken, async (req, res) => {
  try {
    console.log('Approving submission with ID:', req.params.id);
    
    const submission = await Submission.findOne({ _id: req.params.id });
    if (!submission) {
      return res.status(404).json({ success: false, error: 'Submission not found' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: submission.email });
    let plainPassword = null;

    if (!existingUser) {
      plainPassword = crypto.randomBytes(8).toString('hex');
      const hashedPassword = await bcrypt.hash(plainPassword, 10);

      const user = new User({
        _id: new mongoose.Types.ObjectId().toString(),
        fullName: submission.fullName,
        email: submission.email,
        password: hashedPassword,
        createdAt: new Date()
      });

      await user.save();
      console.log('New user account created');
    }

    submission.status = 'approved';
    await submission.save();

    // SendGrid email
       const msg = {
      to: submission.email,
      from: process.env.FROM_EMAIL, // Simple string format
      subject: 'BHSS Registration Approved',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #00ffae;">Congratulations!</h2>
          <p>Hello <strong>${submission.fullName}</strong>,</p>
          <p>Your registration for BHSS has been approved!</p>
          ${plainPassword ? `
            <div style="background-color: #f0f8f0; padding: 15px; border-left: 4px solid #00ffae; margin: 20px 0;">
              <p><strong>Your login password is: ${plainPassword}</strong></p>
              <p style="font-size: 0.9em; color: #666;">Please keep this password safe and secure.</p>
            </div>
          ` : `
            <p>You can now log in to the BHSS portal with your existing credentials.</p>
          `}
          <p>Welcome to BHSS!</p>
          <p>Best regards,<br><strong>BHSS Council</strong></p>
        </div>
      `,
      text: `Hello ${submission.fullName},\n\nCongratulations! Your registration for BHSS has been approved.\n\n${plainPassword ? `Your login password is: ${plainPassword}\n\nPlease keep it safe.\n\n` : 'You can now log in with your existing credentials.\n\n'}Best regards,\nBHSS Council`
    };

    await sgMail.send(msg);
    console.log('Approval email sent via SendGrid');

    res.json({ success: true, message: 'User approved and email sent' });
  } catch (err) {
    console.error('Approve submission error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error: ' + err.message 
    });
  }
});

// Update your reject endpoint:
app.post('/api/submissions/:id/reject', authenticateToken, async (req, res) => {
  try {
    console.log('Rejecting submission with ID:', req.params.id);
    const { rejectionDetails, notes } = req.body;
    
    const submission = await Submission.findOne({ _id: req.params.id });
    if (!submission) {
      return res.status(404).json({ success: false, error: 'Submission not found' });
    }

    // Update submission with rejection details
    submission.status = 'rejected';
    submission.notes = notes || '';
    if (rejectionDetails) {
      submission.rejectionDetails = rejectionDetails;
    }
    await submission.save();

    // Customize email based on rejection reason
    let emailSubject = 'BHSS Registration Status';
    let emailHtml = '';
    let emailText = '';

    if (rejectionDetails) {
      switch(rejectionDetails.reason) {
        case 'age':
          if (rejectionDetails.detail === 'lower') {
            emailSubject = 'BHSS Registration - Age Requirement';
            emailHtml = `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333;">BHSS Registration Update</h2>
                <p>Hello <strong>${submission.fullName}</strong>,</p>
                <p>Thank you for your interest in BHSS.</p>
                <p>After careful consideration, we are unable to approve your registration at this time because you don't meet our minimum age requirement.</p>
                <p>We encourage you to apply again in the future when you meet our age criteria.</p>
                <p>Best regards,<br><strong>BHSS Council</strong></p>
              </div>
            `;
            emailText = `Hello ${submission.fullName},\n\nThank you for your interest in BHSS.\n\nAfter careful consideration, we are unable to approve your registration at this time because you don't meet our minimum age requirement.\n\nWe encourage you to apply again in the future when you meet our age criteria.\n\nBest regards,\nBHSS Council`;
          } else {
            emailSubject = 'BHSS Registration - Age Requirement';
            emailHtml = `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333;">BHSS Registration Update</h2>
                <p>Hello <strong>${submission.fullName}</strong>,</p>
                <p>Thank you for your interest in BHSS.</p>
                <p>After careful consideration, we are unable to approve your registration at this time because you exceed our maximum age requirement.</p>
                <p>Best regards,<br><strong>BHSS Council</strong></p>
              </div>
            `;
            emailText = `Hello ${submission.fullName},\n\nThank you for your interest in BHSS.\n\nAfter careful consideration, we are unable to approve your registration at this time because you exceed our maximum age requirement.\n\nBest regards,\nBHSS Council`;
          }
          break;
        
        case 'grade':
          if (rejectionDetails.detail === 'lower') {
            emailSubject = 'BHSS Registration - Grade Requirement';
            emailHtml = `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333;">BHSS Registration Update</h2>
                <p>Hello <strong>${submission.fullName}</strong>,</p>
                <p>Thank you for your interest in BHSS.</p>
                <p>After careful consideration, we are unable to approve your registration at this time because you don't meet our minimum grade requirement.</p>
                <p>We encourage you to apply again in the future when you meet our grade criteria.</p>
                <p>Best regards,<br><strong>BHSS Council</strong></p>
              </div>
            `;
            emailText = `Hello ${submission.fullName},\n\nThank you for your interest in BHSS.\n\nAfter careful consideration, we are unable to approve your registration at this time because you don't meet our minimum grade requirement.\n\nWe encourage you to apply again in the future when you meet our grade criteria.\n\nBest regards,\nBHSS Council`;
          } else {
            emailSubject = 'BHSS Registration - Grade Requirement';
            emailHtml = `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333;">BHSS Registration Update</h2>
                <p>Hello <strong>${submission.fullName}</strong>,</p>
                <p>Thank you for your interest in BHSS.</p>
                <p>After careful consideration, we are unable to approve your registration at this time because you exceed our maximum grade requirement.</p>
                <p>Best regards,<br><strong>BHSS Council</strong></p>
              </div>
            `;
            emailText = `Hello ${submission.fullName},\n\nThank you for your interest in BHSS.\n\nAfter careful consideration, we are unable to approve your registration at this time because you exceed our maximum grade requirement.\n\nBest regards,\nBHSS Council`;
          }
          break;
          
        case 'other':
        default:
          emailSubject = 'BHSS Registration Status';
          emailHtml = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #333;">BHSS Registration Update</h2>
              <p>Hello <strong>${submission.fullName}</strong>,</p>
              <p>Thank you for your interest in BHSS.</p>
              <p>After careful consideration, we are unable to approve your registration at this time.</p>
              <p>We encourage you to apply again in the future when you meet our requirements.</p>
              <p>Best regards,<br><strong>BHSS Council</strong></p>
            </div>
          `;
          emailText = `Hello ${submission.fullName},\n\nThank you for your interest in BHSS.\n\nAfter careful consideration, we are unable to approve your registration at this time.\n\nWe encourage you to apply again in the future when you meet our requirements.\n\nBest regards,\nBHSS Council`;
      }
    } else {
      // Default rejection message if no reason specified
      emailSubject = 'BHSS Registration Status';
      emailHtml = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">BHSS Registration Update</h2>
          <p>Hello <strong>${submission.fullName}</strong>,</p>
          <p>Thank you for your interest in BHSS.</p>
          <p>After careful consideration, we are unable to approve your registration at this time.</p>
          <p>We encourage you to apply again in the future when you meet our requirements.</p>
          <p>Best regards,<br><strong>BHSS Council</strong></p>
        </div>
      `;
      emailText = `Hello ${submission.fullName},\n\nThank you for your interest in BHSS.\n\nAfter careful consideration, we are unable to approve your registration at this time.\n\nWe encourage you to apply again in the future when you meet our requirements.\n\nBest regards,\nBHSS Council`;
    }

    // SendGrid rejection email
    const msg = {
      to: submission.email,
      from: process.env.FROM_EMAIL,
      subject: emailSubject,
      html: emailHtml,
      text: emailText
    };

    await sgMail.send(msg);
    console.log('Rejection email sent via SendGrid');

    res.json({ 
      success: true, 
      message: 'User rejected and email sent',
      rejectionDetails: rejectionDetails || null
    });
  } catch (err) {
    console.error('Reject submission error:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error: ' + err.message 
    });
  }
});
// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
