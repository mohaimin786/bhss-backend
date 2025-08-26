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
  _id: { type: String, required: true },
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

// Password reset token schema
const passwordResetTokenSchema = new mongoose.Schema({
  userId: { type: String, required: true, ref: 'User' },
  token: { type: String, required: true },
  expires: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
}, { versionKey: false });

const dashboardInfoSchema = new mongoose.Schema({
  _id: { type: String, required: true },
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
  timestamp: { type: Date, default: Date.now },
  dashboardNotes: { type: String, default: '' },
  priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  lastUpdated: { type: Date, default: Date.now }
}, { versionKey: false });

const Submission = mongoose.model('Submission', submissionSchema);
const User = mongoose.model('User', userSchema);
const PasswordResetToken = mongoose.model('PasswordResetToken', passwordResetTokenSchema);
const DashboardInfo = mongoose.model('DashboardInfo', dashboardInfoSchema);

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
  origin: ['https://bhsciencesociety.vercel.app', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  handler: (req, res) => {
    res.redirect('https://bhsciencesociety.vercel.app/index.html?error=rateLimitReached');
  }
});

const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: 'Too many password reset requests, please try again later'
});

const submissionLimiter = rateLimit({
  windowMs: 24 * 60 * 60 * 1000,
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
        return true;
      }
      return false;
    } catch {
      return false;
    }
  },
  handler: function (req, res) {
    console.log('Rate limit exceeded for IP:', req.headers['x-forwarded-for'] || req.ip);
    res.redirect('https://bhsciencesociety.vercel.app/index.html?error=rateLimitReached');
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

// Helper function to copy submission to dashboard info
async function copySubmissionToDashboard(submissionData) {
  try {
    const dashboardData = {
      _id: submissionData._id,
      fullName: submissionData.fullName,
      email: submissionData.email,
      countryCode: submissionData.countryCode,
      phone: submissionData.phone,
      dob: submissionData.dob,
      grade: submissionData.grade,
      isBhStudent: submissionData.isBhStudent,
      bhBranch: submissionData.bhBranch,
      section: submissionData.section,
      city: submissionData.city,
      school: submissionData.school,
      country: submissionData.country,
      subjects: submissionData.subjects,
      category: submissionData.category,
      motivation: submissionData.motivation,
      whyChosenSubjects: submissionData.whyChosenSubjects,
      heardAbout: submissionData.heardAbout,
      social: submissionData.social,
      prevCompetitions: submissionData.prevCompetitions,
      skills: submissionData.skills,
      ideas: submissionData.ideas,
      role: submissionData.role,
      status: submissionData.status,
      notes: submissionData.notes,
      timestamp: submissionData.timestamp,
      lastUpdated: new Date()
    };

    await DashboardInfo.findOneAndUpdate(
      { _id: submissionData._id },
      dashboardData,
      { upsert: true, new: true }
    );

    console.log(`Dashboard info updated/created for submission: ${submissionData._id}`);
  } catch (err) {
    console.error('Error copying submission to dashboard:', err);
  }
}

// Routes

// User login route with remember me functionality
app.post('/api/user/login', async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and password are required' 
      });
    }

    // Check if user exists
    const user = await User.findOne({ email });
    
    if (!user) {
      const submission = await Submission.findOne({ email });
      
      if (!submission) {
        return res.status(401).json({ 
          success: false, 
          message: 'Email not registered. Please register first.',
          redirect: 'https://bhsciencesociety.vercel.app/register.html'
        });
      }
      
      if (submission.status === 'pending') {
        return res.status(401).json({ 
          success: false, 
          message: 'Your application is still under review. Please wait for approval.',
          redirect: 'https://bhsciencesociety.vercel.app/index.html'
        });
      }
      
      if (submission.status === 'rejected') {
        return res.status(401).json({ 
          success: false, 
          message: 'Your application was rejected. Please contact admin if you believe this is an error.',
          redirect: 'https://bhsciencesociety.vercel.app/index.html'
        });
      }
      
      return res.status(401).json({ 
        success: false, 
        message: 'Account not found. Please register first.',
        redirect: 'https://bhsciencesociety.vercel.app/register.html'
      });
    }

    // Compare passwords using bcrypt
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid password' 
      });
    }

    // Create JWT token with different expiration based on remember me
    const tokenExpiry = rememberMe ? '30d' : '1d';
    const token = jwt.sign(
      { userId: user._id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: tokenExpiry }
    );

    res.json({ 
      success: true, 
      message: 'Login successful',
      token,
      expiresIn: tokenExpiry
    });

  } catch (err) {
    console.error('User login error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during login' 
    });
  }
});

// Forgot Password route - Send reset link
app.post('/api/user/forgot-password', passwordResetLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is required' 
      });
    }

    // Check if user exists
    const user = await User.findOne({ email });
    
    if (!user) {
      // Check if there's a submission with this email
      const submission = await Submission.findOne({ email });
      
      if (!submission) {
        return res.status(404).json({ 
          success: false, 
          message: 'Email not found in our system' 
        });
      }
      
      if (submission.status !== 'approved') {
        return res.status(401).json({ 
          success: false, 
          message: 'Your account has not been approved yet' 
        });
      }
      
      return res.status(404).json({ 
        success: false, 
        message: 'Email not found in our system' 
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    
    // Set expiration (1 hour)
    const expires = new Date(Date.now() + 60 * 60 * 1000);
    
    // Delete any existing reset tokens for this user
    await PasswordResetToken.deleteMany({ userId: user._id });
    
    // Save new reset token
    const resetTokenDoc = new PasswordResetToken({
      userId: user._id,
      token: hashedToken,
      expires: expires
    });
    
    await resetTokenDoc.save();
    
    // Create reset URL
    const resetUrl = `https://bhsciencesociety.vercel.app/reset-password.html?token=${resetToken}&id=${user._id}`;
    
    // Send email with reset link
    const msg = {
      to: user.email,
      from: process.env.FROM_EMAIL,
      subject: 'BHSS Password Reset',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #00ffae;">Password Reset Request</h2>
          <p>Hello <strong>${user.fullName}</strong>,</p>
          <p>You requested to reset your password. Click the button below to reset it:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" style="background-color: #00ffae; color: #0f111a; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">
              Reset Password
            </a>
          </div>
          <p style="font-size: 0.9em; color: #666;">This link will expire in 1 hour for security reasons.</p>
          <p>If you didn't request this reset, please ignore this email.</p>
          <p>Best regards,<br><strong>BHSS Council</strong></p>
        </div>
      `,
      text: `Hello ${user.fullName},\n\nYou requested to reset your password. Use this link to reset it:\n\n${resetUrl}\n\nThis link will expire in 1 hour for security reasons.\n\nIf you didn't request this reset, please ignore this email.\n\nBest regards,\nBHSS Council`
    };

    await sgMail.send(msg);
    console.log('Password reset email sent');

    res.json({ 
      success: true, 
      message: 'Password reset link sent to your email' 
    });

  } catch (err) {
    console.error('Password reset error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during password reset' 
    });
  }
});

// Verify reset token
app.get('/api/user/verify-reset-token', async (req, res) => {
  try {
    const { token, userId } = req.query;
    
    if (!token || !userId) {
      return res.status(400).json({ 
        success: false, 
        message: 'Token and user ID are required' 
      });
    }

    // Hash the token
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    
    // Find the token
    const resetToken = await PasswordResetToken.findOne({
      userId: userId,
      token: hashedToken,
      expires: { $gt: new Date() }
    });

    if (!resetToken) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired reset token' 
      });
    }

    res.json({ 
      success: true, 
      message: 'Token is valid' 
    });

  } catch (err) {
    console.error('Token verification error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during token verification' 
    });
  }
});

// Reset password with token
app.post('/api/user/reset-password', async (req, res) => {
  try {
    const { token, userId, password } = req.body;
    
    if (!token || !userId || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Token, user ID, and password are required' 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 6 characters long' 
      });
    }

    // Hash the token
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    
    // Find the token
    const resetToken = await PasswordResetToken.findOne({
      userId: userId,
      token: hashedToken,
      expires: { $gt: new Date() }
    });

    if (!resetToken) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired reset token' 
      });
    }

    // Find user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Update user password
    user.password = hashedPassword;
    await user.save();
    
    // Delete the used token
    await PasswordResetToken.deleteMany({ userId: userId });
    
    // Send confirmation email
    const msg = {
      to: user.email,
      from: process.env.FROM_EMAIL,
      subject: 'BHSS Password Changed',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #00ffae;">Password Changed Successfully</h2>
          <p>Hello <strong>${user.fullName}</strong>,</p>
          <p>Your password has been successfully changed.</p>
          <p>If you did not make this change, please contact us immediately.</p>
          <p>Best regards,<br><strong>BHSS Council</strong></p>
        </div>
      `,
      text: `Hello ${user.fullName},\n\nYour password has been successfully changed.\n\nIf you did not make this change, please contact us immediately.\n\nBest regards,\nBHSS Council`
    };

    await sgMail.send(msg);
    console.log('Password changed confirmation email sent');

    res.json({ 
      success: true, 
      message: 'Password reset successfully' 
    });

  } catch (err) {
    console.error('Password reset error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during password reset' 
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

// Dashboard Info Routes

// Get all dashboard info (protected)
app.get('/api/dashboard-info', authenticateToken, async (req, res) => {
  try {
    const docs = await DashboardInfo.find({}).sort({ timestamp: -1 }).exec();
    res.json({ success: true, data: docs });
  } catch (err) {
    console.error('Fetch dashboard info error:', err);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// Sync all submissions to dashboard info (protected)
app.post('/api/dashboard-info/sync-all', authenticateToken, async (req, res) => {
  try {
    const submissions = await Submission.find({});
    let syncedCount = 0;
    
    for (const submission of submissions) {
      await copySubmissionToDashboard(submission);
      syncedCount++;
    }
    
    res.json({ 
      success: true, 
      message: `Synced ${syncedCount} submissions to dashboard info`,
      synced: syncedCount
    });
  } catch (err) {
    console.error('Sync dashboard info error:', err);
    res.status(500).json({ success: false, error: 'Sync failed' });
  }
});

// Update dashboard info item (protected)
app.put('/api/dashboard-info/:id', authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    const { dashboardNotes, priority, ...otherFields } = req.body;
    
    const updateData = {
      ...otherFields,
      lastUpdated: new Date()
    };
    
    if (dashboardNotes !== undefined) updateData.dashboardNotes = dashboardNotes;
    if (priority !== undefined) updateData.priority = priority;
    
    const result = await DashboardInfo.updateOne(
      { _id: id },
      { $set: updateData }
    );
    
    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, error: 'Dashboard info not found' });
    }
    
    res.json({ success: true, updated: result.modifiedCount });
  } catch (err) {
    console.error('Update dashboard info error:', err);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// Delete dashboard info item (protected)
app.delete('/api/dashboard-info/:id', authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    const result = await DashboardInfo.deleteOne({ _id: id });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, error: 'Dashboard info not found' });
    }
    
    res.json({ success: true, deleted: result.deletedCount });
  } catch (err) {
    console.error('Delete dashboard info error:', err);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// Export dashboard info CSV (protected)
app.get('/api/dashboard-info/export', authenticateToken, async (req, res) => {
  try {
    const docs = await DashboardInfo.find({}).sort({ timestamp: -1 }).exec();

    let csv = 'Full Name,Email,Country Code,Phone Number,Date of Birth,Grade,Is BH Student,Country,School Name,Subjects,Role,Motivation,Priority,Dashboard Notes,Status\n';

    docs.forEach((item) => {
      const escapeCsv = (str) => {
        if (!str) return '';
        return `"${String(str).replace(/"/g, '""')}"`;
      };

      const subjects = item.subjects ? item.subjects.join('; ') : '';

      csv += [
        escapeCsv(item.fullName),
        escapeCsv(item.email),
        escapeCsv(item.countryCode),
        escapeCsv(item.phone),
        escapeCsv(item.dob),
        escapeCsv(item.grade),
        escapeCsv(item.isBhStudent ? 'Yes' : 'No'),
        escapeCsv(item.country),
        escapeCsv(item.school),
        escapeCsv(subjects),
        escapeCsv(item.role),
        escapeCsv(item.motivation),
        escapeCsv(item.priority),
        escapeCsv(item.dashboardNotes),
        escapeCsv(item.status)
      ].join(',') + '\n';
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader(
      'Content-Disposition',
      'attachment; filename=dashboard-info-' + new Date().toISOString().slice(0, 10) + '.csv'
    );
    res.send(csv);
  } catch (err) {
    console.error('Dashboard export error:', err);
    res.status(500).json({ success: false, error: 'Export failed' });
  }
});

// Original Submission Routes (modified to also update dashboard info)

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
// server.js (continued)
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
    
    // Delete from both collections
    const submissionResult = await Submission.deleteMany({ _id: { $in: validIds } });
    const dashboardResult = await DashboardInfo.deleteMany({ _id: { $in: validIds } });
    
    res.json({ 
      success: true, 
      deleted: submissionResult.deletedCount,
      dashboardDeleted: dashboardResult.deletedCount,
      message: `Deleted ${submissionResult.deletedCount} submissions and ${dashboardResult.deletedCount} dashboard entries`
    });
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

// Bulk update submissions status (protected) - also updates dashboard
app.put('/api/submissions/bulk-update', authenticateToken, async (req, res) => {
  try {
    const { ids, status } = req.body;
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ success: false, error: 'Invalid submission IDs' });
    }
    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({ success: false, error: 'Invalid status' });
    }
    
    // Update submissions
    const submissionResult = await Submission.updateMany(
      { _id: { $in: ids } },
      { $set: { status } }
    );
    
    // Update dashboard info
    const dashboardResult = await DashboardInfo.updateMany(
      { _id: { $in: ids } },
      { $set: { status, lastUpdated: new Date() } }
    );
    
    res.json({ 
      success: true, 
      updated: submissionResult.modifiedCount,
      dashboardUpdated: dashboardResult.modifiedCount
    });
  } catch (err) {
    console.error('Bulk update error:', err);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// Update single submission (protected) - also updates dashboard
app.put('/api/submissions/:id', authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    const { status, notes } = req.body;
    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({ success: false, error: 'Invalid status' });
    }
    
    // Update submission
    const submissionResult = await Submission.updateOne(
      { _id: id },
      { $set: { status, notes: notes || '' } }
    );
    
    if (submissionResult.matchedCount === 0) {
      return res.status(404).json({ success: false, error: 'Submission not found' });
    }
    
    // Update dashboard info
    await DashboardInfo.updateOne(
      { _id: id },
      { $set: { status, notes: notes || '', lastUpdated: new Date() } }
    );
    
    res.json({ success: true, updated: submissionResult.modifiedCount });
  } catch (err) {
    console.error('Update submission error:', err);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// Delete single submission (protected) - also deletes from dashboard
app.delete('/api/submissions/:id', authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    
    // Delete from both collections
    const submissionResult = await Submission.deleteOne({ _id: id });
    const dashboardResult = await DashboardInfo.deleteOne({ _id: id });
    
    if (submissionResult.deletedCount === 0) {
      return res.status(404).json({ success: false, error: 'Submission not found' });
    }
    
    res.json({ 
      success: true, 
      deleted: submissionResult.deletedCount,
      dashboardDeleted: dashboardResult.deletedCount
    });
  } catch (err) {
    console.error('Delete submission error:', err);
    res.status(500).json({ success: false, error: 'Database error' });
  }
});

// Create submission (public) with rate limiting except admin - also copies to dashboard
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
      role: role || null,
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
    
    console.log('Submission object before saving:', submission);
    await submission.save();
    
    // Also copy to dashboard info
    await copySubmissionToDashboard(submission);
    
    res.redirect('https://bhsciencesociety.vercel.app/thank-you.html');

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
// Approve submission (generate password, create user, send email) - also updates dashboard
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

    // Update submission status
    submission.status = 'approved';
    await submission.save();
    
    // Update dashboard info
    await DashboardInfo.updateOne(
      { _id: req.params.id },
      { $set: { status: 'approved', lastUpdated: new Date() } }
    );

    // SendGrid email
    const msg = {
      to: submission.email,
      from: process.env.FROM_EMAIL,
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

// Get user profile

// Reject submission - also updates dashboard
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
    
    // Update dashboard info
    const dashboardUpdate = {
      status: 'rejected',
      notes: notes || '',
      lastUpdated: new Date()
    };
    if (rejectionDetails) {
      dashboardUpdate.rejectionDetails = rejectionDetails;
    }
    await DashboardInfo.updateOne({ _id: req.params.id }, { $set: dashboardUpdate });

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
