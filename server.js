// server.js
const express = require('express');
const Datastore = require('nedb');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fetch = require('node-fetch');
const nodemailer = require('nodemailer');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const db = new Datastore({ filename: 'submissions.db', autoload: true });
const usersDb = new Datastore({ filename: 'users.db', autoload: true });

// Use an env var for JWT secret if provided, otherwise generate a random secret.
// NOTE: if you rely on the generated secret, tokens will be invalid after a server restart.
// Recommended: set process.env.JWT_SECRET in your Railway environment variables.
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(48).toString('hex');

// CORS: allow your frontend origin and allow Authorization header
app.use(cors({
  origin: 'https://stackblitz-starters-uogm5vlf.vercel.app',
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS']
}));

// Trust proxy for Railway / Vercel TLS handling
app.set('trust proxy', 1);

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// -------------------- Rate limiters --------------------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts, please try again later',
});

const submissionLimiter = rateLimit({
  windowMs: 24 * 60 * 60 * 1000,
  max: 3,
  message:
    'You have reached the maximum number of submissions allowed per day (3). Please try again tomorrow.',
  keyGenerator: function (req) {
    var forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
      var ips = forwarded.split(',');
      return ips[0].trim();
    }
    return req.connection.remoteAddress || req.ip;
  },
  handler: function (req, res) {
    console.log(
      'Rate limit exceeded for IP:',
      req.headers['x-forwarded-for'] || req.ip
    );
    res.status(429).json({
      success: false,
      error:
        'You have reached the maximum number of submissions allowed per day (3). Please try again tomorrow.',
    });
  },
  // Skip rate limiting for authenticated admin (via valid JWT)
  skip: function (req, res) {
    // If a valid admin token is present, skip
    try {
      const authHeader = req.headers['authorization'];
      if (!authHeader) return false;
      const token = authHeader.split(' ')[1];
      if (!token) return false;
      const decoded = jwt.verify(token, JWT_SECRET);
      // Optionally you can check decoded.role or username to ensure it's admin
      if (decoded && decoded.username && decoded.username === (process.env.ADMIN_USER || 'BHSS_COUNCIL')) {
        return true;
      }
      return false;
    } catch (err) {
      return false;
    }
  },
  onLimitReached: function (req) {
    console.log(
      'Rate limit reached for',
      req.headers['x-forwarded-for'] || req.ip,
      'at',
      new Date()
    );
  },
});

const ipinfoLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 100,
  message: 'Too many IP info requests, please try again later',
});

// -------------------- Helpers & Auth Middleware --------------------

// Admin credentials (hashed password)
const ADMIN_CREDENTIALS = {
  username: process.env.ADMIN_USER || 'BHSS_COUNCIL',
  password: process.env.ADMIN_PASS
    ? bcrypt.hashSync(process.env.ADMIN_PASS, 10)
    : bcrypt.hashSync('temporary1234', 10),
};

// Create JWT for admin
function createAdminToken(username) {
  const payload = {
    username: username,
    iss: 'bhss-backend',
  };
  // 1 day expiry
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' });
}

// Middleware to authenticate via Authorization header "Bearer <token>"
function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, error: 'Authentication required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ success: false, error: 'Invalid or expired token' });
      req.user = user;
      return next();
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Server error during authentication' });
  }
}

// Small utility: check token but don't return error (used for /api/admin/status)
function checkToken(req) {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return null;
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded;
  } catch (err) {
    return null;
  }
}

// -------------------- Routes --------------------

// IP info route (uses external IP APIs)
app.get('/api/ipinfo', ipinfoLimiter, async (req, res) => {
  try {
    const forwardedHeader = req.headers['x-forwarded-for'];
    const clientIp = forwardedHeader
      ? forwardedHeader.split(',')[0].trim()
      : req.ip;

    const apiKey = process.env.IPAPI_KEY || '';
    const ipapiUrl = apiKey
      ? `https://ipapi.co/${clientIp}/json/?key=${apiKey}`
      : 'https://ipapi.co/json/';
    const fallbackUrl = 'https://ipwhois.app/json/';

    console.log('Fetching IP data from:', ipapiUrl);

    let response = await fetch(ipapiUrl);

    if (!response.ok) {
      console.warn('ipapi failed with status:', response.status);
      response = await fetch(fallbackUrl);
    }

    if (!response.ok) {
      const errorText = await response.text();
      console.error('All IP APIs failed:', errorText);
      throw new Error('Both IP API services failed');
    }

    const data = await response.json();

    res.json({
      country: data.country || data.country_name,
      countryCode: data.country_code,
      ip: data.ip,
    });
  } catch (error) {
    console.error('IP detection error:', error);
    res.status(500).json({
      success: false,
      error: 'Could not detect location',
      fallback: true,
    });
  }
});

// Security headers
app.use(function (req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// -------------------- Admin auth endpoints --------------------

app.post('/api/admin/login', loginLimiter, express.json(), function (req, res) {
  try {
    var username = req.body.username;
    var password = req.body.password;

    if (
      username === ADMIN_CREDENTIALS.username &&
      bcrypt.compareSync(password, ADMIN_CREDENTIALS.password)
    ) {
      // create and return token to the client
      const token = createAdminToken(username);
      return res.json({ success: true, token: token });
    }

    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ success: false, error: 'Server error during login' });
  }
});

// Logout: with JWT stateless auth, logout is client-side (remove token).
// Provide endpoint for convenience (no server-side invalidation here).
app.post('/api/admin/logout', function (req, res) {
  // Nothing to do server-side unless you implement token revocation.
  res.json({ success: true, message: 'Client should delete the stored token' });
});

// Status: returns whether a provided token is valid
app.get('/api/admin/status', function (req, res) {
  const decoded = checkToken(req);
  if (decoded) return res.json({ authenticated: true, user: decoded });
  return res.json({ authenticated: false });
});

// -------------------- Rate-test --------------------
app.get('/api/rate-test', submissionLimiter, function (req, res) {
  res.json({
    success: true,
    message: 'Rate test passed',
    ip: req.ip,
    forwardedFor: req.headers['x-forwarded-for'],
  });
});

// -------------------- Submissions CRUD (protected) --------------------

// Export filtered CSV (protected)
app.get('/api/submissions/export-filtered', authenticateToken, function (req, res) {
  db.find({})
    .sort({ timestamp: -1 })
    .exec(function (err, docs) {
      if (err) {
        console.error('Export error:', err);
        return res.status(500).json({ success: false, error: 'Export failed' });
      }

      let csv = 'Full Name,Email,Country Code,Phone Number,Date of Birth,Grade,Is BH Student,Country,School Name,Subjects,Motivation\n';

      docs.forEach(function (sub) {
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
          escapeCsv(sub.motivation)
        ].join(',') + '\n';
      });

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader(
        'Content-Disposition',
        'attachment; filename=filtered-submissions-' +
          new Date().toISOString().slice(0, 10) +
          '.csv'
      );
      res.send(csv);
    });
});

app.delete('/api/submissions/bulk-delete', authenticateToken, express.json(), (req, res) => {
  try {
    const { ids } = req.body;

    if (!ids || !Array.isArray(ids)) {
      return res.status(400).json({
        success: false,
        error: 'IDs must be provided as an array'
      });
    }

    const validIds = ids.map(id => String(id)).filter(id => id.trim().length > 0);

    if (validIds.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'No valid IDs provided'
      });
    }

    db.remove({ _id: { $in: validIds } }, { multi: true }, (err, numRemoved) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({
          success: false,
          error: 'Database operation failed'
        });
      }

      res.json({
        success: true,
        deleted: numRemoved,
        message: `Deleted ${numRemoved} submissions`
      });
    });
  } catch (err) {
    console.error('Server error:', err);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

app.put('/api/submissions/bulk-update', authenticateToken, express.json(), function (req, res) {
  var ids = req.body.ids;
  var status = req.body.status;

  if (!ids || !Array.isArray(ids)) {
    return res
      .status(400)
      .json({ success: false, error: 'Invalid submission IDs' });
  }

  if (!['pending', 'approved', 'rejected'].includes(status)) {
    return res.status(400).json({ success: false, error: 'Invalid status' });
  }

  db.update(
    { _id: { $in: ids } },
    { $set: { status: status } },
    { multi: true },
    function (err, numUpdated) {
      if (err) {
        return res
          .status(500)
          .json({ success: false, error: 'Database error' });
      }
      res.json({ success: true, updated: numUpdated });
    }
  );
});

// Update single submission (status + notes)
app.put('/api/submissions/:id', authenticateToken, express.json(), function (req, res) {
  const id = req.params.id;
  const { status, notes } = req.body;

  if (!['pending', 'approved', 'rejected'].includes(status)) {
    return res.status(400).json({ success: false, error: 'Invalid status' });
  }

  db.update(
    { _id: id },
    { $set: { status, notes: notes || '' } },
    {},
    (err, numReplaced) => {
      if (err) return res.status(500).json({ success: false, error: 'Database error' });
      res.json({ success: true, updated: numReplaced });
    }
  );
});

// Delete single submission
app.delete('/api/submissions/:id', authenticateToken, (req, res) => {
  const id = req.params.id;

  db.remove({ _id: id }, {}, (err, numRemoved) => {
    if (err) {
      console.error('Delete error:', err);
      return res.status(500).json({
        success: false,
        error: 'Database error'
      });
    }

    if (numRemoved === 0) {
      return res.status(404).json({
        success: false,
        error: 'Submission not found'
      });
    }

    res.json({
      success: true,
      deleted: numRemoved
    });
  });
});

// Create submission (public)
app.post('/api/submit', submissionLimiter, express.json(), function (req, res) {
  if (
    !req.body.fullName ||
    !req.body.email ||
    !req.body.phone ||
    !req.body.dob ||
    !req.body.grade ||
    !req.body.isBhStudent
  ) {
    return res
      .status(400)
      .json({ success: false, error: 'All required fields must be filled' });
  }

  if (!req.body.subjects || req.body.subjects.length === 0) {
    return res
      .status(400)
      .json({ success: false, error: 'Please select at least one subject' });
  }

  if (!req.body.motivation || req.body.motivation.length < 50) {
    return res
      .status(400)
      .json({
        success: false,
        error: 'Motivation must be at least 50 characters long',
      });
  }

  if (req.body.isBhStudent === 'yes' && !req.body.section) {
    return res
      .status(400)
      .json({ success: false, error: 'Section is required for BH students' });
  }

  if (
    req.body.isBhStudent === 'no' &&
    (!req.body.country || !req.body.school)
  ) {
    return res
      .status(400)
      .json({
        success: false,
        error: 'Country and School are required for non-BH students',
      });
  }

  var submission = {
    fullName: req.body.fullName,
    email: req.body.email,
    countryCode: req.body.countryCode,
    phone: req.body.phone,
    dob: req.body.dob,
    grade: req.body.grade,
    isBhStudent: req.body.isBhStudent === 'yes',
    bhBranch: req.body.bhBranch || null,
    section: req.body.section || null,
    city: req.body.city || null,
    school: req.body.school || null,
    country: req.body.country || null,
    subjects: req.body.subjects,
    category: req.body.category || null,
    motivation: req.body.motivation,
    whyChosenSubjects: req.body.whyChosenSubjects || null,
    heardAbout: req.body.heardAbout || null,
    social: req.body.social || null,
    prevCompetitions: req.body.prevCompetitions || null,
    skills: req.body.skills || null,
    ideas: req.body.ideas || null,
    status: 'pending',
    timestamp: new Date(),
  };
  console.log("Incoming submission data:", req.body);
  db.insert(submission, function (err, doc) {
    if (err)
      return res.status(500).json({ success: false, error: 'Database error' });
    console.log(
      'New submission from IP:',
      submission.ipAddress,
      'at',
      new Date()
    );
    res.json({ success: true, id: doc._id });
  });
});

// Get submissions (protected)
app.get('/api/submissions', authenticateToken, function (req, res) {
  db.find({})
    .sort({ timestamp: -1 })
    .exec(function (err, docs) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true, data: docs });
    });
});

// Approve submission: generates password, stores user, sends email
app.post('/api/submissions/:id/approve', authenticateToken, async (req, res) => {
  try {
    const submission = await new Promise((resolve, reject) => {
      db.findOne({ _id: req.params.id }, (err, doc) => {
        if (err) reject(err);
        else resolve(doc);
      });
    });

    if (!submission) {
      return res.status(404).json({ success: false, error: 'Submission not found' });
    }

    const plainPassword = crypto.randomBytes(8).toString('hex');
    const hashedPassword = await bcrypt.hash(plainPassword, 10);

    usersDb.insert({
      fullName: submission.fullName,
      email: submission.email,
      password: hashedPassword,
      createdAt: new Date()
    });

    db.update({ _id: req.params.id }, { $set: { status: 'approved' } }, {}, async () => {
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });

      await transporter.sendMail({
        from: `"BHSS" <${process.env.SMTP_USER}>`,
        to: submission.email,
        subject: "BHSS Registration Approved",
        text: `Hello ${submission.fullName},\n\nCongratulations! Your registration has been approved.\n\nYour login password is: ${plainPassword}\n\nPlease keep it safe.\n\nBest regards,\nBHSS Council`
      });

      res.json({ success: true, message: 'User approved and email sent' });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Reject submission: updates status, sends rejection email
app.post('/api/submissions/:id/reject', authenticateToken, async (req, res) => {
  try {
    const submission = await new Promise((resolve, reject) => {
      db.findOne({ _id: req.params.id }, (err, doc) => {
        if (err) reject(err);
        else resolve(doc);
      });
    });

    if (!submission) {
      return res.status(404).json({ success: false, error: 'Submission not found' });
    }

    db.update({ _id: req.params.id }, { $set: { status: 'rejected' } }, {}, async () => {
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });

      await transporter.sendMail({
        from: `"BHSS" <${process.env.SMTP_USER}>`,
        to: submission.email,
        subject: "BHSS Registration Decision",
        text: `Hello ${submission.fullName},\n\nWe appreciate your interest in joining BHSS, but unfortunately your registration has not been approved at this time.\n\nWe encourage you to apply again in the future.\n\nBest regards,\nBHSS Council`
      });

      res.json({ success: true, message: 'User rejected and email sent' });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// -------------------- Static pages --------------------

// Serve landing pages (frontend handles redirect/login state)
app.get('/', function (req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/register', function (req, res) {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});
// Serve admin pages - frontend should check the token and redirect if invalid
app.get('/admin', function (req, res) {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
app.get('/admin-login', function (req, res) {
  res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
});

// -------------------- Start server --------------------
var PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
  console.log('Server running on port', PORT);
  console.log('Rate limiting configured for 3 submissions per IP per 24 hours');
});
