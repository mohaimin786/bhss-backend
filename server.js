const express = require('express');
const Datastore = require('nedb');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fetch = require('node-fetch');
const nodemailer = require('nodemailer');



const app = express();
const db = new Datastore({ filename: 'submissions.db', autoload: true });
const usersDb = new Datastore({ filename: 'users.db', autoload: true });

const secretKey =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

app.use(
  session({
    secret: secretKey,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
    },
  })
);

app.set('trust proxy', true);

app.use(function (req, res, next) {
  res.header('Access-Control-Allow-Origin', 'https://stackblitz-starters-uogm5vlf.vercel.app');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');

  // Respond immediately to preflight requests
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }

  next();
});
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));




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
    return req.connection.remoteAddress;
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
  skip: function (req, res) {
    return req.session.authenticated;
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

app.use(function (req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

const ADMIN_CREDENTIALS = {
  username: process.env.ADMIN_USER || 'BHSS_COUNCIL',
  password: process.env.ADMIN_PASS
    ? bcrypt.hashSync(process.env.ADMIN_PASS, 10)
    : bcrypt.hashSync('temporary1234', 10),
};

function requireAuth(req, res, next) {
  if (req.session.authenticated) {
    return next();
  }
  res.status(403).json({ error: 'Authentication required' });
}

app.post('/api/admin/login', loginLimiter, express.json(), function (req, res) {
  var username = req.body.username;
  var password = req.body.password;

  if (
    username === ADMIN_CREDENTIALS.username &&
    bcrypt.compareSync(password, ADMIN_CREDENTIALS.password)
  ) {
    req.session.authenticated = true;
    req.session.user = { username: username };
    return res.json({ success: true });
  }

  res.status(401).json({ success: false, error: 'Invalid credentials' });
});

app.post('/api/admin/logout', function (req, res) {
  req.session.destroy(function (err) {
    if (err) {
      console.error('Session destruction error:', err);
    }
    res.json({ success: true });
  });
});

app.get('/api/admin/status', function (req, res) {
  res.json({ authenticated: !!req.session.authenticated });
});

app.get('/api/rate-test', submissionLimiter, function (req, res) {
  res.json({
    success: true,
    message: 'Rate test passed',
    ip: req.ip,
    forwardedFor: req.headers['x-forwarded-for'],
  });
});

app.get('/api/submissions/export-filtered', requireAuth, function (req, res) {
  db.find({})
    .sort({ timestamp: -1 })
    .exec(function (err, docs) {
      if (err) {
        console.error('Export error:', err);
        return res.status(500).json({ success: false, error: 'Export failed' });
      }

      // CSV header row with only the required fields
      let csv = 'Full Name,Email,Country Code,Phone Number,Date of Birth,Grade,Is BH Student,Country,School Name,Subjects,Motivation\n';

      docs.forEach(function (sub) {
        // Format each field with proper escaping
        const escapeCsv = (str) => {
          if (!str) return '';
          return `"${String(str).replace(/"/g, '""')}"`;
        };

        // Format subjects array
        const subjects = sub.subjects ? sub.subjects.join('; ') : '';

        // Build the CSV row
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

app.delete('/api/submissions/bulk-delete', requireAuth, express.json(), (req, res) => {
  try {
    const { ids } = req.body;

    // Validate input
    if (!ids || !Array.isArray(ids)) {
      return res.status(400).json({ 
        success: false, 
        error: 'IDs must be provided as an array' 
      });
    }

    // Convert all IDs to strings and filter empty ones
    const validIds = ids.map(id => String(id)).filter(id => id.trim().length > 0);

    if (validIds.length === 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'No valid IDs provided' 
      });
    }

    // Perform deletion
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


app.put('/api/submissions/bulk-update', requireAuth, function (req, res) {
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

app.put('/api/submissions/:id', requireAuth, function (req, res) {
  db.update(
    { _id: req.params.id },
    {
      $set: {
        status: req.body.status,
        notes: req.body.notes || '',
      },
    },
    {},
    function (err, numReplaced) {
      if (err)
        return res
          .status(500)
          .json({ success: false, error: 'Database error' });
      res.json({ success: true, updated: numReplaced });
    }
  );
});

// Single delete endpoint
app.delete('/api/submissions/:id', requireAuth, (req, res) => {
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

// Single status update endpoint
// Single status update (merged with notes update)
app.put('/api/submissions/:id', requireAuth, express.json(), (req, res) => {
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

app.get('/api/submissions', requireAuth, function (req, res) {
  db.find({})
    .sort({ timestamp: -1 })
    .exec(function (err, docs) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true, data: docs });
    });
});
// Approve submission: generates password, stores user, sends email
app.post('/api/submissions/:id/approve', requireAuth, async (req, res) => {
  try {
    // Find submission
    const submission = await new Promise((resolve, reject) => {
      db.findOne({ _id: req.params.id }, (err, doc) => {
        if (err) reject(err);
        else resolve(doc);
      });
    });

    if (!submission) {
      return res.status(404).json({ success: false, error: 'Submission not found' });
    }

    // Generate random password
    const plainPassword = crypto.randomBytes(8).toString('hex');
    const hashedPassword = await bcrypt.hash(plainPassword, 10);

    // Save to users database
    usersDb.insert({
      fullName: submission.fullName,
      email: submission.email,
      password: hashedPassword,
      createdAt: new Date()
    });

    // Update submission status
    db.update({ _id: req.params.id }, { $set: { status: 'approved' } }, {}, async () => {
      // Send acceptance email
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
app.post('/api/submissions/:id/reject', requireAuth, async (req, res) => {
  try {
    // Find submission
    const submission = await new Promise((resolve, reject) => {
      db.findOne({ _id: req.params.id }, (err, doc) => {
        if (err) reject(err);
        else resolve(doc);
      });
    });

    if (!submission) {
      return res.status(404).json({ success: false, error: 'Submission not found' });
    }

    // Update submission status
    db.update({ _id: req.params.id }, { $set: { status: 'rejected' } }, {}, async () => {
      // Send rejection email
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


app.get('/', function (req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/register', function (req, res) {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/admin', function (req, res) {
  if (!req.session.authenticated) {
    return res.redirect('/admin-login');
  }
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin-login', function (req, res) {
  res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
});

var PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
  console.log('Server running on port', PORT);
  console.log('Rate limiting configured for 3 submissions per IP per 24 hours');
});
