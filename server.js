const express = require('express');
const mysql = require('mysql2');
const dotenv = require('dotenv');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

dotenv.config();

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const app = express();
const PORT = process.env.PORT || 4000;

// Helper function to generate correct file URLs
const getFileUrl = (req, file) => {
  if (process.env.CLOUDINARY_CLOUD_NAME && file.url) {
    return file.url;
  }
  const host = req.get('host');
  const filename = file.filename || file;
  if (req.get('x-forwarded-proto') === 'https' || process.env.NODE_ENV === 'production') {
    return `https://${host}/uploads/${filename}`;
  }
  return `${req.protocol}://${host}/uploads/${filename}`;
};

// Ensure uploads directory exists
const uploadDir = 'uploads/';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Middleware
app.use(cors());
app.use(express.json());

// Database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'careerlinkgh_db',
  port: process.env.DB_PORT || 3306,
  ssl: process.env.DB_HOST ? { rejectUnauthorized: false } : null
});

db.connect(err => {
  if (err) {
    console.log('❌ Database connection failed:', err.message);
  } else {
    console.log('✅ Database connected successfully');
    
    // Create notifications table after DB is connected
    const createNotificationsTable = `
      CREATE TABLE IF NOT EXISTS notifications (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        type ENUM('application', 'new_application', 'application_update', 'job_alert', 'message', 'system', 'interview') NOT NULL,
        title VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        related_id VARCHAR(36),
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        read_at TIMESTAMP NULL,
        INDEX idx_user_id (user_id),
        INDEX idx_created_at (created_at),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `;
    
    db.query(createNotificationsTable, (err) => {
      if (err) {
        console.error('Error creating notifications table:', err);
      } else {
        console.log('✅ Notifications table ready');
      }
    });
  }
});

// Helper function to create notification
const createNotification = (userId, type, title, message, relatedId = null) => {
  if (!userId) {
    console.error('Cannot create notification: userId is required');
    return;
  }
  
  const notificationId = uuidv4();
  db.query(
    'INSERT INTO notifications (id, user_id, type, title, message, related_id, is_read, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, NOW())',
    [notificationId, userId, type, title, message, relatedId],
    (err) => {
      if (err) {
        console.error('Error creating notification:', err);
      } else {
        console.log(`✅ Notification created: ${type} for user ${userId}`);
      }
    }
  );
};

// ==================== AUTH MIDDLEWARE ====================
const authMiddleware = (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) throw new Error();
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'careerlinkgh_secret_key_2024');
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: 'Please authenticate' });
  }
};

// ==================== AUTH ROUTES ====================

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, first_name, last_name, phone, user_type, company_name } = req.body;
    
    console.log('📝 Register attempt for:', email);
    console.log('📝 User type:', user_type);
    console.log('📝 Company name received:', company_name);

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      
      if (results.length > 0) {
        return res.status(400).json({ success: false, message: 'User already exists' });
      }

      const salt = await bcrypt.genSalt(10);
      const password_hash = await bcrypt.hash(password, salt);
      const userId = uuidv4();

      db.query(
        'INSERT INTO users (id, email, password_hash, first_name, last_name, phone, user_type) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [userId, email, password_hash, first_name, last_name, phone || null, user_type || 'job_seeker'],
        (err, result) => {
          if (err) {
            console.error('Insert error:', err);
            return res.status(500).json({ success: false, message: 'Registration failed' });
          }

          if (user_type === 'employer') {
            const employerId = uuidv4();
            const companyName = company_name || `${first_name}'s Company`;
            console.log('📝 Creating employer with company name:', companyName);
            db.query(
              'INSERT INTO employers (id, user_id, company_name) VALUES (?, ?, ?)',
              [employerId, userId, companyName]
            );
          } else if (user_type === 'job_seeker') {
            const seekerId = uuidv4();
            db.query('INSERT INTO job_seekers (id, user_id) VALUES (?, ?)', [seekerId, userId]);
          }

          const token = jwt.sign(
            { id: userId, email, user_type },
            process.env.JWT_SECRET || 'careerlinkgh_secret_key_2024',
            { expiresIn: '24h' }
          );

          res.status(201).json({
            success: true,
            message: 'Registration successful',
            data: {
              user: { id: userId, email, first_name, last_name, user_type },
              token
            }
          });
        }
      );
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Login endpoint
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  
  console.log('🔑 Login attempt for:', email);

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    
    if (results.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const user = results[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    db.query('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);

    const token = jwt.sign(
      { id: user.id, email: user.email, user_type: user.user_type },
      process.env.JWT_SECRET || 'careerlinkgh_secret_key_2024',
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user.id,
          email: user.email,
          first_name: user.first_name,
          last_name: user.last_name,
          user_type: user.user_type
        },
        token
      }
    });
  });
});

// Get current user
app.get('/api/auth/me', authMiddleware, (req, res) => {
  db.query(
    `SELECT u.id, u.email, u.first_name, u.last_name, u.phone, u.user_type, u.email_verified, u.avatar_url,
            e.id as employer_id, e.company_name, e.company_logo, e.company_description, e.industry, e.city, e.verified as company_verified,
            js.id as job_seeker_id, js.headline, js.location, js.skills, js.resume_url, js.experience_years,
            js.current_salary, js.expected_salary, js.bio, js.summary, js.experiences, js.educations, js.is_open_to_work
     FROM users u
     LEFT JOIN employers e ON u.id = e.user_id
     LEFT JOIN job_seekers js ON u.id = js.user_id
     WHERE u.id = ?`,
    [req.user.id],
    (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      if (results.length === 0) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }
      res.json({ success: true, data: results[0] });
    }
  );
});

// ==================== JOB CATEGORIES ====================
app.get('/api/categories', (req, res) => {
  db.query('SELECT * FROM job_categories ORDER BY name', (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, data: results });
  });
});

// ==================== JOBS CRUD ====================

// Create job (employer only)
app.post('/api/jobs', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'employer') {
    return res.status(403).json({ success: false, message: 'Only employers can post jobs' });
  }

  db.query('SELECT id FROM employers WHERE user_id = ?', [req.user.id], (err, employerResults) => {
    if (err || employerResults.length === 0) {
      return res.status(400).json({ success: false, message: 'Employer profile not found' });
    }

    const employer_id = employerResults[0].id;
    const jobId = uuidv4();
    const {
      title, description, requirements, benefits, job_type,
      experience_level, category_id, location, is_remote,
      salary_min, salary_max, salary_currency, application_deadline,
      is_featured, is_urgent
    } = req.body;

    const slug = title.toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/(^-|-$)/g, '');

    db.query(
      `INSERT INTO jobs (
        id, employer_id, title, slug, description, requirements, benefits,
        job_type, experience_level, category_id, location, is_remote,
        salary_min, salary_max, salary_currency, application_deadline,
        is_featured, is_urgent, is_active, views_count, applications_count
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        jobId, employer_id, title, slug, description, requirements, benefits,
        job_type, experience_level, category_id, location, is_remote || false,
        salary_min || null, salary_max || null, salary_currency || 'GHS',
        application_deadline || null, is_featured || false, is_urgent || false,
        true, 0, 0
      ],
      (err, result) => {
        if (err) {
          console.error('Job creation error:', err);
          return res.status(500).json({ success: false, message: 'Failed to create job' });
        }

        db.query(
          `UPDATE employers SET total_jobs_posted = total_jobs_posted + 1, active_jobs = active_jobs + 1 WHERE id = ?`,
          [employer_id]
        );

        res.status(201).json({
          success: true,
          message: 'Job posted successfully',
          data: { job_id: jobId }
        });
      }
    );
  });
});

// Get all jobs with filters
app.get('/api/jobs', (req, res) => {
  let query = `
    SELECT j.*, 
           e.company_name, e.company_logo, e.verified as company_verified,
           c.name as category_name, c.icon as category_icon
    FROM jobs j
    LEFT JOIN employers e ON j.employer_id = e.id
    LEFT JOIN job_categories c ON j.category_id = c.id
    WHERE j.is_active = true
  `;
  
  const params = [];

  if (req.query.search) {
    query += ` AND (j.title LIKE ? OR j.description LIKE ?)`;
    params.push(`%${req.query.search}%`, `%${req.query.search}%`);
  }
  if (req.query.location) {
    query += ` AND j.location LIKE ?`;
    params.push(`%${req.query.location}%`);
  }
  if (req.query.type) {
    query += ` AND j.job_type = ?`;
    params.push(req.query.type);
  }
  if (req.query.category) {
    query += ` AND j.category_id = ?`;
    params.push(req.query.category);
  }
  if (req.query.experience) {
    query += ` AND j.experience_level = ?`;
    params.push(req.query.experience);
  }

  query += ` ORDER BY j.created_at DESC`;

  if (req.query.limit) {
    query += ` LIMIT ?`;
    params.push(parseInt(req.query.limit));
  }

  db.query(query, params, (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, data: results });
  });
});

// Get single job by ID
app.get('/api/jobs/:id', (req, res) => {
  db.query('UPDATE jobs SET views_count = views_count + 1 WHERE id = ?', [req.params.id]);

  db.query(
    `SELECT j.*, 
            e.company_name, e.company_logo, e.company_description, e.verified as company_verified,
            c.name as category_name, c.icon as category_icon
     FROM jobs j
     LEFT JOIN employers e ON j.employer_id = e.id
     LEFT JOIN job_categories c ON j.category_id = c.id
     WHERE j.id = ? AND j.is_active = true`,
    [req.params.id],
    (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      if (results.length === 0) {
        return res.status(404).json({ success: false, message: 'Job not found' });
      }
      res.json({ success: true, data: results[0] });
    }
  );
});

// ==================== APPLICATIONS WITH NOTIFICATIONS ====================

// Apply for a job
app.post('/api/jobs/:jobId/apply', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'job_seeker') {
    return res.status(403).json({ success: false, message: 'Only job seekers can apply' });
  }

  db.query('SELECT id FROM job_seekers WHERE user_id = ?', [req.user.id], (err, seekerResults) => {
    if (err || seekerResults.length === 0) {
      return res.status(400).json({ success: false, message: 'Job seeker profile not found' });
    }

    const job_seeker_id = seekerResults[0].id;
    const { cover_letter, resume_url } = req.body;
    const applicationId = uuidv4();

    db.query(
      'SELECT id FROM applications WHERE job_id = ? AND job_seeker_id = ?',
      [req.params.jobId, job_seeker_id],
      (err, results) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (results.length > 0) {
          return res.status(400).json({ success: false, message: 'Already applied for this job' });
        }

        db.query('SELECT j.title, j.employer_id, e.user_id as employer_user_id FROM jobs j LEFT JOIN employers e ON j.employer_id = e.id WHERE j.id = ?', [req.params.jobId], (err, jobResults) => {
          if (err || jobResults.length === 0) {
            console.error('Job not found:', err);
            return res.status(400).json({ success: false, message: 'Job not found' });
          }

          const jobTitle = jobResults[0].title;
          const employerUserId = jobResults[0].employer_user_id;

          db.query(
            'INSERT INTO applications (id, job_id, job_seeker_id, cover_letter, resume_url) VALUES (?, ?, ?, ?, ?)',
            [applicationId, req.params.jobId, job_seeker_id, cover_letter, resume_url],
            (err, result) => {
              if (err) {
                console.error('Application error:', err);
                return res.status(500).json({ success: false, message: 'Failed to submit application' });
              }

              db.query('UPDATE jobs SET applications_count = applications_count + 1 WHERE id = ?', [req.params.jobId]);

              // Notification for job seeker
              createNotification(
                req.user.id,
                'application',
                'Application Submitted',
                `You have successfully applied for "${jobTitle}"`,
                req.params.jobId
              );

              // Get seeker's name for employer notification
              db.query('SELECT first_name, last_name FROM users WHERE id = ?', [req.user.id], (err, userResults) => {
                const seekerName = userResults && userResults.length > 0 ? `${userResults[0].first_name} ${userResults[0].last_name}` : 'A candidate';
                
                // Notification for employer
                createNotification(
                  employerUserId,
                  'new_application',
                  'New Application Received',
                  `${seekerName} has applied for "${jobTitle}"`,
                  req.params.jobId
                );
              });

              res.status(201).json({
                success: true,
                message: 'Application submitted successfully',
                data: { application_id: applicationId }
              });
            }
          );
        });
      }
    );
  });
});

// Update application status (employer only) - WITH NOTIFICATIONS
app.put('/api/applications/:id/status', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'employer') {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  const { status, interview_date, interview_notes } = req.body;

  db.query(
    `SELECT a.id, a.job_id, a.job_seeker_id, j.title 
     FROM applications a
     LEFT JOIN jobs j ON a.job_id = j.id
     LEFT JOIN employers e ON j.employer_id = e.id
     WHERE a.id = ? AND e.user_id = ?`,
    [req.params.id, req.user.id],
    (err, results) => {
      if (err || results.length === 0) {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
      }

      const application = results[0];
      const jobTitle = application.title;

      db.query(
        `UPDATE applications 
         SET status = ?, interview_date = ?, interview_notes = ?, updated_at = NOW()
         WHERE id = ?`,
        [status, interview_date, interview_notes, req.params.id],
        (err, result) => {
          if (err) {
            console.error('Update error:', err);
            return res.status(500).json({ success: false, message: 'Failed to update status' });
          }

          // Get job seeker's user_id and name
          db.query(
            'SELECT js.user_id, u.first_name, u.last_name FROM job_seekers js LEFT JOIN users u ON js.user_id = u.id WHERE js.id = ?',
            [application.job_seeker_id],
            (err, seekerResults) => {
              if (seekerResults && seekerResults.length > 0) {
                const seekerUserId = seekerResults[0].user_id;
                const seekerName = `${seekerResults[0].first_name || ''} ${seekerResults[0].last_name || ''}`.trim() || 'Candidate';

                let notificationTitle = 'Application Status Updated';
                let notificationMessage = `Your application for "${jobTitle}" has been ${status}`;
                let employerNotificationTitle = 'Application Status Updated';
                let employerNotificationMessage = `You have ${status} the application from ${seekerName} for "${jobTitle}"`;

                switch(status) {
                  case 'shortlisted':
                    notificationTitle = '🎉 Shortlisted!';
                    notificationMessage = `Great news! You've been shortlisted for "${jobTitle}"`;
                    employerNotificationTitle = 'Application Shortlisted';
                    employerNotificationMessage = `You have shortlisted ${seekerName} for "${jobTitle}"`;
                    break;
                  case 'interview':
                    notificationTitle = '📅 Interview Scheduled';
                    notificationMessage = `You have an interview scheduled for "${jobTitle}"${interview_date ? ` on ${new Date(interview_date).toLocaleDateString()}` : ''}`;
                    employerNotificationTitle = 'Interview Scheduled';
                    employerNotificationMessage = `You have scheduled an interview with ${seekerName} for "${jobTitle}"${interview_date ? ` on ${new Date(interview_date).toLocaleDateString()}` : ''}`;
                    break;
                  case 'accepted':
                    notificationTitle = '🎉 Congratulations!';
                    notificationMessage = `Congratulations! Your application for "${jobTitle}" has been accepted!`;
                    employerNotificationTitle = 'Application Accepted';
                    employerNotificationMessage = `You have accepted the application from ${seekerName} for "${jobTitle}"`;
                    break;
                  case 'rejected':
                    notificationTitle = 'Application Update';
                    notificationMessage = `Your application for "${jobTitle}" was not successful this time. Keep trying!`;
                    employerNotificationTitle = 'Application Rejected';
                    employerNotificationMessage = `You have rejected the application from ${seekerName} for "${jobTitle}"`;
                    break;
                }

                // Send notification to job seeker
                createNotification(
                  seekerUserId,
                  'application_update',
                  notificationTitle,
                  notificationMessage,
                  application.job_id
                );

                // Send notification to employer
                createNotification(
                  req.user.id,
                  'application_update',
                  employerNotificationTitle,
                  employerNotificationMessage,
                  application.job_id
                );
              }
            }
          );

          res.json({ success: true, message: 'Application status updated' });
        }
      );
    }
  );
});

// Get user's applications
app.get('/api/my-applications', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'job_seeker') {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  db.query(
    `SELECT a.*, 
            j.title as job_title, j.location, j.job_type,
            e.company_name, e.company_logo
     FROM applications a
     LEFT JOIN jobs j ON a.job_id = j.id
     LEFT JOIN employers e ON j.employer_id = e.id
     LEFT JOIN job_seekers js ON a.job_seeker_id = js.id
     WHERE js.user_id = ?
     ORDER BY a.applied_at DESC`,
    [req.user.id],
    (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      res.json({ success: true, data: results });
    }
  );
});

// Get applications for a job (employer only)
app.get('/api/jobs/:jobId/applications', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'employer') {
    return res.status(403).json({ success: false, message: 'Access denied - Employers only' });
  }

  db.query('SELECT id FROM employers WHERE user_id = ?', [req.user.id], (err, employerResults) => {
    if (err || employerResults.length === 0) {
      return res.status(404).json({ success: false, message: 'Employer profile not found' });
    }
    
    const employer_id = employerResults[0].id;
    
    db.query('SELECT id FROM jobs WHERE id = ? AND employer_id = ?', [req.params.jobId, employer_id], (err, jobResults) => {
      if (err || jobResults.length === 0) {
        return res.status(403).json({ success: false, message: 'This job does not belong to you' });
      }
      
      db.query(
        `SELECT a.*, 
                u.first_name, u.last_name, u.email, u.phone, u.avatar_url,
                js.headline, js.location, js.skills, js.resume_url, js.experience_years
         FROM applications a
         LEFT JOIN job_seekers js ON a.job_seeker_id = js.id
         LEFT JOIN users u ON js.user_id = u.id
         WHERE a.job_id = ?
         ORDER BY a.applied_at DESC`,
        [req.params.jobId],
        (err, results) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Database error' });
          }
          res.json({ success: true, data: results });
        }
      );
    });
  });
});

// ==================== SAVED JOBS ====================
app.post('/api/jobs/:jobId/save', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'job_seeker') {
    return res.status(403).json({ success: false, message: 'Only job seekers can save jobs' });
  }

  db.query('SELECT id FROM job_seekers WHERE user_id = ?', [req.user.id], (err, seekerResults) => {
    if (err || seekerResults.length === 0) {
      return res.status(400).json({ success: false, message: 'Job seeker profile not found' });
    }

    const job_seeker_id = seekerResults[0].id;

    db.query(
      'INSERT INTO saved_jobs (job_seeker_id, job_id) VALUES (?, ?)',
      [job_seeker_id, req.params.jobId],
      (err, result) => {
        if (err) {
          console.error('Save error:', err);
          return res.status(500).json({ success: false, message: 'Failed to save job' });
        }
        res.json({ success: true, message: 'Job saved successfully' });
      }
    );
  });
});

app.delete('/api/jobs/:jobId/save', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'job_seeker') {
    return res.status(403).json({ success: false, message: 'Only job seekers can unsave jobs' });
  }

  db.query('SELECT id FROM job_seekers WHERE user_id = ?', [req.user.id], (err, seekerResults) => {
    if (err || seekerResults.length === 0) {
      return res.status(400).json({ success: false, message: 'Job seeker profile not found' });
    }

    const job_seeker_id = seekerResults[0].id;

    db.query(
      'DELETE FROM saved_jobs WHERE job_seeker_id = ? AND job_id = ?',
      [job_seeker_id, req.params.jobId],
      (err, result) => {
        if (err) {
          console.error('Unsave error:', err);
          return res.status(500).json({ success: false, message: 'Failed to unsave job' });
        }
        res.json({ success: true, message: 'Job removed from saved' });
      }
    );
  });
});

app.get('/api/saved-jobs', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'job_seeker') {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  db.query(
    `SELECT j.*, e.company_name, e.company_logo
     FROM saved_jobs sj
     LEFT JOIN jobs j ON sj.job_id = j.id
     LEFT JOIN employers e ON j.employer_id = e.id
     LEFT JOIN job_seekers js ON sj.job_seeker_id = js.id
     WHERE js.user_id = ?
     ORDER BY sj.saved_at DESC`,
    [req.user.id],
    (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      res.json({ success: true, data: results });
    }
  );
});

// ==================== NOTIFICATION ROUTES ====================
app.get('/api/notifications', authMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  const offset = parseInt(req.query.offset) || 0;
  
  db.query(
    `SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    [req.user.id, limit, offset],
    (err, results) => {
      if (err) {
        console.error('Notifications error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      
      db.query(
        'SELECT COUNT(*) as unread FROM notifications WHERE user_id = ? AND is_read = false',
        [req.user.id],
        (err, countResult) => {
          if (err) {
            return res.json({ success: true, data: results, unread: 0 });
          }
          res.json({ success: true, data: results, unread: countResult[0].unread });
        }
      );
    }
  );
});

app.put('/api/notifications/:id/read', authMiddleware, (req, res) => {
  db.query('UPDATE notifications SET is_read = true, read_at = NOW() WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, result) => {
    if (err) {
      console.error('Mark read error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, message: 'Notification marked as read' });
  });
});

app.put('/api/notifications/read-all', authMiddleware, (req, res) => {
  db.query('UPDATE notifications SET is_read = true, read_at = NOW() WHERE user_id = ? AND is_read = false', [req.user.id], (err, result) => {
    if (err) {
      console.error('Mark all read error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, message: 'All notifications marked as read', count: result.affectedRows });
  });
});

app.delete('/api/notifications/:id', authMiddleware, (req, res) => {
  db.query('DELETE FROM notifications WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, result) => {
    if (err) {
      console.error('Delete notification error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, message: 'Notification deleted' });
  });
});

app.get('/api/notifications/unread-count', authMiddleware, (req, res) => {
  db.query('SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = false', [req.user.id], (err, results) => {
    if (err) {
      console.error('Unread count error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, data: { unread: results[0].count } });
  });
});

// ==================== SEEKER PROFILE ENDPOINTS ====================
app.put('/api/seeker/profile', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'job_seeker') {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  const { headline, location, skills, experience_years, current_salary, expected_salary, summary, bio, experiences, educations } = req.body;

  const updates = [];
  const values = [];

  if (headline !== undefined) { updates.push('headline = ?'); values.push(headline); }
  if (location !== undefined) { updates.push('location = ?'); values.push(location); }
  if (skills !== undefined) { updates.push('skills = ?'); values.push(typeof skills === 'string' ? skills : JSON.stringify(skills)); }
  if (experience_years !== undefined) { updates.push('experience_years = ?'); values.push(experience_years); }
  if (current_salary !== undefined) { updates.push('current_salary = ?'); values.push(current_salary); }
  if (expected_salary !== undefined) { updates.push('expected_salary = ?'); values.push(expected_salary); }
  if (summary !== undefined) { updates.push('summary = ?'); values.push(summary); }
  if (bio !== undefined) { updates.push('bio = ?'); values.push(bio); }
  if (experiences !== undefined) { updates.push('experiences = ?'); values.push(typeof experiences === 'string' ? experiences : JSON.stringify(experiences)); }
  if (educations !== undefined) { updates.push('educations = ?'); values.push(typeof educations === 'string' ? educations : JSON.stringify(educations)); }

  if (updates.length === 0) {
    return res.status(400).json({ success: false, message: 'No fields to update' });
  }

  updates.push('updated_at = NOW()');
  values.push(req.user.id);

  const query = `UPDATE job_seekers SET ${updates.join(', ')} WHERE user_id = ?`;
  
  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error: ' + err.message });
    }
    res.json({ success: true, message: 'Profile updated successfully' });
  });
});

app.get('/api/seeker/profile', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'job_seeker') {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  db.query(
    `SELECT u.id, u.email, u.first_name, u.last_name, u.phone, u.avatar_url,
            js.headline, js.location, js.skills, js.resume_url, js.experience_years,
            js.current_salary, js.expected_salary, js.bio, js.summary,
            js.experiences, js.educations, js.is_open_to_work
     FROM users u
     LEFT JOIN job_seekers js ON u.id = js.user_id
     WHERE u.id = ?`,
    [req.user.id],
    (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      if (results.length === 0) {
        return res.status(404).json({ success: false, message: 'Profile not found' });
      }
      
      const profile = results[0];
      if (profile.skills && typeof profile.skills === 'string') { try { profile.skills = JSON.parse(profile.skills); } catch(e) { profile.skills = []; } }
      if (profile.experiences && typeof profile.experiences === 'string') { try { profile.experiences = JSON.parse(profile.experiences); } catch(e) { profile.experiences = []; } }
      if (profile.educations && typeof profile.educations === 'string') { try { profile.educations = JSON.parse(profile.educations); } catch(e) { profile.educations = []; } }
      
      res.json({ success: true, data: profile });
    }
  );
});

app.put('/api/auth/profile', authMiddleware, (req, res) => {
  const { first_name, last_name, phone, location, headline } = req.body;
  
  const userUpdates = [];
  const userValues = [];
  
  if (first_name !== undefined) { userUpdates.push('first_name = ?'); userValues.push(first_name); }
  if (last_name !== undefined) { userUpdates.push('last_name = ?'); userValues.push(last_name); }
  if (phone !== undefined) { userUpdates.push('phone = ?'); userValues.push(phone); }
  
  if (userUpdates.length > 0) {
    userUpdates.push('updated_at = NOW()');
    userValues.push(req.user.id);
    db.query(`UPDATE users SET ${userUpdates.join(', ')} WHERE id = ?`, userValues);
  }
  
  if (location !== undefined || headline !== undefined) {
    const seekerUpdates = [];
    const seekerValues = [];
    if (location !== undefined) { seekerUpdates.push('location = ?'); seekerValues.push(location); }
    if (headline !== undefined) { seekerUpdates.push('headline = ?'); seekerValues.push(headline); }
    if (seekerUpdates.length > 0) {
      seekerUpdates.push('updated_at = NOW()');
      seekerValues.push(req.user.id);
      db.query(`UPDATE job_seekers SET ${seekerUpdates.join(', ')} WHERE user_id = ?`, seekerValues);
    }
  }
  
  res.json({ success: true, message: 'Profile updated successfully' });
});

// ==================== FILE UPLOAD CONFIGURATION ====================
let storage;

if (process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET) {
  storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: { folder: 'careerlinkgh-uploads', allowed_formats: ['jpg', 'jpeg', 'png', 'pdf'], transformation: [{ width: 1000, height: 1000, crop: 'limit' }] }
  });
  console.log('📁 Using Cloudinary storage for file uploads');
} else {
  storage = multer.diskStorage({
    destination: function (req, file, cb) { cb(null, 'uploads/'); },
    filename: function (req, file, cb) { cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname)); }
  });
  console.log('📁 Using local storage for file uploads');
}

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
    cb(null, true);
  } else {
    cb(new Error('Only images and PDFs are allowed'), false);
  }
};

const upload = multer({ storage: storage, fileFilter: fileFilter, limits: { fileSize: 5 * 1024 * 1024 } });
app.use('/uploads', express.static('uploads'));

app.post('/api/upload/resume', authMiddleware, upload.single('resume'), (req, res) => {
  if (req.user.user_type !== 'job_seeker') {
    return res.status(403).json({ success: false, message: 'Only job seekers can upload resumes' });
  }
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No file uploaded' });
  }
  const fileUrl = getFileUrl(req, req.file.filename);
  db.query('UPDATE job_seekers SET resume_url = ? WHERE user_id = ?', [fileUrl, req.user.id], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, message: 'Resume uploaded successfully', data: { url: fileUrl, filename: req.file.originalname } });
  });
});

app.post('/api/upload/company-logo', authMiddleware, upload.single('logo'), (req, res) => {
  if (req.user.user_type !== 'employer') {
    return res.status(403).json({ success: false, message: 'Only employers can upload company logos' });
  }
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No file uploaded' });
  }
  const fileUrl = getFileUrl(req, req.file.filename);
  db.query('UPDATE employers SET company_logo = ? WHERE user_id = ?', [fileUrl, req.user.id], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, message: 'Company logo uploaded successfully', data: { url: fileUrl } });
  });
});

// ==================== STATISTICS ====================
app.get('/api/stats', (req, res) => {
  const stats = {};
  db.query('SELECT COUNT(*) as total FROM jobs WHERE is_active = true', (err, result) => {
    stats.totalJobs = result[0].total;
    db.query('SELECT COUNT(*) as total FROM employers WHERE verified = true', (err, result) => {
      stats.totalCompanies = result[0].total;
      db.query('SELECT COUNT(*) as total FROM job_seekers', (err, result) => {
        stats.totalJobSeekers = result[0].total;
        db.query('SELECT COUNT(*) as total FROM applications', (err, result) => {
          stats.totalApplications = result[0].total;
          res.json({ success: true, data: stats });
        });
      });
    });
  });
});

// ==================== COMPANIES ENDPOINTS ====================
app.get('/api/employers', (req, res) => {
  db.query(`
    SELECT e.id, e.company_name, e.company_logo, e.company_description, e.industry, e.city as location, e.verified, e.total_jobs_posted, e.active_jobs, COUNT(DISTINCT j.id) as total_jobs
    FROM employers e LEFT JOIN jobs j ON j.employer_id = e.id AND j.is_active = true GROUP BY e.id ORDER BY e.total_jobs_posted DESC LIMIT 50
  `, (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, data: results });
  });
});

app.get('/api/employers/:id', (req, res) => {
  db.query(`SELECT e.*, COUNT(DISTINCT j.id) as total_jobs FROM employers e LEFT JOIN jobs j ON j.employer_id = e.id AND j.is_active = true WHERE e.id = ? GROUP BY e.id`, [req.params.id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Company not found' });
    }
    res.json({ success: true, data: results[0] });
  });
});

app.get('/api/employers/:id/jobs', (req, res) => {
  db.query(`SELECT j.*, c.name as category_name FROM jobs j LEFT JOIN job_categories c ON j.category_id = c.id WHERE j.employer_id = ? AND j.is_active = true ORDER BY j.created_at DESC`, [req.params.id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, data: results });
  });
});

// ==================== PAYMENT ROUTES (Simplified) ====================
app.post('/api/payments/initiate', authMiddleware, (req, res) => {
  res.json({ success: true, message: 'Payment initiated', data: { payment_id: 'pay_' + Date.now() } });
});

app.get('/api/payments/:paymentId/status', authMiddleware, (req, res) => {
  res.json({ success: true, data: { status: 'completed' } });
});

app.get('/api/subscription/status', authMiddleware, (req, res) => {
  res.json({ success: true, data: { plan: 'free', is_active: true, can_post_jobs: true } });
});

// ==================== TEST ENDPOINTS ====================
app.get('/', (req, res) => {
  res.json({ success: true, message: '🎉 CareerLinkGH API is running!', developer: 'Justice Quarshie', location: 'Takoradi, Ghana', version: '1.0.0', timestamp: new Date().toISOString() });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', uptime: process.uptime(), database: db.state, timestamp: new Date().toISOString() });
});

app.use('*', (req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found', path: req.originalUrl });
});

app.listen(PORT, () => {
  console.log(`\n  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║   🚀 CareerLinkGH Server Started Successfully!           ║
  ║                                                           ║
  ╠═══════════════════════════════════════════════════════════╣
  ║                                                           ║
  ║   📍 Port: ${PORT}                                        ║
  ║   🌐 URL: http://localhost:${PORT}                       ║
  ║                                                           ║
  ╠═══════════════════════════════════════════════════════════╣
  ║                                                           ║
  ║   👨‍💻 Developer: Justice Quarshie                        ║
  ║   🏢 Project: CareerLinkGH                               ║
  ║   📍 Location: Takoradi, Ghana                           ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝
  `);
});
