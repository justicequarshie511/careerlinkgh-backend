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

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

// Helper function to generate correct file URLs
const getFileUrl = (req, file) => {
  // If using Cloudinary, the file has a path property with the URL
  if (file && file.path) {
    return file.path;
  }
  // Fallback to local storage
  const host = req.get('host');
  const filename = typeof file === 'string' ? file : file.filename;
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

// Database connection - FIXED for Aiven MySQL (cloud database)
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'careerlinkgh_db',
  port: process.env.DB_PORT || 3306,
  // Add SSL for Aiven cloud database
  ssl: process.env.DB_HOST ? { rejectUnauthorized: false } : null
});

db.connect(err => {
  if (err) {
    console.log('❌ Database connection failed:', err.message);
  } else {
    console.log('✅ Database connected successfully');
    
    // Create notifications table if it doesn't exist (MOVED HERE)
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
  if (!userId) return;
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
    
    if (!token) {
      throw new Error();
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'careerlinkgh_secret_key_2024');
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ 
      success: false, 
      message: 'Please authenticate' 
    });
  }
};

// ==================== ADMIN MIDDLEWARE ====================
const adminMiddleware = (req, res, next) => {
  if (req.user.user_type !== 'admin') {
    return res.status(403).json({ success: false, message: 'Access denied. Admin only.' });
  }
  next();
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

// Create job (employer only) - UPDATES employer counts WITH VERIFICATION CHECK
app.post('/api/jobs', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'employer') {
    return res.status(403).json({ success: false, message: 'Only employers can post jobs' });
  }

  db.query('SELECT id, verified FROM employers WHERE user_id = ?', [req.user.id], (err, employerResults) => {
    if (err || employerResults.length === 0) {
      return res.status(400).json({ success: false, message: 'Employer profile not found' });
    }

    // VERIFICATION CHECK - Only verified employers can post jobs
    const employer = employerResults[0];
    if (employer.verified !== 1) {
      return res.status(403).json({ 
        success: false, 
        message: 'Your company must be verified before you can post jobs. Please upload your business registration document in your profile.' 
      });
    }

    const employer_id = employer.id;
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

        // Update employer's job counts
        db.query(
          `UPDATE employers SET 
            total_jobs_posted = total_jobs_posted + 1,
            active_jobs = active_jobs + 1
           WHERE id = ?`,
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

// Get featured jobs
app.get('/api/jobs/featured', (req, res) => {
  const limit = parseInt(req.query.limit) || 6;
  
  db.query(
    `SELECT j.*, e.company_name, e.company_logo
     FROM jobs j
     LEFT JOIN employers e ON j.employer_id = e.id
     WHERE j.is_featured = true AND j.is_active = true
     ORDER BY j.created_at DESC
     LIMIT ?`,
    [limit],
    (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      res.json({ success: true, data: results });
    }
  );
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

// Update job (employer only)
app.put('/api/jobs/:id', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'employer') {
    return res.status(403).json({ success: false, message: 'Only employers can update jobs' });
  }

  db.query('SELECT id FROM employers WHERE user_id = ?', [req.user.id], (err, employerResults) => {
    if (err || employerResults.length === 0) {
      return res.status(400).json({ success: false, message: 'Employer profile not found' });
    }

    const employer_id = employerResults[0].id;

    db.query('SELECT * FROM jobs WHERE id = ? AND employer_id = ?', [req.params.id, employer_id], (err, jobResults) => {
      if (err || jobResults.length === 0) {
        return res.status(403).json({ success: false, message: 'Unauthorized to update this job' });
      }

      const {
        title, description, requirements, benefits, job_type,
        experience_level, category_id, location, is_remote,
        salary_min, salary_max, salary_currency, application_deadline,
        is_featured, is_urgent, is_active
      } = req.body;

      let slug;
      if (title) {
        slug = title.toLowerCase()
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/(^-|-$)/g, '');
      }

      db.query(
        `UPDATE jobs SET
          title = COALESCE(?, title),
          slug = COALESCE(?, slug),
          description = COALESCE(?, description),
          requirements = COALESCE(?, requirements),
          benefits = COALESCE(?, benefits),
          job_type = COALESCE(?, job_type),
          experience_level = COALESCE(?, experience_level),
          category_id = COALESCE(?, category_id),
          location = COALESCE(?, location),
          is_remote = COALESCE(?, is_remote),
          salary_min = COALESCE(?, salary_min),
          salary_max = COALESCE(?, salary_max),
          salary_currency = COALESCE(?, salary_currency),
          application_deadline = COALESCE(?, application_deadline),
          is_featured = COALESCE(?, is_featured),
          is_urgent = COALESCE(?, is_urgent),
          is_active = COALESCE(?, is_active)
        WHERE id = ?`,
        [
          title, slug, description, requirements, benefits,
          job_type, experience_level, category_id, location, is_remote,
          salary_min, salary_max, salary_currency, application_deadline,
          is_featured, is_urgent, is_active, req.params.id
        ],
        (err, result) => {
          if (err) {
            console.error('Update error:', err);
            return res.status(500).json({ success: false, message: 'Failed to update job' });
          }

          res.json({ success: true, message: 'Job updated successfully' });
        }
      );
    });
  });
});

// Delete job (employer only) - UPDATES employer counts
app.delete('/api/jobs/:id', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'employer') {
    return res.status(403).json({ success: false, message: 'Only employers can delete jobs' });
  }

  db.query('SELECT id FROM employers WHERE user_id = ?', [req.user.id], (err, employerResults) => {
    if (err || employerResults.length === 0) {
      return res.status(400).json({ success: false, message: 'Employer profile not found' });
    }

    const employer_id = employerResults[0].id;

    db.query('SELECT is_active FROM jobs WHERE id = ? AND employer_id = ?', [req.params.id, employer_id], (err, jobResults) => {
      if (err || jobResults.length === 0) {
        return res.status(404).json({ success: false, message: 'Job not found' });
      }

      const wasActive = jobResults[0].is_active === 1;

      db.query('DELETE FROM jobs WHERE id = ? AND employer_id = ?', [req.params.id, employer_id], (err, result) => {
        if (err) {
          console.error('Delete error:', err);
          return res.status(500).json({ success: false, message: 'Failed to delete job' });
        }

        if (result.affectedRows === 0) {
          return res.status(404).json({ success: false, message: 'Job not found or unauthorized' });
        }

        if (wasActive) {
          db.query(
            `UPDATE employers SET 
              total_jobs_posted = GREATEST(total_jobs_posted - 1, 0),
              active_jobs = GREATEST(active_jobs - 1, 0)
             WHERE id = ?`,
            [employer_id]
          );
        }

        res.json({ success: true, message: 'Job deleted successfully' });
      });
    });
  });
});

// ==================== APPLICATIONS ====================

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

        // Get job details for notification
        db.query('SELECT title, employer_id FROM jobs WHERE id = ?', [req.params.jobId], (err, jobResults) => {
          if (err || jobResults.length === 0) {
            console.error('Job not found:', err);
            return res.status(400).json({ success: false, message: 'Job not found' });
          }

          const jobTitle = jobResults[0].title;
          const employerId = jobResults[0].employer_id;

          db.query(
            'INSERT INTO applications (id, job_id, job_seeker_id, cover_letter, resume_url) VALUES (?, ?, ?, ?, ?)',
            [applicationId, req.params.jobId, job_seeker_id, cover_letter, resume_url],
            (err, result) => {
              if (err) {
                console.error('Application error:', err);
                return res.status(500).json({ success: false, message: 'Failed to submit application' });
              }

              db.query('UPDATE jobs SET applications_count = applications_count + 1 WHERE id = ?', [req.params.jobId]);

              // Create notification for job seeker
              createNotification(
                req.user.id,
                'application',
                'Application Submitted',
                `You have successfully applied for the job: ${jobTitle}`,
                req.params.jobId
              );

              // Get employer user_id to send them a notification
              db.query('SELECT user_id FROM employers WHERE id = ?', [employerId], (err, empResults) => {
                if (empResults && empResults.length > 0) {
                  const employerUserId = empResults[0].user_id;
                  
                  // Get seeker's name for notification
                  db.query(
                    'SELECT first_name, last_name FROM users WHERE id = ?',
                    [req.user.id],
                    (err, userResults) => {
                      if (userResults && userResults.length > 0) {
                        const seekerName = `${userResults[0].first_name} ${userResults[0].last_name}`;
                        
                        // Create notification for employer
                        createNotification(
                          employerUserId,
                          'new_application',
                          'New Job Application',
                          `${seekerName} has applied for your job: ${jobTitle}`,
                          req.params.jobId
                        );
                      }
                    }
                  );
                }
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

// Update application status (employer only)
app.put('/api/applications/:id/status', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'employer') {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  const { status, interview_date, interview_notes } = req.body;

  db.query(
    `SELECT a.id, a.job_id, a.job_seeker_id, j.title FROM applications a
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

          // Get job seeker's user_id and name to send notification
          db.query(
            'SELECT js.user_id, u.first_name, u.last_name FROM job_seekers js LEFT JOIN users u ON js.user_id = u.id WHERE js.id = ?',
            [application.job_seeker_id],
            (err, seekerResults) => {
              if (seekerResults && seekerResults.length > 0) {
                const seekerUserId = seekerResults[0].user_id;
                const seekerName = `${seekerResults[0].first_name} ${seekerResults[0].last_name}`;

                // Create status-specific notification messages for job seeker
                let notificationTitle = 'Application Status Updated';
                let notificationMessage = `Your application for ${jobTitle} has been ${status}`;

                switch(status) {
                  case 'shortlisted':
                    notificationTitle = '🎉 Shortlisted!';
                    notificationMessage = `Great news! You've been shortlisted for ${jobTitle}`;
                    break;
                  case 'interview':
                    notificationTitle = '📅 Interview Scheduled';
                    notificationMessage = `You have an interview scheduled for ${jobTitle}${interview_date ? ` on ${new Date(interview_date).toLocaleDateString()}` : ''}`;
                    break;
                  case 'accepted':
                    notificationTitle = '🎉 Congratulations!';
                    notificationMessage = `Congratulations! Your application for ${jobTitle} has been accepted!`;
                    break;
                  case 'rejected':
                    notificationTitle = 'Application Update';
                    notificationMessage = `Your application for ${jobTitle} was not successful this time. Keep trying!`;
                    break;
                }

                createNotification(
                  seekerUserId,
                  'application_update',
                  notificationTitle,
                  notificationMessage,
                  application.job_id
                );

                // Create notification for employer
                let employerNotificationTitle = 'Application Status Updated';
                let employerNotificationMessage = `You have ${status} the application from ${seekerName} for ${jobTitle}`;

                switch(status) {
                  case 'shortlisted':
                    employerNotificationTitle = 'Application Shortlisted';
                    employerNotificationMessage = `You have shortlisted ${seekerName} for ${jobTitle}`;
                    break;
                  case 'interview':
                    employerNotificationTitle = 'Interview Scheduled';
                    employerNotificationMessage = `You have scheduled an interview with ${seekerName} for ${jobTitle}${interview_date ? ` on ${new Date(interview_date).toLocaleDateString()}` : ''}`;
                    break;
                  case 'accepted':
                    employerNotificationTitle = 'Application Accepted';
                    employerNotificationMessage = `You have accepted the application from ${seekerName} for ${jobTitle}`;
                    break;
                  case 'rejected':
                    employerNotificationTitle = 'Application Rejected';
                    employerNotificationMessage = `You have rejected the application from ${seekerName} for ${jobTitle}`;
                    break;
                }

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

// ==================== SAVED JOBS ====================

// Save a job
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

// Unsave a job
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

// Get saved jobs
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

// Get user notifications
app.get('/api/notifications', authMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  const offset = parseInt(req.query.offset) || 0;
  
  db.query(
    `SELECT * FROM notifications 
     WHERE user_id = (SELECT id FROM users WHERE id = ?)
     ORDER BY created_at DESC 
     LIMIT ? OFFSET ?`,
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
          
          res.json({ 
            success: true, 
            data: results,
            unread: countResult[0].unread
          });
        }
      );
    }
  );
});

// Local disk storage configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
    cb(null, true);
  } else {
    cb(new Error('Only images and PDFs are allowed'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }
});

// Serve uploaded files statically (for backward compatibility)
app.use('/uploads', express.static('uploads'));

// ==================== FILE UPLOAD ROUTES ====================

// Upload profile picture
app.post('/api/upload/profile-picture', authMiddleware, upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No file uploaded' });
  }

  const fileUrl = getFileUrl(req, req.file);
  
  db.query('UPDATE users SET avatar_url = ? WHERE id = ?', [fileUrl, req.user.id], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, message: 'Profile picture uploaded successfully', data: { url: fileUrl } });
  });
});

// ==================== EMPLOYER VERIFICATION ENDPOINTS ====================

// Upload verification document (employer only)
app.post('/api/employer/upload-verification', authMiddleware, upload.single('document'), (req, res) => {
  if (req.user.user_type !== 'employer') {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No file uploaded' });
  }

  // Check file type (only PDF and images allowed)
  const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg'];
  if (!allowedTypes.includes(req.file.mimetype)) {
    return res.status(400).json({ success: false, message: 'Only PDF, JPEG, and PNG files are allowed' });
  }

  // Check file size (max 5MB)
  if (req.file.size > 5 * 1024 * 1024) {
    return res.status(400).json({ success: false, message: 'File size must be less than 5MB' });
  }

  const fileUrl = getFileUrl(req, req.file);
  const { business_registration_number } = req.body;

  db.query(
    `UPDATE employers SET 
      verification_document = ?,
      business_registration_number = ?,
      verification_requested_at = NOW(),
      verified = 0
     WHERE user_id = ?`,
    [fileUrl, business_registration_number || null, req.user.id],
    (err, result) => {
      if (err) {
        console.error('Upload verification error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }

      // Notify admin that verification is requested
      db.query('SELECT id FROM users WHERE user_type = "admin" LIMIT 1', (err, adminResults) => {
        if (adminResults && adminResults.length > 0) {
          createNotification(
            adminResults[0].id,
            'system',
            'Company Verification Request',
            `A new company has requested verification. Please review the documents.`,
            req.user.id
          );
        }
      });

      res.json({ 
        success: true, 
        message: 'Verification document uploaded successfully. Your account will be reviewed by an admin.',
        data: { document_url: fileUrl }
      });
    }
  );
});

// Check verification status (employer only)
app.get('/api/employer/verification-status', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'employer') {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  db.query(
    `SELECT verified, verification_document, business_registration_number, 
            verification_requested_at, verification_notes, verified_at
     FROM employers WHERE user_id = ?`,
    [req.user.id],
    (err, results) => {
      if (err) {
        console.error('Verification status error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }

      const status = results[0] || { verified: 0 };
      let message = '';
      
      if (status.verified === 1) {
        message = 'Your company is verified. You can now post jobs.';
      } else if (status.verification_requested_at) {
        message = 'Your verification documents are being reviewed. You will be notified once approved.';
      } else {
        message = 'Please upload your business registration document to get verified.';
      }

      res.json({ 
        success: true, 
        data: status,
        message: message
      });
    }
  );
});

// Get pending verifications (admin only)
app.get('/api/admin/pending-verifications', authMiddleware, adminMiddleware, (req, res) => {
  db.query(
    `SELECT e.id, e.company_name, e.company_logo, e.verification_document, 
            e.business_registration_number, e.verification_requested_at,
            u.id as user_id, u.email, u.first_name, u.last_name, u.created_at
     FROM employers e
     LEFT JOIN users u ON e.user_id = u.id
     WHERE e.verified = 0 AND e.verification_document IS NOT NULL
     ORDER BY e.verification_requested_at ASC`,
    (err, results) => {
      if (err) {
        console.error('Pending verifications error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      res.json({ success: true, data: results });
    }
  );
});

// ==================== UPDATED SEEKER PROFILE ENDPOINTS (FOR RESUME BUILDER) ====================

// UPDATE: Enhanced PUT endpoint for seeker profile (supports all resume fields)
app.put('/api/seeker/profile', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'job_seeker') {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  const { 
    headline, location, skills, experience_years, 
    current_salary, expected_salary, summary, 
    bio, experiences, educations 
  } = req.body;

  // Build dynamic update query
  const updates = [];
  const values = [];

  if (headline !== undefined) {
    updates.push('headline = ?');
    values.push(headline);
  }
  if (location !== undefined) {
    updates.push('location = ?');
    values.push(location);
  }
  if (skills !== undefined) {
    const skillsJson = typeof skills === 'string' ? skills : JSON.stringify(skills);
    updates.push('skills = ?');
    values.push(skillsJson);
  }
  if (experience_years !== undefined) {
    updates.push('experience_years = ?');
    values.push(experience_years);
  }
  if (current_salary !== undefined) {
    updates.push('current_salary = ?');
    values.push(current_salary);
  }
  if (expected_salary !== undefined) {
    updates.push('expected_salary = ?');
    values.push(expected_salary);
  }
  if (summary !== undefined) {
    updates.push('summary = ?');
    values.push(summary);
  }
  if (bio !== undefined) {
    updates.push('bio = ?');
    values.push(bio);
  }
  if (experiences !== undefined) {
    const experiencesJson = typeof experiences === 'string' ? experiences : JSON.stringify(experiences);
    updates.push('experiences = ?');
    values.push(experiencesJson);
  }
  if (educations !== undefined) {
    const educationsJson = typeof educations === 'string' ? educations : JSON.stringify(educations);
    updates.push('educations = ?');
    values.push(educationsJson);
  }

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

// UPDATE: Enhanced GET endpoint for seeker profile (returns all resume data)
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
      
      // Parse JSON fields if they exist and are strings
      if (profile.skills && typeof profile.skills === 'string') {
        try {
          profile.skills = JSON.parse(profile.skills);
        } catch(e) {
          profile.skills = [];
        }
      }
      
      if (profile.experiences && typeof profile.experiences === 'string') {
        try {
          profile.experiences = JSON.parse(profile.experiences);
        } catch(e) {
          profile.experiences = [];
        }
      }
      
      if (profile.educations && typeof profile.educations === 'string') {
        try {
          profile.educations = JSON.parse(profile.educations);
        } catch(e) {
          profile.educations = [];
        }
      }
      
      res.json({ success: true, data: profile });
    }
  );
});

// Upload resume (for job seekers)
app.post('/api/upload/resume', authMiddleware, upload.single('resume'), (req, res) => {
  if (req.user.user_type !== 'job_seeker') {
    return res.status(403).json({ success: false, message: 'Only job seekers can upload resumes' });
  }

  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No file uploaded' });
  }

  const fileUrl = getFileUrl(req, req.file);
  
  db.query(
    'UPDATE job_seekers SET resume_url = ? WHERE user_id = ?',
    [fileUrl, req.user.id],
    (err, result) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      res.json({ success: true, message: 'Resume uploaded successfully', data: { url: fileUrl, filename: req.file.originalname } });
    }
  );
});

// Upload company logo (for employers)
app.post('/api/upload/company-logo', authMiddleware, upload.single('logo'), (req, res) => {
  if (req.user.user_type !== 'employer') {
    return res.status(403).json({ success: false, message: 'Only employers can upload company logos' });
  }

  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No file uploaded' });
  }

  const fileUrl = getFileUrl(req, req.file);
  
  db.query('UPDATE employers SET company_logo = ? WHERE user_id = ?', [fileUrl, req.user.id], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, message: 'Company logo uploaded successfully', data: { url: fileUrl } });
  });
});

// Mark notification as read
app.put('/api/notifications/:id/read', authMiddleware, (req, res) => {
  db.query('UPDATE notifications SET is_read = true, read_at = NOW() WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, result) => {
    if (err) {
      console.error('Mark read error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, message: 'Notification marked as read' });
  });
});

// Mark all notifications as read
app.put('/api/notifications/read-all', authMiddleware, (req, res) => {
  db.query('UPDATE notifications SET is_read = true, read_at = NOW() WHERE user_id = ? AND is_read = false', [req.user.id], (err, result) => {
    if (err) {
      console.error('Mark all read error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, message: 'All notifications marked as read', count: result.affectedRows });
  });
});

// ==================== AVATAR & PROFILE MANAGEMENT ====================

// Upload avatar (profile picture)
app.post('/api/auth/avatar', authMiddleware, upload.single('avatar'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No file uploaded' });
  }

  if (!req.file.mimetype.startsWith('image/')) {
    return res.status(400).json({ success: false, message: 'Only image files are allowed' });
  }

  if (req.file.size > 2 * 1024 * 1024) {
    return res.status(400).json({ success: false, message: 'File size must be less than 2MB' });
  }

  const fileUrl = getFileUrl(req, req.file);
  
  db.query('UPDATE users SET avatar_url = ? WHERE id = ?', [fileUrl, req.user.id], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, message: 'Avatar uploaded successfully', data: { url: fileUrl } });
  });
});

// Remove avatar
app.delete('/api/auth/avatar', authMiddleware, (req, res) => {
  db.query('UPDATE users SET avatar_url = NULL WHERE id = ?', [req.user.id], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, message: 'Avatar removed successfully' });
  });
});

// UPDATE: Enhanced profile update endpoint (handles both users and job_seekers)
app.put('/api/auth/profile', authMiddleware, (req, res) => {
  const { first_name, last_name, phone, location, headline } = req.body;
  
  // Update users table
  const userUpdates = [];
  const userValues = [];
  
  if (first_name !== undefined) {
    userUpdates.push('first_name = ?');
    userValues.push(first_name);
  }
  if (last_name !== undefined) {
    userUpdates.push('last_name = ?');
    userValues.push(last_name);
  }
  if (phone !== undefined) {
    userUpdates.push('phone = ?');
    userValues.push(phone);
  }
  
  if (userUpdates.length > 0) {
    userUpdates.push('updated_at = NOW()');
    userValues.push(req.user.id);
    
    db.query(
      `UPDATE users SET ${userUpdates.join(', ')} WHERE id = ?`,
      userValues,
      (err, result) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ success: false, message: 'Database error' });
        }
      }
    );
  }
  
  // Update job_seekers table if location or headline provided
  if (location !== undefined || headline !== undefined) {
    const seekerUpdates = [];
    const seekerValues = [];
    
    if (location !== undefined) {
      seekerUpdates.push('location = ?');
      seekerValues.push(location);
    }
    if (headline !== undefined) {
      seekerUpdates.push('headline = ?');
      seekerValues.push(headline);
    }
    
    if (seekerUpdates.length > 0) {
      seekerUpdates.push('updated_at = NOW()');
      seekerValues.push(req.user.id);
      
      db.query(
        `UPDATE job_seekers SET ${seekerUpdates.join(', ')} WHERE user_id = ?`,
        seekerValues,
        (err, result) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Database error' });
          }
        }
      );
    }
  }
  
  res.json({ success: true, message: 'Profile updated successfully' });
});

// Delete notification
app.delete('/api/notifications/:id', authMiddleware, (req, res) => {
  db.query('DELETE FROM notifications WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, result) => {
    if (err) {
      console.error('Delete notification error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, message: 'Notification deleted' });
  });
});

// Get unread count
app.get('/api/notifications/unread-count', authMiddleware, (req, res) => {
  db.query('SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = false', [req.user.id], (err, results) => {
    if (err) {
      console.error('Unread count error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, data: { unread: results[0].count } });
  });
});

// ==================== JOB ALERTS ====================
app.post('/api/job-alerts', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'job_seeker') {
    return res.status(403).json({ success: false, message: 'Only job seekers can create alerts' });
  }
  res.json({ success: true, message: 'Job alert created (feature coming soon)' });
});

app.get('/api/job-alerts', authMiddleware, (req, res) => {
  res.json({ success: true, data: [] });
});

// ==================== COMPANY REVIEWS ====================
app.post('/api/companies/:companyId/reviews', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'job_seeker') {
    return res.status(403).json({ success: false, message: 'Only job seekers can review companies' });
  }
  res.json({ success: true, message: 'Review added (feature coming soon)' });
});

app.get('/api/companies/:companyId/reviews', (req, res) => {
  res.json({ success: true, data: [] });
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

// Get employer dashboard stats
app.get('/api/employer/stats', authMiddleware, (req, res) => {
  if (req.user.user_type !== 'employer') {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  db.query(
    `SELECT 
      (SELECT COUNT(*) FROM jobs WHERE employer_id = e.id AND is_active = true) as active_jobs,
      (SELECT COUNT(*) FROM jobs WHERE employer_id = e.id) as total_jobs,
      (SELECT COUNT(*) FROM applications a JOIN jobs j ON a.job_id = j.id WHERE j.employer_id = e.id) as total_applications,
      (SELECT COUNT(*) FROM applications a JOIN jobs j ON a.job_id = j.id WHERE j.employer_id = e.id AND a.status = 'pending') as pending_applications
     FROM employers e
     WHERE e.user_id = ?`,
    [req.user.id],
    (err, results) => {
      if (err) {
        console.error('Stats error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      res.json({ success: true, data: results[0] });
    }
  );
});

// ==================== PAYMENT ROUTES ====================

// Initialize payment
app.post('/api/payments/initiate', authMiddleware, (req, res) => {
  const { plan, amount, paymentMethod, paymentDetails } = req.body;
  
  console.log('💰 Payment initiated:', { plan, amount, paymentMethod, userId: req.user.id });
  
  if (paymentMethod === 'momo') {
    const momoNumber = paymentDetails?.momoNumber;
    console.log(`📱 Sending payment request to ${momoNumber} for GHS ${amount}`);
    
    setTimeout(() => {
      activateSubscription(req.user.id, plan);
    }, 10000);
    
    res.json({
      success: true,
      message: `Payment request sent to ${momoNumber}. Please check your phone and approve the payment.`,
      data: { payment_id: 'sim_' + Date.now() }
    });
  } 
  else if (paymentMethod === 'bank') {
    const bankDetails = {
      bank_name: "GCB Bank",
      account_name: "CareerLinkGH",
      account_number: "1234567890",
      branch: "Takoradi Main",
      amount: `GHS ${amount}`,
      reference: 'REF_' + Date.now(),
      phone: "0545784013",
      instructions: [
        "Go to any GCB Bank branch or use mobile banking",
        "Transfer the exact amount to the account above",
        "Use the Payment ID as reference",
        "Send payment screenshot to 0545784013 via WhatsApp"
      ]
    };
    
    res.json({
      success: true,
      message: 'Bank transfer instructions generated',
      data: { payment_id: 'bank_' + Date.now(), bank_details: bankDetails }
    });
  }
  else {
    res.status(400).json({ success: false, message: 'Invalid payment method' });
  }
});

// Helper function to activate subscription
function activateSubscription(userId, planName) {
  let jobPostsRemaining = 0;
  let subscriptionDays = 0;
  
  switch(planName) {
    case 'Basic':
      jobPostsRemaining = 5;
      subscriptionDays = 30;
      break;
    case 'Professional':
      jobPostsRemaining = 20;
      subscriptionDays = 30;
      break;
    case 'Enterprise':
      jobPostsRemaining = 999;
      subscriptionDays = 90;
      break;
    default:
      jobPostsRemaining = 1;
      subscriptionDays = 30;
  }
  
  db.query(
    `UPDATE users 
     SET subscription_plan = ?, 
         subscription_expires = DATE_ADD(NOW(), INTERVAL ? DAY),
         job_posts_remaining = ?
     WHERE id = ?`,
    [planName, subscriptionDays, jobPostsRemaining, userId],
    (err) => {
      if (err) {
        console.error('Subscription update error:', err);
      } else {
        console.log(`✅ Subscription activated for user ${userId}: ${planName} plan`);
        db.query(`UPDATE employers SET subscription_tier = ? WHERE user_id = ?`, [planName.toLowerCase(), userId]);
      }
    }
  );
}

// Get payment status
app.get('/api/payments/:paymentId/status', authMiddleware, (req, res) => {
  res.json({ success: true, data: { status: 'completed', message: 'Payment completed successfully' } });
});

// Get subscription status
app.get('/api/subscription/status', authMiddleware, (req, res) => {
  db.query(
    `SELECT subscription_plan, subscription_expires, job_posts_remaining,
            DATEDIFF(subscription_expires, NOW()) as days_remaining
     FROM users WHERE id = ?`,
    [req.user.id],
    (err, results) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      
      const subscription = results[0];
      const isActive = subscription.subscription_expires && 
                       new Date(subscription.subscription_expires) > new Date();
      
      res.json({
        success: true,
        data: {
          ...subscription,
          is_active: isActive,
          can_post_jobs: subscription.job_posts_remaining > 0 && isActive
        }
      });
    }
  );
});

// ==================== COMPANIES (EMPLOYERS) ENDPOINTS ====================

// Get all companies (employers) - Public endpoint
app.get('/api/employers', (req, res) => {
  let query = `
    SELECT e.id, e.company_name, e.company_logo, e.company_description, 
           e.industry, e.city as location, e.verified,
           e.total_jobs_posted, e.active_jobs,
           COUNT(DISTINCT j.id) as total_jobs
    FROM employers e
    LEFT JOIN jobs j ON j.employer_id = e.id AND j.is_active = true
    GROUP BY e.id
    ORDER BY e.total_jobs_posted DESC
    LIMIT 50
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    
    const companies = results.map(company => ({
      id: company.id,
      company_name: company.company_name,
      company_logo: company.company_logo,
      company_description: company.company_description,
      industry: company.industry || 'General',
      location: company.location || 'Ghana',
      verified: company.verified === 1,
      total_jobs_posted: company.total_jobs_posted || 0,
      active_jobs: company.active_jobs || 0,
      total_jobs: company.total_jobs || 0
    }));
    
    res.json({ success: true, data: companies });
  });
});

// Get single company details
app.get('/api/employers/:id', (req, res) => {
  db.query(
    `SELECT e.*, 
            COUNT(DISTINCT j.id) as total_jobs
     FROM employers e
     LEFT JOIN jobs j ON j.employer_id = e.id AND j.is_active = true
     WHERE e.id = ?
     GROUP BY e.id`,
    [req.params.id],
    (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      
      if (results.length === 0) {
        return res.status(404).json({ success: false, message: 'Company not found' });
      }
      
      res.json({ success: true, data: results[0] });
    }
  );
});

// Get jobs for a specific company
app.get('/api/employers/:id/jobs', (req, res) => {
  db.query(
    `SELECT j.*, c.name as category_name
     FROM jobs j
     LEFT JOIN job_categories c ON j.category_id = c.id
     WHERE j.employer_id = ? AND j.is_active = true
     ORDER BY j.created_at DESC`,
    [req.params.id],
    (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      res.json({ success: true, data: results });
    }
  );
});

// ==================== TEST ENDPOINTS ====================
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🎉 CareerLinkGH API is running!',
    developer: 'Justice Quarshie',
    location: 'Takoradi, Ghana',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    uptime: process.uptime(),
    database: db.state,
    timestamp: new Date().toISOString()
  });
});

// ==================== ADMIN ROUTES ====================

// Get all users (admin only)
app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const offset = parseInt(req.query.offset) || 0;
  
  db.query(
    `SELECT id, email, first_name, last_name, phone, user_type, is_active, email_verified, created_at, last_login
     FROM users 
     ORDER BY created_at DESC 
     LIMIT ? OFFSET ?`,
    [limit, offset],
    (err, results) => {
      if (err) {
        console.error('Admin users error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      
      // Get total count
      db.query('SELECT COUNT(*) as total FROM users', (err, countResult) => {
        res.json({ 
          success: true, 
          data: results,
          total: countResult[0].total,
          limit: limit,
          offset: offset
        });
      });
    }
  );
});

// Get all employers (admin only)
app.get('/api/admin/employers', authMiddleware, adminMiddleware, (req, res) => {
  db.query(
    `SELECT e.*, u.email, u.first_name, u.last_name, u.created_at as user_joined
     FROM employers e
     LEFT JOIN users u ON e.user_id = u.id
     ORDER BY e.created_at DESC`,
    (err, results) => {
      if (err) {
        console.error('Admin employers error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      res.json({ success: true, data: results });
    }
  );
});

// Get all jobs (admin only)
app.get('/api/admin/jobs', authMiddleware, adminMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  
  db.query(
    `SELECT j.*, e.company_name, u.email as employer_email, c.name as category_name
     FROM jobs j
     LEFT JOIN employers e ON j.employer_id = e.id
     LEFT JOIN users u ON e.user_id = u.id
     LEFT JOIN job_categories c ON j.category_id = c.id
     ORDER BY j.created_at DESC
     LIMIT ?`,
    [limit],
    (err, results) => {
      if (err) {
        console.error('Admin jobs error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      res.json({ success: true, data: results });
    }
  );
});

// Verify a company (admin only) - ENHANCED with notes
app.put('/api/admin/verify-company/:id', authMiddleware, adminMiddleware, (req, res) => {
  const { verified, notes } = req.body;
  
  db.query(
    `UPDATE employers SET 
      verified = ?, 
      verification_notes = ?,
      verified_by = ?,
      verified_at = NOW()
     WHERE id = ?`,
    [verified ? 1 : 0, notes || null, req.user.id, req.params.id],
    (err, result) => {
      if (err) {
        console.error('Verify company error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      
      // Get employer user_id and company name
      db.query(
        'SELECT e.user_id, e.company_name FROM employers e WHERE e.id = ?',
        [req.params.id],
        (err, companyResults) => {
          if (companyResults && companyResults.length > 0) {
            const employerUserId = companyResults[0].user_id;
            const companyName = companyResults[0].company_name;
            
            if (verified) {
              createNotification(
                employerUserId,
                'system',
                '✅ Company Verified!',
                `Your company "${companyName}" has been verified. You can now post jobs on CareerLinkGH.`,
                req.params.id
              );
            } else {
              createNotification(
                employerUserId,
                'system',
                'Company Verification Update',
                `Your company "${companyName}" verification request has been reviewed. ${notes || 'Please contact support for more information.'}`,
                req.params.id
              );
            }
          }
        }
      );
      
      res.json({ success: true, message: `Company ${verified ? 'verified' : 'rejected'} successfully` });
    }
  );
});

// Delete a user (admin only)
app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, (req, res) => {
  db.query('DELETE FROM users WHERE id = ?', [req.params.id], (err, result) => {
    if (err) {
      console.error('Delete user error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, message: 'User deleted successfully' });
  });
});

// Get platform stats (enhanced for admin)
app.get('/api/admin/stats', authMiddleware, adminMiddleware, (req, res) => {
  const queries = {
    totalUsers: 'SELECT COUNT(*) as count FROM users',
    totalEmployers: 'SELECT COUNT(*) as count FROM users WHERE user_type = "employer"',
    totalJobSeekers: 'SELECT COUNT(*) as count FROM users WHERE user_type = "job_seeker"',
    totalJobs: 'SELECT COUNT(*) as count FROM jobs',
    activeJobs: 'SELECT COUNT(*) as count FROM jobs WHERE is_active = true',
    totalApplications: 'SELECT COUNT(*) as count FROM applications',
    pendingApplications: 'SELECT COUNT(*) as count FROM applications WHERE status = "pending"',
    verifiedCompanies: 'SELECT COUNT(*) as count FROM employers WHERE verified = true',
    totalNotifications: 'SELECT COUNT(*) as count FROM notifications'
  };
  
  const results = {};
  let completed = 0;
  const totalQueries = Object.keys(queries).length;
  
  for (const [key, query] of Object.entries(queries)) {
    db.query(query, (err, result) => {
      if (err) {
        console.error(`Stats error for ${key}:`, err);
        results[key] = 0;
      } else {
        results[key] = result[0].count;
      }
      completed++;
      
      if (completed === totalQueries) {
        res.json({ success: true, data: results });
      }
    });
  }
});

// Activate user (admin only)
app.put('/api/admin/users/:id/activate', authMiddleware, adminMiddleware, (req, res) => {
  db.query('UPDATE users SET is_active = 1 WHERE id = ?', [req.params.id], (err, result) => {
    if (err) {
      console.error('Activate user error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    
    // Get user email for notification
    db.query('SELECT email FROM users WHERE id = ?', [req.params.id], (err, userResults) => {
      if (userResults && userResults.length > 0) {
        createNotification(
          req.params.id,
          'system',
          'Account Activated ✓',
          'Your account has been activated by admin. You can now log in.',
          null
        );
      }
    });
    
    res.json({ success: true, message: 'User activated successfully' });
  });
});

// Deactivate user (admin only)
app.put('/api/admin/users/:id/deactivate', authMiddleware, adminMiddleware, (req, res) => {
  db.query('UPDATE users SET is_active = 0 WHERE id = ?', [req.params.id], (err, result) => {
    if (err) {
      console.error('Deactivate user error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    
    createNotification(
      req.params.id,
      'system',
      'Account Deactivated',
      'Your account has been deactivated by admin. Please contact support.',
      null
    );
    
    res.json({ success: true, message: 'User deactivated successfully' });
  });
});

// ==================== ADMIN SETTINGS ENDPOINTS ====================

// Get platform settings
app.get('/api/admin/settings', authMiddleware, adminMiddleware, (req, res) => {
  // For now, return default settings (you can store these in a settings table later)
  const settings = {
    site_name: 'CareerLink GH',
    site_description: 'Find your dream job in Ghana',
    contact_email: 'contact@careerlinkgh.com',
    support_email: 'support@careerlinkgh.com',
    max_jobs_per_employer: 10,
    max_applications_per_job_seeker: 5,
    featured_job_price: 50,
    premium_subscription_price: 99,
    email_verification_required: true,
    job_posting_approval_required: false,
    maintenance_mode: false,
    maintenance_message: 'Site is under maintenance. Please check back later.'
  };
  
  res.json({ success: true, data: settings });
});

// Update platform settings
app.put('/api/admin/settings', authMiddleware, adminMiddleware, (req, res) => {
  const settings = req.body;
  // Here you would save to a settings table in the database
  // For now, just return success
  console.log('Settings updated:', settings);
  res.json({ success: true, message: 'Settings saved successfully' });
});

// ==================== ADMIN REPORTS ENDPOINTS ====================

// Export reports
app.post('/api/reports/export', authMiddleware, (req, res) => {
  const { type, dateRange, format } = req.body;
  
  // For demo purposes, create a simple CSV/PDF report
  // In production, you would generate actual reports from database
  
  let reportData = '';
  let filename = `report_${type}_${Date.now()}`;
  let contentType = '';
  
  switch (type) {
    case 'applications':
      reportData = 'Application ID,Job Title,Applicant Name,Status,Applied Date\n123,Software Engineer,John Doe,Pending,2024-01-15';
      break;
    case 'jobs':
      reportData = 'Job ID,Title,Company,Location,Posted Date,Status\n456,Frontend Developer,Tech Corp,Accra,2024-01-10,Active';
      break;
    case 'users':
      reportData = 'User ID,Name,Email,Type,Joined Date,Status\n789,John Doe,john@email.com,Job Seeker,2024-01-01,Active';
      break;
    case 'revenue':
      reportData = 'Month,Amount,Transactions\nJanuary,₵1,250,15\nFebruary,₵2,100,22';
      break;
    default:
      reportData = 'Report data';
  }
  
  if (format === 'csv') {
    contentType = 'text/csv';
    filename += '.csv';
  } else if (format === 'excel') {
    contentType = 'application/vnd.ms-excel';
    filename += '.xls';
  } else {
    contentType = 'application/pdf';
    filename += '.pdf';
    // For PDF, you'd need a PDF generator library
    reportData = 'PDF report generation would go here';
  }
  
  res.setHeader('Content-Type', contentType);
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(reportData);
});

// ==================== ADMIN DASHBOARD STATS ENHANCED ====================

// Get enhanced admin stats
app.get('/api/admin/dashboard-stats', authMiddleware, adminMiddleware, (req, res) => {
  const queries = {
    totalUsers: 'SELECT COUNT(*) as count FROM users',
    totalEmployers: 'SELECT COUNT(*) as count FROM users WHERE user_type = "employer"',
    totalJobSeekers: 'SELECT COUNT(*) as count FROM users WHERE user_type = "job_seeker"',
    totalJobs: 'SELECT COUNT(*) as count FROM jobs',
    activeJobs: 'SELECT COUNT(*) as count FROM jobs WHERE is_active = true',
    totalApplications: 'SELECT COUNT(*) as count FROM applications',
    pendingApplications: 'SELECT COUNT(*) as count FROM applications WHERE status = "pending"',
    verifiedCompanies: 'SELECT COUNT(*) as count FROM employers WHERE verified = true',
    featuredJobs: 'SELECT COUNT(*) as count FROM jobs WHERE is_featured = true',
    totalNotifications: 'SELECT COUNT(*) as count FROM notifications',
    unreadNotifications: 'SELECT COUNT(*) as count FROM notifications WHERE is_read = false',
    // Recent activity (last 7 days)
    newUsersThisWeek: 'SELECT COUNT(*) as count FROM users WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)',
    newJobsThisWeek: 'SELECT COUNT(*) as count FROM jobs WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)',
    newApplicationsThisWeek: 'SELECT COUNT(*) as count FROM applications WHERE applied_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)'
  };
  
  const results = {};
  let completed = 0;
  const totalQueries = Object.keys(queries).length;
  
  for (const [key, query] of Object.entries(queries)) {
    db.query(query, (err, result) => {
      if (err) {
        console.error(`Stats error for ${key}:`, err);
        results[key] = 0;
      } else {
        results[key] = result[0].count;
      }
      completed++;
      
      if (completed === totalQueries) {
        // Get recent activity for timeline
        db.query(
          `SELECT 
            DATE(created_at) as date, 
            COUNT(*) as count,
            'users' as type
          FROM users 
          WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
          GROUP BY DATE(created_at)
          UNION ALL
          SELECT 
            DATE(created_at) as date, 
            COUNT(*) as count,
            'jobs' as type
          FROM jobs 
          WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
          GROUP BY DATE(created_at)
          ORDER BY date DESC
          LIMIT 30`,
          (err, activityResults) => {
            results.recentActivity = activityResults || [];
            res.json({ success: true, data: results });
          }
        );
      }
    });
  }
});

// ==================== USER MANAGEMENT ENHANCEMENTS ====================

// Get user by ID (admin)
app.get('/api/admin/users/:id', authMiddleware, adminMiddleware, (req, res) => {
  db.query(
    `SELECT u.*, 
            e.company_name, e.company_logo, e.verified as company_verified,
            js.headline, js.location, js.experience_years, js.skills
     FROM users u
     LEFT JOIN employers e ON u.id = e.user_id
     LEFT JOIN job_seekers js ON u.id = js.user_id
     WHERE u.id = ?`,
    [req.params.id],
    (err, results) => {
      if (err) {
        console.error('Get user error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      if (results.length === 0) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }
      res.json({ success: true, data: results[0] });
    }
  );
});

// Update user role (admin)
app.put('/api/admin/users/:id/role', authMiddleware, adminMiddleware, (req, res) => {
  const { user_type } = req.body;
  
  if (!['job_seeker', 'employer', 'admin'].includes(user_type)) {
    return res.status(400).json({ success: false, message: 'Invalid user type' });
  }
  
  db.query('UPDATE users SET user_type = ? WHERE id = ?', [user_type, req.params.id], (err, result) => {
    if (err) {
      console.error('Update user role error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    
    createNotification(
      req.params.id,
      'system',
      'Account Role Updated',
      `Your account role has been changed to ${user_type.replace('_', ' ')} by admin.`,
      null
    );
    
    res.json({ success: true, message: 'User role updated successfully' });
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found',
    path: req.originalUrl
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════════════════════════════╗
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
