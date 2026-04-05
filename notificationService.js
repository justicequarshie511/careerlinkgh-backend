// Notification Service for CareerLinkGH
const db = require('./config/db');
const { v4: uuidv4 } = require('uuid');

class NotificationService {
  // Create a notification
  static async create(userId, type, title, message, data = null) {
    const id = uuidv4();
    
    return new Promise((resolve, reject) => {
      db.query(
        `INSERT INTO notifications (id, user_id, type, title, message, data)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [id, userId, type, title, message, data ? JSON.stringify(data) : null],
        (err, result) => {
          if (err) {
            console.error('Notification creation error:', err);
            reject(err);
          } else {
            resolve(id);
          }
        }
      );
    });
  }

  // Get user notifications
  static async getUserNotifications(userId, limit = 20, offset = 0) {
    return new Promise((resolve, reject) => {
      db.query(
        `SELECT * FROM notifications 
         WHERE user_id = ? 
         ORDER BY created_at DESC 
         LIMIT ? OFFSET ?`,
        [userId, limit, offset],
        (err, results) => {
          if (err) {
            console.error('Fetch notifications error:', err);
            reject(err);
          } else {
            resolve(results);
          }
        }
      );
    });
  }

  // Mark notification as read
  static async markAsRead(notificationId, userId) {
    return new Promise((resolve, reject) => {
      db.query(
        `UPDATE notifications 
         SET is_read = true, read_at = NOW() 
         WHERE id = ? AND user_id = ?`,
        [notificationId, userId],
        (err, result) => {
          if (err) {
            console.error('Mark as read error:', err);
            reject(err);
          } else {
            resolve(result.affectedRows > 0);
          }
        }
      );
    });
  }

  // Mark all notifications as read
  static async markAllAsRead(userId) {
    return new Promise((resolve, reject) => {
      db.query(
        `UPDATE notifications 
         SET is_read = true, read_at = NOW() 
         WHERE user_id = ? AND is_read = false`,
        [userId],
        (err, result) => {
          if (err) {
            console.error('Mark all as read error:', err);
            reject(err);
          } else {
            resolve(result.affectedRows);
          }
        }
      );
    });
  }

  // Get unread count
  static async getUnreadCount(userId) {
    return new Promise((resolve, reject) => {
      db.query(
        'SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = false',
        [userId],
        (err, results) => {
          if (err) {
            console.error('Get unread count error:', err);
            reject(err);
          } else {
            resolve(results[0].count);
          }
        }
      );
    });
  }

  // Application status notification
  static async applicationStatusChanged(applicationId, jobSeekerId, jobTitle, status) {
    const messages = {
      'reviewed': 'Your application is being reviewed',
      'shortlisted': 'Congratulations! You have been shortlisted',
      'interview': 'Interview has been scheduled',
      'accepted': 'Congratulations! You got the job',
      'rejected': 'Application status update'
    };

    const titles = {
      'reviewed': 'Application Under Review',
      'shortlisted': 'You\'ve Been Shortlisted! 🎉',
      'interview': 'Interview Invitation',
      'accepted': 'Job Offer Received! 🎊',
      'rejected': 'Application Update'
    };

    await this.create(
      jobSeekerId,
      'application',
      titles[status] || 'Application Update',
      messages[status] || `Your application status changed to ${status}`,
      { application_id: applicationId, status }
    );
  }

  // New job alert for saved searches
  static async newJobAlert(jobSeekerId, jobData) {
    await this.create(
      jobSeekerId,
      'job_alert',
      'New Job Matching Your Profile! 🎯',
      `New position: ${jobData.title} at ${jobData.company_name}`,
      { job_id: jobData.id }
    );
  }

  // Interview reminder
  static async interviewReminder(applicationId, jobSeekerId, jobTitle, interviewDate) {
    const date = new Date(interviewDate).toLocaleString();
    await this.create(
      jobSeekerId,
      'reminder',
      'Interview Reminder ⏰',
      `Your interview for ${jobTitle} is scheduled for ${date}`,
      { application_id: applicationId, interview_date: interviewDate }
    );
  }
}

module.exports = NotificationService;