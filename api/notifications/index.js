// Notifications API - In-memory store (use Redis/PostgreSQL in production)
// For serverless, this persists per-instance. Consider Vercel KV or external DB for production.

let notifications = [
  // Sample notifications - in production these would come from database events
];

// Generate notification ID
function generateId() {
  return `notif-${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 9)}`;
}

// Add notification (called internally or via webhook)
export function addNotification(notification) {
  const newNotification = {
    id: generateId(),
    type: notification.type || 'system',
    title: notification.title,
    message: notification.message,
    timestamp: new Date().toISOString(),
    isRead: false,
    link: notification.link || null,
    priority: notification.priority || 'low',
    userId: notification.userId || 'admin',
  };

  notifications.unshift(newNotification);

  // Keep only last 100 notifications per user
  const userNotifications = notifications.filter(n => n.userId === newNotification.userId);
  if (userNotifications.length > 100) {
    const toRemove = userNotifications.slice(100);
    notifications = notifications.filter(n => !toRemove.includes(n));
  }

  return newNotification;
}

export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const userId = req.headers['x-user-id'] || 'admin';

  // GET - Retrieve notifications
  if (req.method === 'GET') {
    const userNotifications = notifications.filter(n => n.userId === userId);
    const unreadCount = userNotifications.filter(n => !n.isRead).length;

    return res.status(200).json({
      success: true,
      notifications: userNotifications,
      unreadCount,
      total: userNotifications.length,
    });
  }

  // POST - Create notification (admin/webhook)
  if (req.method === 'POST') {
    try {
      const { type, title, message, link, priority, userId: targetUserId } = req.body;

      if (!title || !message) {
        return res.status(400).json({
          success: false,
          message: 'Title and message are required',
        });
      }

      const notification = addNotification({
        type,
        title,
        message,
        link,
        priority,
        userId: targetUserId || userId,
      });

      return res.status(201).json({
        success: true,
        notification,
      });
    } catch (error) {
      console.error('Create notification error:', error);
      return res.status(500).json({
        success: false,
        message: 'Failed to create notification',
      });
    }
  }

  // PATCH - Mark notifications as read
  if (req.method === 'PATCH') {
    try {
      const { action, notificationId } = req.body;

      if (action === 'mark-all-read') {
        notifications = notifications.map(n =>
          n.userId === userId ? { ...n, isRead: true } : n
        );
        return res.status(200).json({
          success: true,
          message: 'All notifications marked as read',
        });
      }

      if (action === 'mark-read' && notificationId) {
        notifications = notifications.map(n =>
          n.id === notificationId && n.userId === userId ? { ...n, isRead: true } : n
        );
        return res.status(200).json({
          success: true,
          message: 'Notification marked as read',
        });
      }

      return res.status(400).json({
        success: false,
        message: 'Invalid action',
      });
    } catch (error) {
      console.error('Update notification error:', error);
      return res.status(500).json({
        success: false,
        message: 'Failed to update notifications',
      });
    }
  }

  // DELETE - Delete notification(s)
  if (req.method === 'DELETE') {
    try {
      const { notificationId, clearAll } = req.body;

      if (clearAll) {
        notifications = notifications.filter(n => n.userId !== userId);
        return res.status(200).json({
          success: true,
          message: 'All notifications cleared',
        });
      }

      if (notificationId) {
        notifications = notifications.filter(n =>
          !(n.id === notificationId && n.userId === userId)
        );
        return res.status(200).json({
          success: true,
          message: 'Notification deleted',
        });
      }

      return res.status(400).json({
        success: false,
        message: 'Notification ID or clearAll required',
      });
    } catch (error) {
      console.error('Delete notification error:', error);
      return res.status(500).json({
        success: false,
        message: 'Failed to delete notification',
      });
    }
  }

  return res.status(405).json({
    success: false,
    message: 'Method not allowed',
  });
}
