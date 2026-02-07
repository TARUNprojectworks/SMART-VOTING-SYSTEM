const fs = require('fs');
const path = require('path');

const AUDIT_LOG_FILE = path.join(__dirname, 'audit.log');

/**
 * Log an authentication event to audit log
 * NIST SP 800-63-2 requires comprehensive audit logging
 * @param {string} type - Event type (LOGIN, LOGOUT, LOGIN_FAILED, etc.)
 * @param {string} userId - User identifier
 * @param {boolean} success - Whether action succeeded
 * @param {object} metadata - Additional event metadata
 */
exports.logAuthEvent = (type, userId, success, metadata = {}) => {
    const logEntry = {
        timestamp: new Date().toISOString(),
        eventType: type,
        userId: userId || 'UNKNOWN',
        success: success,
        ip: metadata.ip || 'UNKNOWN',
        sessionToken: metadata.sessionToken ? metadata.sessionToken.substring(0, 16) + '...' : null,
        reason: metadata.reason || null,
        additionalInfo: metadata.additionalInfo || null
    };

    // Append to log file (JSON Lines format)
    const logLine = JSON.stringify(logEntry) + '\n';

    try {
        fs.appendFileSync(AUDIT_LOG_FILE, logLine, 'utf8');
    } catch (error) {
        console.error('Failed to write to audit log:', error);
    }
};

/**
 * Log a voting event
 * @param {string} userId - Voter identifier
 * @param {boolean} success - Whether vote was cast successfully
 * @param {object} metadata - Additional metadata
 */
exports.logVoteEvent = (userId, success, metadata = {}) => {
    exports.logAuthEvent('VOTE', userId, success, metadata);
};

/**
 * Log an access control event
 * @param {string} userId - User identifier
 * @param {string} action - Action attempted
 * @param {boolean} granted - Whether access was granted
 * @param {object} metadata - Additional metadata
 */
exports.logAccessControl = (userId, action, granted, metadata = {}) => {
    exports.logAuthEvent('ACCESS_CONTROL', userId, granted, {
        ...metadata,
        action: action,
        reason: granted ? 'Permission granted' : 'Permission denied'
    });
};

/**
 * Log MFA events
 * @param {string} userId - User identifier
 * @param {string} eventType - MFA_SETUP, MFA_VERIFY, MFA_DISABLE
 * @param {boolean} success - Whether action succeeded
 * @param {object} metadata - Additional metadata
 */
exports.logMFAEvent = (userId, eventType, success, metadata = {}) => {
    exports.logAuthEvent(eventType, userId, success, metadata);
};

/**
 * Read recent audit logs
 * @param {number} limit - Number of recent entries to read (default 100)
 * @returns {Array<object>} - Array of log entries
 */
exports.getRecentLogs = (limit = 100) => {
    try {
        if (!fs.existsSync(AUDIT_LOG_FILE)) {
            return [];
        }

        const content = fs.readFileSync(AUDIT_LOG_FILE, 'utf8');
        const lines = content.trim().split('\n').filter(line => line);

        // Get last N lines
        const recentLines = lines.slice(-limit);

        // Parse JSON entries
        return recentLines.map(line => {
            try {
                return JSON.parse(line);
            } catch (e) {
                return null;
            }
        }).filter(entry => entry !== null);
    } catch (error) {
        console.error('Failed to read audit log:', error);
        return [];
    }
};

/**
 * Get logs for specific user
 * @param {string} userId - User identifier
 * @param {number} limit - Maximum entries to return
 * @returns {Array<object>} - Filtered log entries
 */
exports.getUserLogs = (userId, limit = 50) => {
    const allLogs = exports.getRecentLogs(1000);
    return allLogs
        .filter(log => log.userId === userId)
        .slice(-limit);
};

/**
 * Generic audit event logger
 * @param {string} eventType - Type of event
 * @param {string} userId - User identifier
 * @param {boolean} success - Whether action succeeded
 * @param {object} metadata - Additional metadata
 */
exports.logAuditEvent = (eventType, userId, success, metadata = {}) => {
    exports.logAuthEvent(eventType, userId, success, metadata);
};

