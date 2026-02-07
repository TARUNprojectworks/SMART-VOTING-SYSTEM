const crypto = require("crypto");
const { generateSecureToken, generateHMAC, verifyHMAC } = require("./crypto");

// In-memory session store (in production, use Redis or similar)
const sessions = new Map();

// HMAC secret for session token integrity (in production, use environment variable)
const HMAC_SECRET = process.env.SESSION_HMAC_SECRET || crypto.randomBytes(32).toString('hex');

// Session configuration
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes
const SESSION_RENEWAL_WINDOW = 5 * 60 * 1000; // Renew if activity within last 5 minutes

/**
 * Create session fingerprint from request metadata
 * @param {string} userAgent - User agent string
 * @param {string} ip - IP address
 * @returns {string} - Fingerprint hash
 */
const createFingerprint = (userAgent = '', ip = '') => {
    return crypto.createHash('sha256')
        .update(userAgent + ip)
        .digest('hex');
};

/**
 * Generate secure session token with HMAC signature
 * @param {string} voterId - User's voter ID
 * @param {string} role - User role
 * @param {object} metadata - Session metadata (IP, user agent)
 * @returns {object} - Session token and signature
 */
exports.createSession = (voterId, role, metadata = {}) => {
    const sessionToken = generateSecureToken(32);
    const signature = generateHMAC(sessionToken, HMAC_SECRET);

    const sessionData = {
        voterId,
        role,
        createdAt: new Date().toISOString(),
        lastActivity: new Date().toISOString(),
        expiresAt: new Date(Date.now() + SESSION_TIMEOUT).toISOString(),
        fingerprint: createFingerprint(metadata.userAgent, metadata.ip),
        ip: metadata.ip || 'UNKNOWN',
        signature: signature
    };

    sessions.set(sessionToken, sessionData);

    return {
        sessionToken,
        signature,
        expiresAt: sessionData.expiresAt
    };
};

/**
 * Validate session token with integrity check
 * @param {string} token - Session token
 * @param {string} signature - HMAC signature
 * @param {object} metadata - Request metadata for fingerprint verification
 * @returns {object} - Validation result with session data
 */
exports.validateSession = (token, signature, metadata = {}) => {
    // Verify HMAC integrity
    if (!verifyHMAC(token, signature, HMAC_SECRET)) {
        return {
            valid: false,
            message: "Session integrity check failed",
            errorCode: "SESSION_TAMPERED"
        };
    }

    const session = sessions.get(token);

    if (!session) {
        return {
            valid: false,
            message: "Invalid session",
            errorCode: "INVALID_SESSION"
        };
    }

    // Check expiration
    if (new Date() > new Date(session.expiresAt)) {
        sessions.delete(token);
        return {
            valid: false,
            message: "Session expired",
            errorCode: "SESSION_EXPIRED"
        };
    }

    // Verify session fingerprint to prevent hijacking
    const currentFingerprint = createFingerprint(metadata.userAgent, metadata.ip);
    if (session.fingerprint !== currentFingerprint) {
        // Session hijacking suspected
        sessions.delete(token);
        return {
            valid: false,
            message: "Session fingerprint mismatch",
            errorCode: "SESSION_HIJACKED"
        };
    }

    // Update last activity
    session.lastActivity = new Date().toISOString();

    // Auto-renew session if within renewal window
    const timeSinceCreation = Date.now() - new Date(session.createdAt).getTime();
    if (timeSinceCreation > SESSION_RENEWAL_WINDOW) {
        session.expiresAt = new Date(Date.now() + SESSION_TIMEOUT).toISOString();
    }

    return {
        valid: true,
        session: {
            voterId: session.voterId,
            role: session.role,
            createdAt: session.createdAt,
            expiresAt: session.expiresAt
        }
    };
};

/**
 * Get full session information
 * @param {string} token - Session token
 * @returns {object|null} - Session data or null
 */
exports.getSessionInfo = (token) => {
    return sessions.get(token) || null;
};

/**
 * Destroy session (logout)
 * @param {string} token - Session token
 * @returns {boolean} - True if session was deleted
 */
exports.destroySession = (token) => {
    return sessions.delete(token);
};

/**
 * Clean expired sessions periodically
 */
const cleanupExpiredSessions = () => {
    const now = new Date();
    let cleanedCount = 0;

    for (const [token, session] of sessions.entries()) {
        if (now > new Date(session.expiresAt)) {
            sessions.delete(token);
            cleanedCount++;
        }
    }

    if (cleanedCount > 0) {
        console.log(`[Session Cleanup] Removed ${cleanedCount} expired sessions`);
    }
};

// Run cleanup every hour
setInterval(cleanupExpiredSessions, 60 * 60 * 1000);

/**
 * Get active session count
 * @returns {number} - Number of active sessions
 */
exports.getActiveSessionCount = () => {
    return sessions.size;
};

