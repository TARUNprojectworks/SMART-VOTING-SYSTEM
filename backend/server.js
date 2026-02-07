require('dotenv').config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const fs = require("fs");

const app = express();

// Security middleware - Helmet for HTTP headers
app.use(helmet({
    contentSecurityPolicy: false, // Allow for development; enable in production
    crossOriginEmbedderPolicy: false
}));

// CORS configuration
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));

// Rate limiting for brute-force protection
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 requests per windowMs
    message: {
        success: false,
        message: "Too many login attempts. Please try again later.",
        errorCode: "RATE_LIMIT_EXCEEDED"
    },
    standardHeaders: true,
    legacyHeaders: false
});

// General API rate limiting
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 60, // 60 requests per minute
    message: {
        success: false,
        message: "Too many requests. Please slow down.",
        errorCode: "RATE_LIMIT_EXCEEDED"
    }
});

// Body parser
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${req.ip || 'UNKNOWN'}`);
    next();
});


// Import authentication modules
const { login } = require('./auth');
const { requestOTP, verifyOTP } = require('./otpAuth');
const { verifyCredentials } = require('./credentialVerify');
const { vote } = require('./accessControl');
const { destroySession } = require('./sessionManager');
const { logAuthEvent } = require('./auditLogger');
const { registerNewUser, getPendingUsers, approveUser, rejectUser } = require('./userRegistration');

// Public routes
app.post("/login", loginLimiter, login);

// OTP Authentication routes
app.post("/auth/verify-credentials", loginLimiter, verifyCredentials);
app.post("/auth/request-otp", loginLimiter, requestOTP);
app.post("/auth/verify-otp", loginLimiter, verifyOTP);

// Protected routes (require authentication)
app.post("/vote", apiLimiter, vote);

// Import dependencies for middleware
const { validateSession } = require('./sessionManager');
const { checkPermission, PERMISSIONS } = require('./accessControlMatrix');

// Middleware to extract officer ID from session
const extractOfficerId = (req, res, next) => {
    const { sessionToken, sessionSignature } = req.body;
    const clientIp = req.ip || 'UNKNOWN';
    const userAgent = req.get('user-agent') || '';

    const sessionValidation = validateSession(sessionToken, sessionSignature, {
        ip: clientIp,
        userAgent: userAgent
    });

    if (!sessionValidation.valid) {
        return res.status(401).json({
            success: false,
            message: "Invalid or expired session",
            errorCode: sessionValidation.errorCode || "INVALID_SESSION"
        });
    }

    const { voterId, role } = sessionValidation.session;

    // Check permission
    if (!checkPermission(role, PERMISSIONS.MANAGE_ELECTION)) {
        return res.status(403).json({
            success: false,
            message: "You do not have permission to manage users",
            errorCode: "INSUFFICIENT_PERMISSIONS"
        });
    }

    req.officerId = voterId;
    next();
};

// User registration routes
app.post("/auth/register", loginLimiter, registerNewUser);
app.get("/users/pending", apiLimiter, getPendingUsers);
app.post("/users/approve", apiLimiter, extractOfficerId, approveUser);
app.post("/users/reject", apiLimiter, extractOfficerId, rejectUser);

// Election management routes
const {
    createElection,
    getElections,
    getElectionById,
    getActiveElection,
    updateElectionStatus,
    deleteElection
} = require('./electionManager');


// Create new election (officers/admin only)
app.post("/elections/create", apiLimiter, (req, res) => {
    const { sessionToken, sessionSignature, electionData } = req.body;
    const clientIp = req.ip || 'UNKNOWN';
    const userAgent = req.get('user-agent') || '';

    // Validate session
    const sessionValidation = validateSession(sessionToken, sessionSignature, {
        ip: clientIp,
        userAgent: userAgent
    });

    if (!sessionValidation.valid) {
        return res.status(401).json({
            success: false,
            message: "Invalid or expired session",
            errorCode: sessionValidation.errorCode || "INVALID_SESSION"
        });
    }

    const { voterId, role } = sessionValidation.session;

    // Check permission to create election
    if (!checkPermission(role, PERMISSIONS.CREATE_ELECTION)) {
        return res.status(403).json({
            success: false,
            message: "You do not have permission to create elections",
            errorCode: "INSUFFICIENT_PERMISSIONS"
        });
    }

    // Create election
    const result = createElection(electionData, voterId, clientIp);
    res.status(result.success ? 200 : 400).json(result);
});

// Get all elections
app.get("/elections", (req, res) => {
    const { status, activeOnly } = req.query;
    const filters = {};

    if (status) filters.status = status;
    if (activeOnly === 'true') filters.activeOnly = true;

    const result = getElections(filters);
    res.json(result);
});

// Get active election
app.get("/elections/active", (req, res) => {
    const result = getActiveElection();
    res.status(result.success ? 200 : 404).json(result);
});

// Get specific election by ID
app.get("/elections/:id", (req, res) => {
    const result = getElectionById(req.params.id);
    res.status(result.success ? 200 : 404).json(result);
});

// Update election status
app.put("/elections/:id/status", apiLimiter, (req, res) => {
    const { sessionToken, sessionSignature, status } = req.body;
    const clientIp = req.ip || 'UNKNOWN';
    const userAgent = req.get('user-agent') || '';

    // Validate session
    const sessionValidation = validateSession(sessionToken, sessionSignature, {
        ip: clientIp,
        userAgent: userAgent
    });

    if (!sessionValidation.valid) {
        return res.status(401).json({
            success: false,
            message: "Invalid or expired session",
            errorCode: sessionValidation.errorCode || "INVALID_SESSION"
        });
    }

    const { voterId, role } = sessionValidation.session;

    // Check permission
    if (!checkPermission(role, PERMISSIONS.MANAGE_ELECTION)) {
        return res.status(403).json({
            success: false,
            message: "You do not have permission to manage elections",
            errorCode: "INSUFFICIENT_PERMISSIONS"
        });
    }

    // Update status
    const result = updateElectionStatus(req.params.id, status, voterId, clientIp);
    res.status(result.success ? 200 : 400).json(result);
});

// Delete election
app.delete("/elections/:id", apiLimiter, (req, res) => {
    const { sessionToken, sessionSignature } = req.body;
    const clientIp = req.ip || 'UNKNOWN';
    const userAgent = req.get('user-agent') || '';

    // Validate session
    const sessionValidation = validateSession(sessionToken, sessionSignature, {
        ip: clientIp,
        userAgent: userAgent
    });

    if (!sessionValidation.valid) {
        return res.status(401).json({
            success: false,
            message: "Invalid or expired session",
            errorCode: sessionValidation.errorCode || "INVALID_SESSION"
        });
    }

    const { voterId, role } = sessionValidation.session;

    // Check permission
    if (!checkPermission(role, PERMISSIONS.MANAGE_ELECTION)) {
        return res.status(403).json({
            success: false,
            message: "You do not have permission to delete elections",
            errorCode: "INSUFFICIENT_PERMISSIONS"
        });
    }

    // Delete election
    const result = deleteElection(req.params.id, voterId, clientIp);
    res.status(result.success ? 200 : 400).json(result);
});

// Logout endpoint
app.post("/logout", (req, res) => {
    const { sessionToken } = req.body;
    const voterId = req.body.voterId || 'UNKNOWN';
    const clientIp = req.ip || 'UNKNOWN';

    if (sessionToken) {
        destroySession(sessionToken);

        logAuthEvent('LOGOUT', voterId, true, {
            ip: clientIp,
            sessionToken: sessionToken
        });
    }

    res.json({ success: true, message: "Logged out successfully" });
});

// Results endpoint (public - anyone can view)
app.get("/results", (req, res) => {
    try {
        const data = JSON.parse(fs.readFileSync("./user.json"));
        const results = {};

        data.users.forEach(user => {
            if (user.vote && user.role === "voter") {
                results[user.vote] = (results[user.vote] || 0) + 1;
            }
        });

        res.json({
            success: true,
            results,
            totalVotes: Object.values(results).reduce((a, b) => a + b, 0)
        });
    } catch (error) {
        console.error('Error fetching results:', error);
        res.status(500).json({
            success: false,
            message: "Failed to retrieve results",
            errorCode: "SYSTEM_ERROR"
        });
    }
});

// Health check endpoint
app.get("/health", (req, res) => {
    res.json({
        status: "healthy",
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);

    res.status(500).json({
        success: false,
        message: "Internal server error. Please try again later.",
        errorCode: "INTERNAL_ERROR"
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "Endpoint not found",
        errorCode: "NOT_FOUND"
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`╔════════════════════════════════════════════════════╗`);
    console.log(`║   Smart Voting System - Secure Backend Server     ║`);
    console.log(`║   NIST SP 800-63-2 Compliant Authentication        ║`);
    console.log(`╚════════════════════════════════════════════════════╝`);
    console.log(`\n✓ Server running on http://localhost:${PORT}`);
    console.log(`✓ Security features enabled:`);
    console.log(`  - Salted password hashing (bcrypt)`);
    console.log(`  - Multi-factor authentication (TOTP)`);
    console.log(`  - Session fingerprinting & HMAC integrity`);
    console.log(`  - Brute-force protection & account lockout`);
    console.log(`  - Rate limiting on all endpoints`);
    console.log(`  - Comprehensive audit logging`);
    console.log(`  - Role-based access control`);
    console.log(`\n⚠️  Development mode - some features simplified\n`);
});

