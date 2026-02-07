const fs = require("fs");
const { createSession } = require("./sessionManager");
const { verifyPassword, verifyMFAToken } = require("./crypto");
const { logAuthEvent } = require("./auditLogger");
const { isMFARequired, checkPermission } = require("./accessControlMatrix");

// Brute-force protection constants
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

/**
 * Read user data from file
 * @returns {object} - User data object
 */
const readUserData = () => {
    try {
        return JSON.parse(fs.readFileSync("./user.json", "utf8"));
    } catch (error) {
        throw new Error("Failed to read user data");
    }
};

/**
 * Save user data to file
 * @param {object} data - User data to save
 */
const saveUserData = (data) => {
    try {
        fs.writeFileSync("./user.json", JSON.stringify(data, null, 4));
    } catch (error) {
        throw new Error("Failed to save user data");
    }
};

/**
 * Login endpoint - NIST SP 800-63-2 compliant authentication
 * Supports LOA-1 through LOA-4 authentication levels
 */
exports.login = async (req, res) => {
    const { voterId, password, mfaToken } = req.body;
    const clientIp = req.ip || req.connection.remoteAddress || 'UNKNOWN';
    const userAgent = req.get('user-agent') || '';

    // Validate input
    if (!voterId || voterId.trim() === "") {
        logAuthEvent('LOGIN_FAILED', null, false, {
            ip: clientIp,
            reason: 'Missing voter ID'
        });
        return res.status(400).json({
            success: false,
            message: "Voter ID is required",
            errorCode: "MISSING_VOTER_ID"
        });
    }

    if (!password || password.trim() === "") {
        logAuthEvent('LOGIN_FAILED', voterId, false, {
            ip: clientIp,
            reason: 'Missing password'
        });
        return res.status(400).json({
            success: false,
            message: "Password is required",
            errorCode: "MISSING_PASSWORD"
        });
    }

    // Read user data
    let data;
    try {
        data = readUserData();
    } catch (error) {
        logAuthEvent('LOGIN_FAILED', voterId, false, {
            ip: clientIp,
            reason: 'System error'
        });
        return res.status(500).json({
            success: false,
            message: "System error. Please try again later.",
            errorCode: "SYSTEM_ERROR"
        });
    }

    // Find user
    const user = data.users.find(u => u.voterId === voterId.trim());

    // Generic error message to prevent user enumeration
    const genericError = {
        success: false,
        message: "Invalid credentials. Please check your Voter ID and password.",
        errorCode: "INVALID_CREDENTIALS"
    };

    // Check if user exists
    if (!user) {
        logAuthEvent('LOGIN_FAILED', voterId, false, {
            ip: clientIp,
            reason: 'User not found'
        });
        return res.status(401).json(genericError);
    }

    // Check account lockout
    if (user.accountLockedUntil) {
        const lockoutExpiry = new Date(user.accountLockedUntil);
        if (new Date() < lockoutExpiry) {
            const minutesRemaining = Math.ceil((lockoutExpiry - new Date()) / 60000);
            logAuthEvent('LOGIN_FAILED', voterId, false, {
                ip: clientIp,
                reason: 'Account locked'
            });
            return res.status(403).json({
                success: false,
                message: `Account temporarily locked due to multiple failed login attempts. Please try again in ${minutesRemaining} minutes.`,
                errorCode: "ACCOUNT_LOCKED",
                lockedUntil: user.accountLockedUntil
            });
        } else {
            // Lockout expired, reset
            user.accountLockedUntil = null;
            user.failedLoginAttempts = 0;
        }
    }

    // Verify password
    let passwordValid = false;
    try {
        passwordValid = await verifyPassword(password, user.passwordHash);
    } catch (error) {
        console.error('Password verification error:', error);
        return res.status(500).json({
            success: false,
            message: "Authentication error. Please try again.",
            errorCode: "AUTH_ERROR"
        });
    }

    if (!passwordValid) {
        // Increment failed attempts
        user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;

        // Check if should lock account
        if (user.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
            user.accountLockedUntil = new Date(Date.now() + LOCKOUT_DURATION).toISOString();
            saveUserData(data);

            logAuthEvent('ACCOUNT_LOCKED', voterId, false, {
                ip: clientIp,
                reason: `${MAX_FAILED_ATTEMPTS} failed login attempts`,
                additionalInfo: `Locked for ${LOCKOUT_DURATION / 60000} minutes`
            });

            return res.status(403).json({
                success: false,
                message: "Account locked due to multiple failed login attempts. Please try again in 15 minutes.",
                errorCode: "ACCOUNT_LOCKED",
                lockedUntil: user.accountLockedUntil
            });
        }

        saveUserData(data);

        logAuthEvent('LOGIN_FAILED', voterId, false, {
            ip: clientIp,
            reason: 'Invalid password',
            additionalInfo: `Failed attempts: ${user.failedLoginAttempts}/${MAX_FAILED_ATTEMPTS}`
        });

        return res.status(401).json(genericError);
    }

    // Check if user is registered
    if (!user.registered) {
        logAuthEvent('LOGIN_FAILED', voterId, false, {
            ip: clientIp,
            reason: 'Not registered'
        });
        return res.status(403).json({
            success: false,
            message: "This voter ID is not registered for voting.",
            errorCode: "NOT_REGISTERED"
        });
    }

    // Check MFA requirement
    const mfaRequired = isMFARequired(user.role);
    const mfaEnabled = user.mfaEnabled || false;

    // LOA-3: Multi-Factor Authentication
    if (mfaRequired && !mfaEnabled) {
        // MFA is required but not set up yet - force setup
        logAuthEvent('MFA_SETUP_REQUIRED', voterId, false, {
            ip: clientIp,
            reason: 'MFA required for role but not configured'
        });
        return res.status(403).json({
            success: false,
            message: "Multi-factor authentication is required for your role. Please contact an administrator to set up MFA.",
            errorCode: "MFA_SETUP_REQUIRED",
            requiresMFA: true
        });
    }

    if (mfaEnabled) {
        // User has MFA enabled, verify token
        if (!mfaToken || mfaToken.trim() === "") {
            return res.status(400).json({
                success: false,
                message: "MFA token is required",
                errorCode: "MFA_TOKEN_REQUIRED",
                requiresMFA: true
            });
        }

        // Verify MFA token
        const mfaValid = verifyMFAToken(user.mfaSecret, mfaToken.trim());

        if (!mfaValid) {
            user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;

            if (user.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
                user.accountLockedUntil = new Date(Date.now() + LOCKOUT_DURATION).toISOString();
                saveUserData(data);

                logAuthEvent('ACCOUNT_LOCKED', voterId, false, {
                    ip: clientIp,
                    reason: 'Failed MFA attempts'
                });

                return res.status(403).json({
                    success: false,
                    message: "Account locked due to multiple failed authentication attempts.",
                    errorCode: "ACCOUNT_LOCKED"
                });
            }

            saveUserData(data);

            logAuthEvent('LOGIN_FAILED', voterId, false, {
                ip: clientIp,
                reason: 'Invalid MFA token'
            });

            return res.status(401).json({
                success: false,
                message: "Invalid MFA token. Please try again.",
                errorCode: "INVALID_MFA_TOKEN"
            });
        }
    }

    // Authentication successful - reset failed attempts
    user.failedLoginAttempts = 0;
    user.accountLockedUntil = null;
    user.lastLogin = new Date().toISOString();

    saveUserData(data);

    // Create secure session with fingerprinting
    const sessionData = createSession(user.voterId, user.role, {
        ip: clientIp,
        userAgent: userAgent
    });

    // Log successful login
    logAuthEvent('LOGIN_SUCCESS', voterId, true, {
        ip: clientIp,
        sessionToken: sessionData.sessionToken,
        authenticationLevel: user.authenticationLevel,
        mfaUsed: mfaEnabled
    });

    // Return success response
    res.json({
        success: true,
        message: "Login successful",
        sessionToken: sessionData.sessionToken,
        sessionSignature: sessionData.signature,
        expiresAt: sessionData.expiresAt,
        user: {
            voterId: user.voterId,
            name: user.name,
            role: user.role,
            hasVoted: user.voted || false,
            canVote: user.role === "voter" && !user.voted,
            mfaEnabled: user.mfaEnabled || false,
            authenticationLevel: user.authenticationLevel || 'LOA-2'
        }
    });
};

