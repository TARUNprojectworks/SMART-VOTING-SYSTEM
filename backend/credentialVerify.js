const fs = require('fs');
const { verifyPassword } = require('./crypto');
const { logAuthEvent } = require('./auditLogger');

// Helper functions to read/write user data
const readUserData = () => {
    return JSON.parse(fs.readFileSync('./user.json', 'utf-8'));
};

const writeUserData = (data) => {
    fs.writeFileSync('./user.json', JSON.stringify(data, null, 4));
};

/**
 * Verify credentials (password) without sending OTP
 * POST /auth/verify-credentials
 * Body: { voterId, password, role }
 * 
 * Features:
 * - Validates voter ID and password
 * - Checks role match
 * - 5 failed attempts lockout for 15 minutes
 */
exports.verifyCredentials = async (req, res) => {
    const { voterId, password, role } = req.body;
    const clientIp = req.ip || 'UNKNOWN';

    // Validate input
    if (!voterId || !password || !role) {
        return res.status(400).json({
            success: false,
            message: 'Voter ID, password, and role are required',
            errorCode: 'MISSING_PARAMETERS'
        });
    }

    // Validate role
    if (!['voter', 'election_officer', 'admin'].includes(role)) {
        return res.status(400).json({
            success: false,
            message: 'Role must be "voter", "election_officer", or "admin"',
            errorCode: 'INVALID_ROLE'
        });
    }

    try {
        const data = readUserData();
        const user = data.users.find(u => u.voterId === voterId.trim());

        if (!user) {
            logAuthEvent('CREDENTIAL_VERIFY_FAILED', voterId, false, {
                ip: clientIp,
                reason: 'User not found'
            });

            return res.status(401).json({
                success: false,
                message: 'Invalid credentials. Please check your Voter ID and password.',
                errorCode: 'INVALID_CREDENTIALS'
            });
        }

        if (!user.registered) {
            return res.status(403).json({
                success: false,
                message: 'This voter ID is not registered',
                errorCode: 'NOT_REGISTERED'
            });
        }

        // Verify role matches
        if (user.role !== role) {
            logAuthEvent('CREDENTIAL_VERIFY_FAILED', voterId, false, {
                ip: clientIp,
                reason: 'Role mismatch',
                expectedRole: user.role,
                providedRole: role
            });

            return res.status(403).json({
                success: false,
                message: `This ID is not registered as ${role === 'voter' ? 'a Voter' : 'an Election Officer'}.`,
                errorCode: 'ROLE_MISMATCH'
            });
        }

        // Check user approval status (for voters)
        if (user.status && user.status !== 'approved') {
            let message = 'Account not approved';

            if (user.status === 'pending') {
                message = 'Your registration is pending approval from an Election Officer. Please wait for approval.';
            } else if (user.status === 'rejected') {
                message = 'Your registration has been rejected. Please contact an Election Officer for more information.';
            }

            logAuthEvent('CREDENTIAL_VERIFY_FAILED', voterId, false, {
                ip: clientIp,
                reason: 'Account not approved',
                status: user.status
            });

            return res.status(403).json({
                success: false,
                message: message,
                errorCode: 'NOT_APPROVED',
                status: user.status
            });
        }

        // Check if account is locked
        if (user.accountLockedUntil) {
            const lockExpiry = new Date(user.accountLockedUntil);
            if (lockExpiry > new Date()) {
                const minutesRemaining = Math.ceil((lockExpiry - new Date()) / 60000);

                logAuthEvent('CREDENTIAL_VERIFY_BLOCKED', voterId, false, {
                    ip: clientIp,
                    reason: 'Account locked',
                    lockExpiresAt: user.accountLockedUntil
                });

                return res.status(403).json({
                    success: false,
                    message: `Account temporarily locked. Please try again in ${minutesRemaining} minute(s).`,
                    errorCode: 'ACCOUNT_LOCKED',
                    lockExpiresAt: user.accountLockedUntil
                });
            } else {
                // Lock has expired, reset counters
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
                message: 'Authentication error. Please try again.',
                errorCode: 'AUTH_ERROR'
            });
        }

        if (!passwordValid) {
            // Increment failed attempts
            user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;

            // Lock account after 5 failed attempts for 15 minutes
            if (user.failedLoginAttempts >= 5) {
                const lockUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes from now
                user.accountLockedUntil = lockUntil.toISOString();

                writeUserData(data);

                logAuthEvent('ACCOUNT_LOCKED', voterId, false, {
                    ip: clientIp,
                    reason: 'Too many failed attempts',
                    failedAttempts: user.failedLoginAttempts,
                    lockExpiresAt: user.accountLockedUntil
                });

                return res.status(403).json({
                    success: false,
                    message: 'Account locked due to too many failed attempts. Please try again in 15 minutes.',
                    errorCode: 'ACCOUNT_LOCKED',
                    lockExpiresAt: user.accountLockedUntil
                });
            }

            writeUserData(data);

            const attemptsRemaining = 5 - user.failedLoginAttempts;

            logAuthEvent('CREDENTIAL_VERIFY_FAILED', voterId, false, {
                ip: clientIp,
                reason: 'Invalid password',
                failedAttempts: user.failedLoginAttempts,
                attemptsRemaining
            });

            return res.status(401).json({
                success: false,
                message: `Invalid credentials. ${attemptsRemaining} attempt(s) remaining.`,
                errorCode: 'INVALID_CREDENTIALS',
                attemptsRemaining
            });
        }

        // Password is correct - reset failed attempts
        user.failedLoginAttempts = 0;
        user.accountLockedUntil = null;
        writeUserData(data);

        logAuthEvent('CREDENTIAL_VERIFY_SUCCESS', voterId, true, {
            ip: clientIp,
            role: user.role
        });

        return res.status(200).json({
            success: true,
            message: 'Credentials verified successfully',
            verified: true
        });

    } catch (error) {
        console.error('Credential verification error:', error);
        logAuthEvent('CREDENTIAL_VERIFY_ERROR', voterId, false, {
            ip: clientIp,
            error: error.message
        });

        return res.status(500).json({
            success: false,
            message: 'Server error during verification. Please try again.',
            errorCode: 'SERVER_ERROR'
        });
    }
};
