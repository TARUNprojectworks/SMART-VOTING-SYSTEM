const fs = require('fs');
const { generateMFASecret, verifyMFAToken, generateQRCode, encryptData, decryptData, generateEncryptionKey } = require('./crypto');
const { validateSession } = require('./sessionManager');
const { logMFAEvent } = require('./auditLogger');

// Encryption key for MFA secrets (in production, use environment variable)
const MFA_ENCRYPTION_KEY = process.env.MFA_ENCRYPTION_KEY || generateEncryptionKey();

/**
 * Read user data from file
 */
const readUserData = () => {
    return JSON.parse(fs.readFileSync('./user.json', 'utf8'));
};

/**
 * Save user data to file
 */
const saveUserData = (data) => {
    fs.writeFileSync('./user.json', JSON.stringify(data, null, 4));
};

/**
 * Setup MFA for a user - generate secret and QR code
 * POST /mfa/setup
 */
exports.setupMFA = async (req, res) => {
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
            message: sessionValidation.message,
            errorCode: sessionValidation.errorCode
        });
    }

    const voterId = sessionValidation.session.voterId;

    try {
        // Generate MFA secret
        const mfaData = generateMFASecret(voterId);

        // Generate QR code
        const qrCode = await generateQRCode(mfaData.otpauthUrl);

        // Don't save to database yet - user must verify first

        logMFAEvent(voterId, 'MFA_SETUP_INITIATED', true, {
            ip: clientIp
        });

        res.json({
            success: true,
            message: 'MFA setup initiated',
            secret: mfaData.secret,
            qrCode: qrCode,
            manualEntryKey: mfaData.secret
        });
    } catch (error) {
        console.error('MFA setup error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to setup MFA',
            errorCode: 'MFA_SETUP_ERROR'
        });
    }
};

/**
 * Verify and enable MFA for a user
 * POST /mfa/verify-setup
 */
exports.verifyMFASetup = async (req, res) => {
    const { sessionToken, sessionSignature, secret, token } = req.body;
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
            message: sessionValidation.message,
            errorCode: sessionValidation.errorCode
        });
    }

    const voterId = sessionValidation.session.voterId;

    if (!secret || !token) {
        return res.status(400).json({
            success: false,
            message: 'Secret and token are required',
            errorCode: 'MISSING_PARAMETERS'
        });
    }

    // Verify the token
    const isValid = verifyMFAToken(secret, token);

    if (!isValid) {
        logMFAEvent(voterId, 'MFA_SETUP_FAILED', false, {
            ip: clientIp,
            reason: 'Invalid verification token'
        });

        return res.status(400).json({
            success: false,
            message: 'Invalid verification code. Please try again.',
            errorCode: 'INVALID_MFA_TOKEN'
        });
    }

    // Token is valid - save encrypted secret to user data
    try {
        const data = readUserData();
        const user = data.users.find(u => u.voterId === voterId);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found',
                errorCode: 'USER_NOT_FOUND'
            });
        }

        // Encrypt and save MFA secret
        const encryptedSecret = encryptData(secret, MFA_ENCRYPTION_KEY);
        user.mfaSecret = JSON.stringify(encryptedSecret);
        user.mfaEnabled = true;

        saveUserData(data);

        logMFAEvent(voterId, 'MFA_ENABLED', true, {
            ip: clientIp
        });

        res.json({
            success: true,
            message: 'MFA enabled successfully'
        });
    } catch (error) {
        console.error('MFA enable error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to enable MFA',
            errorCode: 'MFA_ENABLE_ERROR'
        });
    }
};

/**
 * Disable MFA for a user (requires password confirmation)
 * POST /mfa/disable
 */
exports.disableMFA = async (req, res) => {
    const { sessionToken, sessionSignature, password } = req.body;
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
            message: sessionValidation.message,
            errorCode: sessionValidation.errorCode
        });
    }

    const voterId = sessionValidation.session.voterId;

    if (!password) {
        return res.status(400).json({
            success: false,
            message: 'Password confirmation is required',
            errorCode: 'MISSING_PASSWORD'
        });
    }

    try {
        const { verifyPassword } = require('./crypto');
        const data = readUserData();
        const user = data.users.find(u => u.voterId === voterId);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found',
                errorCode: 'USER_NOT_FOUND'
            });
        }

        // Verify password
        const passwordValid = await verifyPassword(password, user.passwordHash);

        if (!passwordValid) {
            logMFAEvent(voterId, 'MFA_DISABLE_FAILED', false, {
                ip: clientIp,
                reason: 'Invalid password'
            });

            return res.status(401).json({
                success: false,
                message: 'Invalid password',
                errorCode: 'INVALID_PASSWORD'
            });
        }

        // Check if MFA is required for this role
        const { isMFARequired } = require('./accessControlMatrix');
        if (isMFARequired(user.role)) {
            return res.status(403).json({
                success: false,
                message: 'MFA is mandatory for your role and cannot be disabled',
                errorCode: 'MFA_REQUIRED'
            });
        }

        // Disable MFA
        user.mfaEnabled = false;
        user.mfaSecret = null;

        saveUserData(data);

        logMFAEvent(voterId, 'MFA_DISABLED', true, {
            ip: clientIp
        });

        res.json({
            success: true,
            message: 'MFA disabled successfully'
        });
    } catch (error) {
        console.error('MFA disable error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to disable MFA',
            errorCode: 'MFA_DISABLE_ERROR'
        });
    }
};
