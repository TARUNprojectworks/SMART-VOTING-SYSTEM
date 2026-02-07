const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { createSession } = require('./sessionManager');
const { logAuthEvent } = require('./auditLogger');

// Configure email transporter (Gmail SMTP)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// In-memory OTP storage (in production, use Redis with TTL)
const otpStore = new Map();

// OTP Configuration
const OTP_LENGTH = 6;
const OTP_EXPIRY = 5 * 60 * 1000; // 5 minutes

/**
 * Read user data
 */
const readUserData = () => {
    return JSON.parse(fs.readFileSync('./user.json', 'utf8'));
};

/**
 * Generate random 6-digit OTP
 */
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

/**
 * Send OTP via email using nodemailer
 */
const sendEmailOTP = async (email, otp, name) => {
    // Console log for debugging
    console.log(`
╔═══════════════════════════════════════════════╗
║            EMAIL OTP SENT                      ║
╠═══════════════════════════════════════════════╣
║ To: ${email.padEnd(40)}║
║ Name: ${name.padEnd(38)}║
║ OTP: ${otp.padEnd(38)}║
║ Valid for: 5 minutes                          ║
╚═══════════════════════════════════════════════╝
    `);

    // Send actual email
    try {
        const mailOptions = {
            from: `Smart Voting System <${process.env.EMAIL_USER}>`,
            to: email,
            subject: '🗳️ Your Smart Voting System OTP',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f9; margin: 0; padding: 20px; }
                        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
                        .header h1 { margin: 0; font-size: 24px; }
                        .content { padding: 40px 30px; }
                        .otp-box { background: #f8f9fa; border: 2px dashed #667eea; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
                        .otp-code { font-size: 36px; font-weight: bold; color: #667eea; letter-spacing: 8px; margin: 10px 0; }
                        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px; }
                        .footer { background: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #6c757d; }
                        .button { display: inline-block; padding: 12px 24px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🗳️ Smart Voting System</h1>
                            <p style="margin: 5px 0 0 0;">Secure Digital Democracy</p>
                        </div>
                        <div class="content">
                            <h2 style="color: #333;">Hello ${name},</h2>
                            <p style="color: #555; line-height: 1.6;">Your One-Time Password (OTP) for logging into the Smart Voting System is:</p>
                            
                            <div class="otp-box">
                                <p style="margin: 0; color: #666; font-size: 14px;">Your OTP Code</p>
                                <div class="otp-code">${otp}</div>
                                <p style="margin: 0; color: #666; font-size: 12px;">Valid for 5 minutes</p>
                            </div>
                            
                            <div class="warning">
                                <strong>⚠️ Security Notice:</strong>
                                <ul style="margin: 10px 0; padding-left: 20px;">
                                    <li>Never share this OTP with anyone</li>
                                    <li>Our team will never ask for your OTP</li>
                                    <li>This code expires in 5 minutes</li>
                                    <li>If you didn't request this, please ignore this email</li>
                                </ul>
                            </div>
                            
                            <p style="color: #555;">If you have any questions or concerns, please contact your election administrator.</p>
                        </div>
                        <div class="footer">
                            <p>This is an automated message from Smart Voting System</p>
                            <p>Secured with OTP verification • NIST SP 800-63-2 Compliant</p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log(`✓ Email successfully sent to ${email}`);
        return true;
    } catch (error) {
        console.error('Error sending email:', error);
        throw new Error(`Failed to send email: ${error.message}`);
    }
};

/**
 * Send OTP via SMS (simulated - in production, use Twilio or similar)
 */
const sendSMSOTP = async (phone, otp, name) => {
    console.log(`
╔═══════════════════════════════════════════════╗
║             SMS OTP SENT                       ║
╠═══════════════════════════════════════════════╣
║ To: ${phone.padEnd(40)}║
║ Name: ${name.padEnd(38)}║
║ OTP: ${otp.padEnd(38)}║
║ Valid for: 5 minutes                          ║
╚═══════════════════════════════════════════════╝
    `);

    // In production, replace with actual SMS sending:
    // const twilio = require('twilio');
    // await client.messages.create({
    //     to: phone,
    //     from: process.env.TWILIO_PHONE,
    //     body: `Your Smart Voting System OTP is: ${otp}. Valid for 5 minutes.`
    // });

    return true;
};

/**
 * Request OTP - Verify password and send OTP to email
 * POST /auth/request-otp
 * Body: { voterId, password, email, role }
 */
exports.requestOTP = async (req, res) => {
    const { voterId, password, email, role } = req.body;
    const clientIp = req.ip || 'UNKNOWN';

    // Validate input
    if (!voterId || !password || !email || !role) {
        return res.status(400).json({
            success: false,
            message: 'Voter ID, password, email, and role are required',
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

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({
            success: false,
            message: 'Please enter a valid email address',
            errorCode: 'INVALID_EMAIL'
        });
    }

    try {
        const data = readUserData();
        const user = data.users.find(u => u.voterId === voterId.trim());

        if (!user) {
            logAuthEvent('OTP_REQUEST_FAILED', voterId, false, {
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
            logAuthEvent('OTP_REQUEST_FAILED', voterId, false, {
                ip: clientIp,
                reason: 'Role mismatch',
                expectedRole: user.role,
                providedRole: role
            });

            return res.status(403).json({
                success: false,
                message: `This ID is not registered as ${role === 'voter' ? 'a Voter' :
                    role === 'election_officer' ? 'an Election Officer' :
                        'an Administrator'
                    }.`,
                errorCode: 'ROLE_MISMATCH'
            });
        }

        // Verify password
        const { verifyPassword } = require('./crypto');
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
            logAuthEvent('OTP_REQUEST_FAILED', voterId, false, {
                ip: clientIp,
                reason: 'Invalid password'
            });

            return res.status(401).json({
                success: false,
                message: 'Invalid credentials. Please check your Voter ID and password.',
                errorCode: 'INVALID_CREDENTIALS'
            });
        }

        // Generate OTP
        const otp = generateOTP();
        const otpKey = `${voterId}_email_${email}`;

        // Store OTP with expiry
        otpStore.set(otpKey, {
            otp: otp,
            expiresAt: Date.now() + OTP_EXPIRY,
            attempts: 0,
            maxAttempts: 3
        });

        // Send OTP via email
        try {
            await sendEmailOTP(email, otp, user.name);

            logAuthEvent('OTP_SENT', voterId, true, {
                ip: clientIp,
                method: 'email',
                contact: email.substring(0, 3) + '***' // Partial masking for privacy
            });

            res.json({
                success: true,
                message: 'OTP sent to your email',
                expiresIn: OTP_EXPIRY / 1000 // seconds
            });

        } catch (sendError) {
            console.error('Error sending OTP:', sendError);

            logAuthEvent('OTP_SEND_FAILED', voterId, false, {
                ip: clientIp,
                error: sendError.message
            });

            res.status(500).json({
                success: false,
                message: 'Failed to send OTP via email',
                errorCode: 'OTP_SEND_ERROR'
            });
        }

    } catch (error) {
        console.error('OTP request error:', error);

        res.status(500).json({
            success: false,
            message: 'System error. Please try again later.',
            errorCode: 'SYSTEM_ERROR'
        });
    }
};

/**
 * Verify OTP and login
 * POST /auth/verify-otp
 * Body: { voterId, email, otp }
 */
exports.verifyOTP = async (req, res) => {
    const { voterId, email, otp } = req.body;
    const clientIp = req.ip || 'UNKNOWN';
    const userAgent = req.get('user-agent') || '';

    // Validate input
    if (!voterId || !email || !otp) {
        return res.status(400).json({
            success: false,
            message: 'All fields are required',
            errorCode: 'MISSING_PARAMETERS'
        });
    }

    if (otp.length !== OTP_LENGTH) {
        return res.status(400).json({
            success: false,
            message: 'OTP must be 6 digits',
            errorCode: 'INVALID_OTP_FORMAT'
        });
    }

    const otpKey = `${voterId}_email_${email}`;
    const storedOTP = otpStore.get(otpKey);

    // Check if OTP exists
    if (!storedOTP) {
        logAuthEvent('OTP_VERIFY_FAILED', voterId, false, {
            ip: clientIp,
            reason: 'No OTP found'
        });

        return res.status(400).json({
            success: false,
            message: 'No OTP found. Please request a new one.',
            errorCode: 'OTP_NOT_FOUND'
        });
    }

    // Check if OTP expired
    if (Date.now() > storedOTP.expiresAt) {
        otpStore.delete(otpKey);

        logAuthEvent('OTP_VERIFY_FAILED', voterId, false, {
            ip: clientIp,
            reason: 'OTP expired'
        });

        return res.status(400).json({
            success: false,
            message: 'OTP has expired. Please request a new one.',
            errorCode: 'OTP_EXPIRED'
        });
    }

    // Check max attempts
    if (storedOTP.attempts >= storedOTP.maxAttempts) {
        otpStore.delete(otpKey);

        logAuthEvent('OTP_VERIFY_FAILED', voterId, false, {
            ip: clientIp,
            reason: 'Max attempts exceeded'
        });

        return res.status(429).json({
            success: false,
            message: 'Too many failed attempts. Please request a new OTP.',
            errorCode: 'MAX_ATTEMPTS_EXCEEDED'
        });
    }

    // Verify OTP
    if (storedOTP.otp !== otp) {
        storedOTP.attempts++;

        logAuthEvent('OTP_VERIFY_FAILED', voterId, false, {
            ip: clientIp,
            reason: 'Invalid OTP',
            attemptsRemaining: storedOTP.maxAttempts - storedOTP.attempts
        });

        return res.status(401).json({
            success: false,
            message: `Invalid OTP. ${storedOTP.maxAttempts - storedOTP.attempts} attempts remaining.`,
            errorCode: 'INVALID_OTP'
        });
    }

    // OTP is valid - proceed with login
    try {
        const data = readUserData();
        const user = data.users.find(u => u.voterId === voterId.trim());

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found',
                errorCode: 'USER_NOT_FOUND'
            });
        }

        // Clear OTP after successful verification
        otpStore.delete(otpKey);

        // Update last login
        user.lastLogin = new Date().toISOString();
        fs.writeFileSync('./user.json', JSON.stringify(data, null, 4));

        // Create session
        const sessionData = createSession(user.voterId, user.role, {
            ip: clientIp,
            userAgent: userAgent
        });

        logAuthEvent('OTP_LOGIN_SUCCESS', voterId, true, {
            ip: clientIp,
            method: 'email',
            sessionToken: sessionData.sessionToken
        });

        res.json({
            success: true,
            message: 'Login successful',
            sessionToken: sessionData.sessionToken,
            sessionSignature: sessionData.signature,
            expiresAt: sessionData.expiresAt,
            user: {
                voterId: user.voterId,
                name: user.name,
                role: user.role,
                hasVoted: user.voted || false,
                canVote: user.role === 'voter' && !user.voted
            }
        });

    } catch (error) {
        console.error('OTP verification error:', error);

        res.status(500).json({
            success: false,
            message: 'System error. Please try again later.',
            errorCode: 'SYSTEM_ERROR'
        });
    }
};

/**
 * Clean expired OTPs periodically
 */
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, value] of otpStore.entries()) {
        if (now > value.expiresAt) {
            otpStore.delete(key);
            cleaned++;
        }
    }

    if (cleaned > 0) {
        console.log(`[OTP Cleanup] Removed ${cleaned} expired OTPs`);
    }
}, 60 * 1000); // Run every minute
