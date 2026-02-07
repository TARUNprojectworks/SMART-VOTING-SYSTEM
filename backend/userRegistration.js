const fs = require('fs');
const { hashPassword } = require('./crypto');
const { logAuthEvent } = require('./auditLogger');

// Helper functions
const readUserData = () => {
    return JSON.parse(fs.readFileSync('./user.json', 'utf-8'));
};

const writeUserData = (data) => {
    fs.writeFileSync('./user.json', JSON.stringify(data, null, 4));
};

/**
 * Generate unique Voter ID
 * @returns {string} - New voter ID (e.g., V2001, V2002)
 */
const generateVoterId = () => {
    const data = readUserData();
    const voterIds = data.users
        .filter(u => u.voterId.startsWith('V'))
        .map(u => parseInt(u.voterId.substring(1)))
        .filter(id => !isNaN(id));

    const maxId = voterIds.length > 0 ? Math.max(...voterIds) : 1000;
    return `V${maxId + 1}`;
};

/**
 * Register new user (voter only)
 * POST /auth/register
 * Body: { name, email, password }
 */
exports.registerNewUser = async (req, res) => {
    const { name, email, password } = req.body;
    const clientIp = req.ip || 'UNKNOWN';

    // Validate input
    if (!name || !email || !password) {
        return res.status(400).json({
            success: false,
            message: 'Name, email, and password are required',
            errorCode: 'MISSING_FIELDS'
        });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid email address',
            errorCode: 'INVALID_EMAIL'
        });
    }

    // Validate password strength
    if (password.length < 8) {
        return res.status(400).json({
            success: false,
            message: 'Password must be at least 8 characters long',
            errorCode: 'WEAK_PASSWORD'
        });
    }

    try {
        const data = readUserData();

        // Check if email already exists
        const existingUser = data.users.find(u => u.email === email.toLowerCase());
        if (existingUser) {
            logAuthEvent('REGISTRATION_FAILED', email, false, {
                ip: clientIp,
                reason: 'Email already registered'
            });

            return res.status(409).json({
                success: false,
                message: 'Email already registered',
                errorCode: 'EMAIL_EXISTS'
            });
        }

        // Generate voter ID
        const voterId = generateVoterId();

        // Hash password
        const passwordHash = await hashPassword(password);

        // Create new user object
        const newUser = {
            voterId: voterId,
            name: name.trim(),
            email: email.toLowerCase(),
            role: 'voter',
            registered: true,
            status: 'pending', // Pending approval
            voted: false,
            vote: null,
            lastLogin: null,
            passwordHash: passwordHash,
            mfaEnabled: false,
            mfaSecret: null,
            failedLoginAttempts: 0,
            accountLockedUntil: null,
            lastPasswordChange: null,
            authenticationLevel: 'LOA-2',
            votedAt: null,
            registeredAt: new Date().toISOString(),
            approvedBy: null,
            approvedAt: null
        };

        // Add user to data
        data.users.push(newUser);
        writeUserData(data);

        logAuthEvent('USER_REGISTERED', voterId, true, {
            ip: clientIp,
            email: email.toLowerCase(),
            name: name.trim()
        });

        return res.status(201).json({
            success: true,
            message: 'Registration successful! Your account is pending approval from an Election Officer.',
            voterId: voterId
        });

    } catch (error) {
        console.error('Registration error:', error);
        logAuthEvent('REGISTRATION_ERROR', email, false, {
            ip: clientIp,
            error: error.message
        });

        return res.status(500).json({
            success: false,
            message: 'Server error during registration',
            errorCode: 'SERVER_ERROR'
        });
    }
};

/**
 * Get all pending users (Election Officer only)
 * GET /users/pending
 */
exports.getPendingUsers = (req, res) => {
    try {
        const data = readUserData();

        const pendingUsers = data.users
            .filter(u => u.status === 'pending')
            .map(u => ({
                voterId: u.voterId,
                name: u.name,
                email: u.email,
                registeredAt: u.registeredAt,
                role: u.role
            }));

        return res.json({
            success: true,
            users: pendingUsers,
            count: pendingUsers.length
        });
    } catch (error) {
        console.error('Error fetching pending users:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to fetch pending users',
            errorCode: 'SERVER_ERROR'
        });
    }
};

/**
 * Approve user (Election Officer only)
 * POST /users/approve
 * Body: { voterId }
 */
exports.approveUser = (req, res) => {
    const { voterId } = req.body;
    const officerId = req.officerId; // Set by auth middleware
    const clientIp = req.ip || 'UNKNOWN';

    if (!voterId) {
        return res.status(400).json({
            success: false,
            message: 'Voter ID is required',
            errorCode: 'MISSING_VOTER_ID'
        });
    }

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

        if (user.status === 'approved') {
            return res.status(400).json({
                success: false,
                message: 'User is already approved',
                errorCode: 'ALREADY_APPROVED'
            });
        }

        // Approve user
        user.status = 'approved';
        user.approvedBy = officerId;
        user.approvedAt = new Date().toISOString();

        writeUserData(data);

        logAuthEvent('USER_APPROVED', voterId, true, {
            ip: clientIp,
            approvedBy: officerId,
            userName: user.name
        });

        return res.json({
            success: true,
            message: `User ${user.name} approved successfully`
        });

    } catch (error) {
        console.error('Error approving user:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to approve user',
            errorCode: 'SERVER_ERROR'
        });
    }
};

/**
 * Reject user (Election Officer only)
 * POST /users/reject
 * Body: { voterId }
 */
exports.rejectUser = (req, res) => {
    const { voterId } = req.body;
    const officerId = req.officerId; // Set by auth middleware
    const clientIp = req.ip || 'UNKNOWN';

    if (!voterId) {
        return res.status(400).json({
            success: false,
            message: 'Voter ID is required',
            errorCode: 'MISSING_VOTER_ID'
        });
    }

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

        // Reject user
        user.status = 'rejected';
        user.approvedBy = officerId;
        user.approvedAt = new Date().toISOString();

        writeUserData(data);

        logAuthEvent('USER_REJECTED', voterId, true, {
            ip: clientIp,
            rejectedBy: officerId,
            userName: user.name
        });

        return res.json({
            success: true,
            message: `User ${user.name} rejected`
        });

    } catch (error) {
        console.error('Error rejecting user:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to reject user',
            errorCode: 'SERVER_ERROR'
        });
    }
};
