const fs = require("fs");
const { validateSession } = require("./sessionManager");
const { logVoteEvent, logAccessControl } = require("./auditLogger");
const { checkPermission, PERMISSIONS } = require("./accessControlMatrix");

exports.vote = (req, res) => {
    const { voterId, candidate, electionId, sessionToken, sessionSignature } = req.body;
    const clientIp = req.ip || req.connection.remoteAddress || 'UNKNOWN';
    const userAgent = req.get('user-agent') || '';

    // Validate session with integrity check
    const sessionValidation = validateSession(sessionToken, sessionSignature, {
        ip: clientIp,
        userAgent: userAgent
    });

    if (!sessionValidation.valid) {
        logAccessControl(voterId, 'VOTE', false, {
            ip: clientIp,
            reason: sessionValidation.message
        });

        return res.status(401).json({
            success: false,
            message: "Invalid or expired session. Please login again.",
            errorCode: sessionValidation.errorCode || "INVALID_SESSION"
        });
    }

    // Verify session belongs to the voter
    if (sessionValidation.session.voterId !== voterId) {
        logAccessControl(voterId, 'VOTE', false, {
            ip: clientIp,
            reason: 'Session mismatch'
        });

        return res.status(403).json({
            success: false,
            message: "Unauthorized access.",
            errorCode: "UNAUTHORIZED"
        });
    }

    const data = JSON.parse(fs.readFileSync("./user.json"));
    const user = data.users.find(u => u.voterId === voterId);

    if (!user) {
        logAccessControl(voterId, 'VOTE', false, {
            ip: clientIp,
            reason: 'User not found'
        });

        return res.status(400).json({
            success: false,
            message: "User not found",
            errorCode: "USER_NOT_FOUND"
        });
    }

    // Check if user has permission to vote
    if (!checkPermission(user.role, PERMISSIONS.VOTE)) {
        logAccessControl(voterId, 'VOTE', false, {
            ip: clientIp,
            reason: 'Insufficient permissions',
            role: user.role
        });

        return res.status(403).json({
            success: false,
            message: "You do not have permission to vote.",
            errorCode: "INSUFFICIENT_PERMISSIONS"
        });
    }

    // Check if user is a voter (additional check beyond permissions)
    if (user.role !== "voter") {
        logAccessControl(voterId, 'VOTE', false, {
            ip: clientIp,
            reason: 'Invalid role',
            role: user.role
        });

        return res.status(403).json({
            success: false,
            message: "Only voters can cast votes.",
            errorCode: "INVALID_ROLE"
        });
    }

    // If electionId is provided, use election-based voting
    if (electionId) {
        const { getElectionById, recordVote } = require('./electionManager');
        const electionResult = getElectionById(electionId);

        if (!electionResult.success) {
            logVoteEvent(voterId, false, {
                ip: clientIp,
                reason: 'Election not found',
                electionId
            });

            return res.status(404).json({
                success: false,
                message: "Election not found",
                errorCode: "ELECTION_NOT_FOUND"
            });
        }

        const election = electionResult.election;

        // Check if election is active
        if (election.status !== 'active') {
            logVoteEvent(voterId, false, {
                ip: clientIp,
                reason: 'Election not active',
                electionId,
                status: election.status
            });

            return res.status(403).json({
                success: false,
                message: `Election is ${election.status}. Voting is only allowed for active elections.`,
                errorCode: "ELECTION_NOT_ACTIVE"
            });
        }

        // Check if within voting window
        const now = new Date();
        const startDate = new Date(election.startDate);
        const endDate = new Date(election.endDate);

        if (now < startDate) {
            logVoteEvent(voterId, false, {
                ip: clientIp,
                reason: 'Election not started',
                electionId
            });

            return res.status(403).json({
                success: false,
                message: "Voting has not started yet.",
                errorCode: "ELECTION_NOT_STARTED"
            });
        }

        if (now > endDate) {
            logVoteEvent(voterId, false, {
                ip: clientIp,
                reason: 'Election ended',
                electionId
            });

            return res.status(403).json({
                success: false,
                message: "Voting has ended.",
                errorCode: "ELECTION_ENDED"
            });
        }

        // Initialize electionVotes if not exists
        if (!user.electionVotes) {
            user.electionVotes = {};
        }

        // Check if user has already voted in this election
        if (user.electionVotes[electionId]?.voted) {
            logVoteEvent(voterId, false, {
                ip: clientIp,
                reason: 'Duplicate vote attempt in election',
                electionId,
                votedAt: user.electionVotes[electionId].votedAt
            });

            return res.status(403).json({
                success: false,
                message: "You have already voted in this election.",
                errorCode: "ALREADY_VOTED",
                votedAt: user.electionVotes[electionId].votedAt
            });
        }

        // Verify candidate exists in election and get candidateId
        const selectedCandidate = election.candidates.find(c =>
            c.id === candidate || c.name === candidate
        );

        if (!selectedCandidate) {
            logVoteEvent(voterId, false, {
                ip: clientIp,
                reason: 'Invalid candidate',
                electionId,
                candidate
            });

            return res.status(400).json({
                success: false,
                message: "Invalid candidate selection.",
                errorCode: "INVALID_CANDIDATE"
            });
        }

        // Record vote in election
        const voteResult = recordVote(electionId, selectedCandidate.id);
        if (!voteResult.success) {
            return res.status(500).json(voteResult);
        }

        // Record vote in user data
        user.electionVotes[electionId] = {
            voted: true,
            candidateId: selectedCandidate.id,
            candidateName: selectedCandidate.name,
            votedAt: new Date().toISOString()
        };
        user.voted = true; // Keep for backward compatibility

        fs.writeFileSync("./user.json", JSON.stringify(data, null, 4));

        logVoteEvent(voterId, true, {
            ip: clientIp,
            electionId,
            votedAt: user.electionVotes[electionId].votedAt
        });

        return res.json({
            success: true,
            message: "Vote recorded successfully",
            votedAt: user.electionVotes[electionId].votedAt
        });
    }

    // Legacy voting (backward compatibility - no election)
    // Duplicate vote prevention
    if (user.voted) {
        logVoteEvent(voterId, false, {
            ip: clientIp,
            reason: 'Duplicate vote attempt',
            votedAt: user.votedAt
        });

        return res.status(403).json({
            success: false,
            message: "You have already cast your vote. Duplicate voting is not allowed.",
            errorCode: "ALREADY_VOTED",
            votedAt: user.votedAt
        });
    }

    // Record vote
    user.vote = candidate;
    user.voted = true;
    user.votedAt = new Date().toISOString();

    fs.writeFileSync("./user.json", JSON.stringify(data, null, 4));

    logVoteEvent(voterId, true, {
        ip: clientIp,
        votedAt: user.votedAt,
        candidate: candidate // In production, you might want to anonymize this
    });

    res.json({
        success: true,
        message: "Vote recorded successfully",
        votedAt: user.votedAt
    });
};

