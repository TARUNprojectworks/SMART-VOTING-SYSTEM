const fs = require("fs");
const crypto = require("crypto");
const { logAuditEvent } = require("./auditLogger");

const ELECTIONS_FILE = "./elections.json";

// Helper function to read elections data
function readElections() {
    try {
        if (!fs.existsSync(ELECTIONS_FILE)) {
            fs.writeFileSync(ELECTIONS_FILE, JSON.stringify({ elections: [] }, null, 4));
        }
        const data = fs.readFileSync(ELECTIONS_FILE, "utf8");
        return JSON.parse(data);
    } catch (error) {
        console.error("Error reading elections file:", error);
        return { elections: [] };
    }
}

// Helper function to write elections data
function writeElections(data) {
    try {
        fs.writeFileSync(ELECTIONS_FILE, JSON.stringify(data, null, 4));
        return true;
    } catch (error) {
        console.error("Error writing elections file:", error);
        return false;
    }
}

// Generate unique election ID
function generateElectionId() {
    const timestamp = Date.now();
    const random = crypto.randomBytes(4).toString("hex");
    return `ELECT-${timestamp}-${random}`;
}

// Validate election dates
function validateElectionDates(startDate, endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);
    const now = new Date();

    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
        return { valid: false, message: "Invalid date format" };
    }

    if (end <= start) {
        return { valid: false, message: "End date must be after start date" };
    }

    if (start < now && end < now) {
        return { valid: false, message: "Both start and end dates cannot be in the past" };
    }

    return { valid: true };
}

// Validate candidate data
function validateCandidates(candidates) {
    if (!Array.isArray(candidates) || candidates.length < 2) {
        return { valid: false, message: "At least 2 candidates are required" };
    }

    const names = new Set();
    for (const candidate of candidates) {
        if (!candidate.name || !candidate.name.trim()) {
            return { valid: false, message: "All candidates must have a name" };
        }

        if (names.has(candidate.name.toLowerCase())) {
            return { valid: false, message: `Duplicate candidate name: ${candidate.name}` };
        }

        names.add(candidate.name.toLowerCase());
    }

    return { valid: true };
}

// Create a new election
exports.createElection = (electionData, officerId, clientIp = "UNKNOWN") => {
    try {
        // Validate required fields
        if (!electionData.title || !electionData.title.trim()) {
            return { success: false, message: "Election title is required", errorCode: "VALIDATION_ERROR" };
        }

        if (!electionData.startDate || !electionData.endDate) {
            return { success: false, message: "Start and end dates are required", errorCode: "VALIDATION_ERROR" };
        }

        // Validate dates
        const dateValidation = validateElectionDates(electionData.startDate, electionData.endDate);
        if (!dateValidation.valid) {
            return { success: false, message: dateValidation.message, errorCode: "INVALID_DATES" };
        }

        // Validate candidates
        const candidateValidation = validateCandidates(electionData.candidates || []);
        if (!candidateValidation.valid) {
            return { success: false, message: candidateValidation.message, errorCode: "INVALID_CANDIDATES" };
        }

        // Generate unique ID for election
        const electionId = generateElectionId();

        // Process candidates - add unique IDs
        const processedCandidates = (electionData.candidates || []).map((candidate, index) => ({
            id: `CAND-${electionId}-${index + 1}`,
            name: candidate.name.trim(),
            party: candidate.party?.trim() || "",
            description: candidate.description?.trim() || "",
            imageUrl: candidate.imageUrl || null
        }));

        // Create election object
        const election = {
            electionId,
            title: electionData.title.trim(),
            description: electionData.description?.trim() || "",
            candidates: processedCandidates,
            status: electionData.status === "active" ? "active" : "draft",
            startDate: electionData.startDate,
            endDate: electionData.endDate,
            createdBy: officerId,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            settings: {
                allowMultipleVotes: false,
                requireMFA: electionData.requireMFA || false,
                ...electionData.settings
            },
            totalVotes: 0,
            results: {}
        };

        // Initialize results structure
        processedCandidates.forEach(candidate => {
            election.results[candidate.id] = 0;
        });

        // Read existing elections and add new one
        const data = readElections();
        data.elections.push(election);

        // Save to file
        if (!writeElections(data)) {
            return { success: false, message: "Failed to save election", errorCode: "SYSTEM_ERROR" };
        }

        // Audit log
        logAuditEvent("ELECTION_CREATE", officerId, true, {
            electionId,
            title: election.title,
            status: election.status,
            ip: clientIp,
            candidateCount: processedCandidates.length
        });

        return {
            success: true,
            message: "Election created successfully",
            election: {
                electionId: election.electionId,
                title: election.title,
                status: election.status
            }
        };
    } catch (error) {
        console.error("Error creating election:", error);
        return { success: false, message: "Failed to create election", errorCode: "SYSTEM_ERROR" };
    }
};

// Get all elections with optional filtering
exports.getElections = (filters = {}) => {
    try {
        const data = readElections();
        let elections = data.elections;

        // Filter by status
        if (filters.status) {
            elections = elections.filter(e => e.status === filters.status);
        }

        // Filter by date range
        if (filters.activeOnly) {
            const now = new Date();
            elections = elections.filter(e => {
                const start = new Date(e.startDate);
                const end = new Date(e.endDate);
                return start <= now && now <= end && e.status === "active";
            });
        }

        return {
            success: true,
            elections: elections.map(e => ({
                electionId: e.electionId,
                title: e.title,
                description: e.description,
                status: e.status,
                startDate: e.startDate,
                endDate: e.endDate,
                candidateCount: e.candidates.length,
                totalVotes: e.totalVotes,
                createdBy: e.createdBy,
                createdAt: e.createdAt
            }))
        };
    } catch (error) {
        console.error("Error fetching elections:", error);
        return { success: false, message: "Failed to fetch elections", errorCode: "SYSTEM_ERROR" };
    }
};

// Get specific election by ID
exports.getElectionById = (electionId) => {
    try {
        const data = readElections();
        const election = data.elections.find(e => e.electionId === electionId);

        if (!election) {
            return { success: false, message: "Election not found", errorCode: "NOT_FOUND" };
        }

        return { success: true, election };
    } catch (error) {
        console.error("Error fetching election:", error);
        return { success: false, message: "Failed to fetch election", errorCode: "SYSTEM_ERROR" };
    }
};

// Get currently active election
exports.getActiveElection = () => {
    try {
        const data = readElections();
        const now = new Date();

        // Find election that is active and within date range
        const activeElection = data.elections.find(e => {
            const start = new Date(e.startDate);
            const end = new Date(e.endDate);
            return e.status === "active" && start <= now && now <= end;
        });

        if (!activeElection) {
            return { success: false, message: "No active election found", errorCode: "NO_ACTIVE_ELECTION" };
        }

        return { success: true, election: activeElection };
    } catch (error) {
        console.error("Error fetching active election:", error);
        return { success: false, message: "Failed to fetch active election", errorCode: "SYSTEM_ERROR" };
    }
};

// Update election status
exports.updateElectionStatus = (electionId, newStatus, officerId, clientIp = "UNKNOWN") => {
    try {
        const validStatuses = ["draft", "active", "completed", "cancelled"];
        if (!validStatuses.includes(newStatus)) {
            return { success: false, message: "Invalid status", errorCode: "INVALID_STATUS" };
        }

        const data = readElections();
        const election = data.elections.find(e => e.electionId === electionId);

        if (!election) {
            return { success: false, message: "Election not found", errorCode: "NOT_FOUND" };
        }

        const oldStatus = election.status;

        // Validate status transitions
        if (oldStatus === "completed" || oldStatus === "cancelled") {
            return { success: false, message: "Cannot modify completed or cancelled elections", errorCode: "INVALID_TRANSITION" };
        }

        if (newStatus === "active") {
            // Validate dates when activating
            const dateValidation = validateElectionDates(election.startDate, election.endDate);
            if (!dateValidation.valid) {
                return { success: false, message: dateValidation.message, errorCode: "INVALID_DATES" };
            }

            // Check if another election is already active
            const activeExists = data.elections.some(e =>
                e.status === "active" && e.electionId !== electionId
            );
            if (activeExists) {
                return { success: false, message: "Another election is already active", errorCode: "ACTIVE_ELECTION_EXISTS" };
            }
        }

        // Update status
        election.status = newStatus;
        election.updatedAt = new Date().toISOString();

        if (newStatus === "completed") {
            election.completedAt = new Date().toISOString();
        }

        // Save changes
        if (!writeElections(data)) {
            return { success: false, message: "Failed to update election", errorCode: "SYSTEM_ERROR" };
        }

        // Audit log
        logAuditEvent("ELECTION_STATUS_CHANGE", officerId, true, {
            electionId,
            oldStatus,
            newStatus,
            ip: clientIp
        });

        return {
            success: true,
            message: `Election status updated to ${newStatus}`,
            election: {
                electionId: election.electionId,
                status: election.status
            }
        };
    } catch (error) {
        console.error("Error updating election status:", error);
        return { success: false, message: "Failed to update election status", errorCode: "SYSTEM_ERROR" };
    }
};

// Delete election (only drafts)
exports.deleteElection = (electionId, officerId, clientIp = "UNKNOWN") => {
    try {
        const data = readElections();
        const electionIndex = data.elections.findIndex(e => e.electionId === electionId);

        if (electionIndex === -1) {
            return { success: false, message: "Election not found", errorCode: "NOT_FOUND" };
        }

        const election = data.elections[electionIndex];

        // Only allow deletion of draft elections
        if (election.status !== "draft") {
            return { success: false, message: "Only draft elections can be deleted", errorCode: "INVALID_STATUS" };
        }

        // Remove election
        data.elections.splice(electionIndex, 1);

        // Save changes
        if (!writeElections(data)) {
            return { success: false, message: "Failed to delete election", errorCode: "SYSTEM_ERROR" };
        }

        // Audit log
        logAuditEvent("ELECTION_DELETE", officerId, true, {
            electionId,
            title: election.title,
            ip: clientIp
        });

        return { success: true, message: "Election deleted successfully" };
    } catch (error) {
        console.error("Error deleting election:", error);
        return { success: false, message: "Failed to delete election", errorCode: "SYSTEM_ERROR" };
    }
};

// Record vote for an election
exports.recordVote = (electionId, candidateId) => {
    try {
        const data = readElections();
        const election = data.elections.find(e => e.electionId === electionId);

        if (!election) {
            return { success: false, message: "Election not found", errorCode: "NOT_FOUND" };
        }

        // Verify candidate exists
        const candidate = election.candidates.find(c => c.id === candidateId);
        if (!candidate) {
            return { success: false, message: "Candidate not found", errorCode: "INVALID_CANDIDATE" };
        }

        // Increment vote count
        election.results[candidateId] = (election.results[candidateId] || 0) + 1;
        election.totalVotes = (election.totalVotes || 0) + 1;
        election.updatedAt = new Date().toISOString();

        // Save changes
        if (!writeElections(data)) {
            return { success: false, message: "Failed to record vote", errorCode: "SYSTEM_ERROR" };
        }

        return { success: true, candidate: candidate.name };
    } catch (error) {
        console.error("Error recording vote:", error);
        return { success: false, message: "Failed to record vote", errorCode: "SYSTEM_ERROR" };
    }
};
