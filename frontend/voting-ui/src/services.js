const API = "http://localhost:5000";

export const login = async (voterId, password, mfaToken = null) => {
    try {
        const res = await fetch(`${API}/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ voterId, password, mfaToken })
        });
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};

export const vote = async (voterId, candidate, electionId = null) => {
    const sessionToken = localStorage.getItem('sessionToken');
    const sessionSignature = localStorage.getItem('sessionSignature');

    try {
        const res = await fetch(`${API}/vote`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ voterId, candidate, electionId, sessionToken, sessionSignature })
        });
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};

export const logout = async () => {
    const sessionToken = localStorage.getItem('sessionToken');

    try {
        await fetch(`${API}/logout`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sessionToken })
        });
    } catch (error) {
        console.error("Logout error:", error);
    } finally {
        localStorage.removeItem('sessionToken');
        localStorage.removeItem('sessionSignature');
        localStorage.removeItem('userData');
    }
};

export const results = async () => {
    try {
        const res = await fetch(`${API}/results`);
        const data = await res.json();
        return data.success ? data.results : {};
    } catch (error) {
        return {};
    }
};

// Election Management APIs
export const createElection = async (electionData) => {
    const sessionToken = localStorage.getItem('sessionToken');
    const sessionSignature = localStorage.getItem('sessionSignature');

    try {
        const res = await fetch(`${API}/elections/create`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sessionToken, sessionSignature, electionData })
        });
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};

export const getElections = async (status = null) => {
    try {
        const url = status ? `${API}/elections?status=${status}` : `${API}/elections`;
        const res = await fetch(url);
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};

export const getActiveElection = async () => {
    try {
        const res = await fetch(`${API}/elections/active`);
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error", errorCode: "NO_ACTIVE_ELECTION" };
    }
};

export const getElectionById = async (electionId) => {
    try {
        const res = await fetch(`${API}/elections/${electionId}`);
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};

export const updateElectionStatus = async (electionId, status) => {
    const sessionToken = localStorage.getItem('sessionToken');
    const sessionSignature = localStorage.getItem('sessionSignature');

    try {
        const res = await fetch(`${API}/elections/${electionId}/status`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sessionToken, sessionSignature, status })
        });
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};

export const deleteElection = async (electionId) => {
    const sessionToken = localStorage.getItem('sessionToken');
    const sessionSignature = localStorage.getItem('sessionSignature');

    try {
        const res = await fetch(`${API}/elections/${electionId}`, {
            method: "DELETE",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sessionToken, sessionSignature })
        });
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};

export const setupMFA = async () => {
    const sessionToken = localStorage.getItem('sessionToken');
    const sessionSignature = localStorage.getItem('sessionSignature');

    try {
        const res = await fetch(`${API}/mfa/setup`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sessionToken, sessionSignature })
        });
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};

export const verifyMFASetup = async (secret, token) => {
    const sessionToken = localStorage.getItem('sessionToken');
    const sessionSignature = localStorage.getItem('sessionSignature');

    try {
        const res = await fetch(`${API}/mfa/verify-setup`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sessionToken, sessionSignature, secret, token })
        });
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};

export const disableMFA = async (password) => {
    const sessionToken = localStorage.getItem('sessionToken');
    const sessionSignature = localStorage.getItem('sessionSignature');

    try {
        const res = await fetch(`${API}/mfa/disable`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sessionToken, sessionSignature, password })
        });
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};

// Verify credentials (ID + password) before requesting OTP
export const verifyCredentials = async (voterId, password, role) => {
    try {
        const res = await fetch(`${API}/auth/verify-credentials`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ voterId, password, role })
        });
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};

// OTP-based authentication with password verification
export const requestOTP = async (voterId, password, email, role) => {
    try {
        const res = await fetch(`${API}/auth/request-otp`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ voterId, password, email, role })
        });
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};

export const verifyOTPLogin = async (voterId, email, otp) => {
    try {
        const res = await fetch(`${API}/auth/verify-otp`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ voterId, email, otp })
        });
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};

// User Registration APIs
export const registerUser = async (name, email, password) => {
    try {
        const res = await fetch(`${API}/auth/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, email, password })
        });
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};

export const getPendingUsers = async () => {
    const sessionToken = localStorage.getItem('sessionToken');
    const sessionSignature = localStorage.getItem('sessionSignature');

    try {
        const res = await fetch(`${API}/users/pending?sessionToken=${sessionToken}&sessionSignature=${sessionSignature}`);
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};

export const approveUser = async (voterId) => {
    const sessionToken = localStorage.getItem('sessionToken');
    const sessionSignature = localStorage.getItem('sessionSignature');

    try {
        const res = await fetch(`${API}/users/approve`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ voterId, sessionToken, sessionSignature })
        });
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};

export const rejectUser = async (voterId) => {
    const sessionToken = localStorage.getItem('sessionToken');
    const sessionSignature = localStorage.getItem('sessionSignature');

    try {
        const res = await fetch(`${API}/users/reject`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ voterId, sessionToken, sessionSignature })
        });
        return await res.json();
    } catch (error) {
        return { success: false, message: "Network error" };
    }
};


