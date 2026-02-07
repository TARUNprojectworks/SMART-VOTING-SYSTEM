import { useState, useEffect } from "react";
import Login from "./login";
import Results from "./Results";
import ElectionOfficer from "./ElectionOfficer";
import AdminDashboard from "./AdminDashboard";
import { vote, logout, getActiveElection } from "./services";

function App() {
    const [user, setUser] = useState(null);
    const [message, setMessage] = useState("");
    const [activeElection, setActiveElection] = useState(null);
    const [loadingElection, setLoadingElection] = useState(false);

    // Check for existing session on mount
    useEffect(() => {
        const sessionToken = localStorage.getItem('sessionToken');
        const userData = localStorage.getItem('userData');

        if (sessionToken && userData) {
            try {
                setUser(JSON.parse(userData));
            } catch (e) {
                localStorage.clear();
            }
        }
    }, []);

    // Fetch active election when user logs in as voter
    useEffect(() => {
        if (user && user.role === 'voter') {
            fetchActiveElection();
        }
    }, [user]);

    const fetchActiveElection = async () => {
        setLoadingElection(true);
        const result = await getActiveElection();
        if (result.success) {
            setActiveElection(result.election);
        } else {
            setActiveElection(null);
        }
        setLoadingElection(false);
    };

    const castVote = async (candidateId, candidateName) => {
        if (!activeElection) {
            setMessage("✗ No active election found");
            return;
        }

        const res = await vote(user.voterId, candidateId, activeElection.electionId);

        if (res.success) {
            setMessage(`✓ ${res.message}`);
            // Update user's voted status for this election
            const updatedUser = { ...user, hasVoted: true, canVote: false };
            setUser(updatedUser);
            localStorage.setItem('userData', JSON.stringify(updatedUser));
        } else {
            setMessage(`✗ ${res.message}`);

            // If session expired, logout
            if (res.errorCode === "INVALID_SESSION") {
                setTimeout(() => handleLogout(), 2000);
            }
        }
    };

    const handleLogout = async () => {
        await logout();
        setUser(null);
        setMessage("");
        setActiveElection(null);
    };

    const hasUserVotedInElection = () => {
        if (!user || !activeElection) return false;
        return user.electionVotes && user.electionVotes[activeElection.electionId]?.voted;
    };

    if (!user) return <Login setUser={setUser} />;

    return (
        <div className="voting-container">
            <div className="header-section">
                <div className="welcome-message">
                    <div>
                        <h2>Welcome, {user.name || user.voterId}!</h2>
                    </div>
                    <div className="user-info">
                        <span className="user-badge">
                            {user.role === 'admin' ? '🔐 Administrator' : user.role === 'election_officer' ? '👔 Election Officer' : '🗳️ Voter'}
                        </span>
                        <button onClick={handleLogout} className="logout-button">
                            Logout
                        </button>
                    </div>
                </div>
            </div>

            {/* Voter Dashboard */}
            {user.role === 'voter' && (
                <div className="voting-section">
                    <h3>Cast Your Vote</h3>

                    {message && (
                        <div className={message.startsWith('✓') ? 'success-message' : 'error-message'}>
                            {message}
                        </div>
                    )}

                    {loadingElection ? (
                        <div className="loading-message">Loading active election...</div>
                    ) : !activeElection ? (
                        <div className="no-election-message">
                            <div className="placeholder-icon">📅</div>
                            <p>No active election at the moment</p>
                            <p className="placeholder-details">
                                Please check back later when voting begins.
                            </p>
                        </div>
                    ) : hasUserVotedInElection() ? (
                        <div className="voted-message">
                            ✓ You have already cast your vote in this election. Thank you for participating!
                        </div>
                    ) : (
                        <div className="active-election-container">
                            <div className="election-info">
                                <h4 className="election-title">{activeElection.title}</h4>
                                {activeElection.description && (
                                    <p className="election-description">{activeElection.description}</p>
                                )}
                                <div className="election-deadline">
                                    Voting ends: {new Date(activeElection.endDate).toLocaleString('en-IN', {
                                        year: 'numeric',
                                        month: 'long',
                                        day: 'numeric',
                                        hour: '2-digit',
                                        minute: '2-digit'
                                    })}
                                </div>
                            </div>

                            <div className="candidates-grid">
                                {activeElection.candidates.map(candidate => (
                                    <div key={candidate.id} className="candidate-card-voting">
                                        <div className="candidate-card-content">
                                            <div className="candidate-name">{candidate.name}</div>
                                            {candidate.party && (
                                                <div className="candidate-party">{candidate.party}</div>
                                            )}
                                            {candidate.description && (
                                                <div className="candidate-description">{candidate.description}</div>
                                            )}
                                        </div>
                                        <button
                                            className="vote-button"
                                            onClick={() => castVote(candidate.id, candidate.name)}
                                        >
                                            🗳️ Vote
                                        </button>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* Admin Dashboard */}
            {user.role === 'admin' && (
                <AdminDashboard user={user} />
            )}

            {/* Election Officer Dashboard */}
            {user.role === 'election_officer' && (
                <ElectionOfficer user={user} />
            )}

            {/* Results Section - Visible to both voters and officers */}
            <Results />
        </div>
    );
}

export default App;
