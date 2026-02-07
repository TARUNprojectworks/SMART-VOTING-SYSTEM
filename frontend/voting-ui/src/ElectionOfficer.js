import { useState, useEffect } from "react";
import { results } from "./services";
import CreateVoting from "./CreateVoting";
import ManageElections from "./ManageElections";
import UserManagement from "./UserManagement";

export default function ElectionOfficer({ user }) {
    const [activeTab, setActiveTab] = useState("count");
    const [voteData, setVoteData] = useState({});
    const [loading, setLoading] = useState(true);

    const fetchResults = async () => {
        setLoading(true);
        const res = await results();
        setVoteData(res);
        setLoading(false);
    };

    useEffect(() => {
        fetchResults();
        // Refresh results every 5 seconds
        const interval = setInterval(fetchResults, 5000);
        return () => clearInterval(interval);
    }, []);

    const handleElectionChange = () => {
        // Refresh when elections are created/updated
        fetchResults();
    };

    return (
        <div className="officer-dashboard">
            <div className="dashboard-header">
                <h2>Election Officer Dashboard</h2>
                <p className="officer-name">Welcome, {user.name}</p>
            </div>

            <div className="tab-selector">
                <button
                    className={`tab-btn ${activeTab === 'count' ? 'active' : ''}`}
                    onClick={() => setActiveTab('count')}
                >
                    📊 View Voting Count
                </button>
                <button
                    className={`tab-btn ${activeTab === 'create' ? 'active' : ''}`}
                    onClick={() => setActiveTab('create')}
                >
                    ➕ Create Voting
                </button>
                <button
                    className={`tab-btn ${activeTab === 'manage' ? 'active' : ''}`}
                    onClick={() => setActiveTab('manage')}
                >
                    ⚙️ Manage Elections
                </button>
                <button
                    className={`tab-btn ${activeTab === 'users' ? 'active' : ''}`}
                    onClick={() => setActiveTab('users')}
                >
                    👥 User Management
                </button>
            </div>

            <div className="tab-content">
                {activeTab === 'count' ? (
                    <div className="vote-count-section">
                        <h3>Live Vote Count</h3>
                        {loading ? (
                            <div className="loading-message">Loading results...</div>
                        ) : Object.keys(voteData).length > 0 ? (
                            <div className="vote-count-grid">
                                {Object.keys(voteData).map(candidate => (
                                    <div key={candidate} className="vote-count-card">
                                        <div className="candidate-name">{candidate}</div>
                                        <div className="vote-number">{voteData[candidate]}</div>
                                        <div className="vote-label">
                                            vote{voteData[candidate] !== 1 ? 's' : ''}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <div className="no-votes-message">No votes cast yet</div>
                        )}
                    </div>
                ) : activeTab === 'create' ? (
                    <CreateVoting onElectionCreated={handleElectionChange} />
                ) : activeTab === 'manage' ? (
                    <ManageElections onElectionUpdated={handleElectionChange} />
                ) : (
                    <UserManagement />
                )}
            </div>
        </div>
    );
}


