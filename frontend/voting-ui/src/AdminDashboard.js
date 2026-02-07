import { useState, useEffect } from "react";
import { results } from "./services";
import CreateVoting from "./CreateVoting";
import ManageElections from "./ManageElections";
import UserManagement from "./UserManagement";

export default function AdminDashboard({ user }) {
    const [activeTab, setActiveTab] = useState("overview");
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
                <h2>🔐 Administrator Dashboard</h2>
                <p className="officer-name">Welcome, {user.name}</p>
            </div>

            <div className="tab-selector">
                <button
                    className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
                    onClick={() => setActiveTab('overview')}
                >
                    📊 System Overview
                </button>
                <button
                    className={`tab-btn ${activeTab === 'users' ? 'active' : ''}`}
                    onClick={() => setActiveTab('users')}
                >
                    👥 User Management
                </button>
                <button
                    className={`tab-btn ${activeTab === 'create' ? 'active' : ''}`}
                    onClick={() => setActiveTab('create')}
                >
                    ➕ Create Election
                </button>
                <button
                    className={`tab-btn ${activeTab === 'manage' ? 'active' : ''}`}
                    onClick={() => setActiveTab('manage')}
                >
                    ⚙️ Manage Elections
                </button>
                <button
                    className={`tab-btn ${activeTab === 'count' ? 'active' : ''}`}
                    onClick={() => setActiveTab('count')}
                >
                    🗳️ Vote Count
                </button>
                <button
                    className={`tab-btn ${activeTab === 'audit' ? 'active' : ''}`}
                    onClick={() => setActiveTab('audit')}
                >
                    🔍 Audit Logs
                </button>
            </div>

            <div className="tab-content">
                {activeTab === 'overview' ? (
                    <SystemOverview />
                ) : activeTab === 'count' ? (
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
                ) : activeTab === 'users' ? (
                    <UserManagement />
                ) : (
                    <AuditLogs />
                )}
            </div>
        </div>
    );
}

// System Overview Component
function SystemOverview() {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // Simulate loading stats - in production, fetch from backend
        setTimeout(() => {
            setStats({
                totalUsers: 6,
                activeElections: 1,
                completedElections: 0,
                totalVotes: 1,
                pendingApprovals: 1
            });
            setLoading(false);
        }, 500);
    }, []);

    if (loading) {
        return <div className="loading-message">Loading system overview...</div>;
    }

    return (
        <div className="system-overview">
            <h3>System Statistics</h3>
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-icon">👥</div>
                    <div className="stat-value">{stats.totalUsers}</div>
                    <div className="stat-label">Total Users</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">🗳️</div>
                    <div className="stat-value">{stats.activeElections}</div>
                    <div className="stat-label">Active Elections</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">✅</div>
                    <div className="stat-value">{stats.completedElections}</div>
                    <div className="stat-label">Completed Elections</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">📝</div>
                    <div className="stat-value">{stats.totalVotes}</div>
                    <div className="stat-label">Total Votes Cast</div>
                </div>
                <div className="stat-card pending">
                    <div className="stat-icon">⏳</div>
                    <div className="stat-value">{stats.pendingApprovals}</div>
                    <div className="stat-label">Pending Approvals</div>
                </div>
            </div>

            <div className="system-info">
                <h4>System Information</h4>
                <div className="info-grid">
                    <div className="info-item">
                        <span className="info-label">Authentication Level:</span>
                        <span className="info-value">LOA-3 (MFA Enabled)</span>
                    </div>
                    <div className="info-item">
                        <span className="info-label">Compliance:</span>
                        <span className="info-value">NIST SP 800-63-2</span>
                    </div>
                    <div className="info-item">
                        <span className="info-label">Session Timeout:</span>
                        <span className="info-value">30 minutes</span>
                    </div>
                    <div className="info-item">
                        <span className="info-label">System Status:</span>
                        <span className="info-value status-active">🟢 Operational</span>
                    </div>
                </div>
            </div>
        </div>
    );
}

// Audit Logs Component
function AuditLogs() {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // Simulate loading audit logs - in production, fetch from backend
        setTimeout(() => {
            setLogs([
                {
                    id: 1,
                    timestamp: new Date().toISOString(),
                    event: 'LOGIN_SUCCESS',
                    user: 'ADMIN001',
                    ip: '127.0.0.1',
                    details: 'Admin logged in successfully'
                },
                {
                    id: 2,
                    timestamp: new Date(Date.now() - 60000).toISOString(),
                    event: 'USER_APPROVED',
                    user: 'ADMIN001',
                    ip: '127.0.0.1',
                    details: 'Approved voter V1001'
                },
                {
                    id: 3,
                    timestamp: new Date(Date.now() - 120000).toISOString(),
                    event: 'ELECTION_CREATED',
                    user: 'OFFICER001',
                    ip: '127.0.0.1',
                    details: 'Created election: Sample Election'
                }
            ]);
            setLoading(false);
        }, 500);
    }, []);

    if (loading) {
        return <div className="loading-message">Loading audit logs...</div>;
    }

    return (
        <div className="audit-logs-container">
            <h3>Security Audit Logs</h3>
            <p className="audit-description">
                View security events and system activities for compliance and monitoring.
            </p>

            {logs.length === 0 ? (
                <div className="no-logs-message">
                    <div className="placeholder-icon">📋</div>
                    <p>No audit logs available</p>
                </div>
            ) : (
                <div className="audit-logs-table">
                    <table>
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Event</th>
                                <th>User</th>
                                <th>IP Address</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            {logs.map(log => (
                                <tr key={log.id}>
                                    <td>{new Date(log.timestamp).toLocaleString()}</td>
                                    <td>
                                        <span className={`event-badge ${log.event.toLowerCase()}`}>
                                            {log.event}
                                        </span>
                                    </td>
                                    <td>{log.user}</td>
                                    <td>{log.ip}</td>
                                    <td>{log.details}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}
