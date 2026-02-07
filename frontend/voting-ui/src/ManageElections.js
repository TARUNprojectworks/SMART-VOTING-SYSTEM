import { useState, useEffect } from "react";
import { getElections, updateElectionStatus, deleteElection } from "./services";

export default function ManageElections({ onElectionUpdated }) {
    const [elections, setElections] = useState([]);
    const [filter, setFilter] = useState("all");
    const [loading, setLoading] = useState(true);
    const [message, setMessage] = useState("");

    const fetchElections = async () => {
        setLoading(true);
        const statusFilter = filter === "all" ? null : filter;
        const result = await getElections(statusFilter);

        if (result.success) {
            setElections(result.elections || []);
        } else {
            setMessage("✗ Failed to load elections");
        }
        setLoading(false);
    };

    useEffect(() => {
        fetchElections();
    }, [filter]);

    const handleStatusChange = async (electionId, newStatus) => {
        const result = await updateElectionStatus(electionId, newStatus);

        if (result.success) {
            setMessage(`✓ Election ${newStatus} successfully`);
            fetchElections();
            if (onElectionUpdated) onElectionUpdated();
        } else {
            setMessage(`✗ ${result.message}`);
        }

        setTimeout(() => setMessage(""), 3000);
    };

    const handleDelete = async (electionId) => {
        if (!window.confirm("Are you sure you want to delete this election? This action cannot be undone.")) {
            return;
        }

        const result = await deleteElection(electionId);

        if (result.success) {
            setMessage("✓ Election deleted successfully");
            fetchElections();
            if (onElectionUpdated) onElectionUpdated();
        } else {
            setMessage(`✗ ${result.message}`);
        }

        setTimeout(() => setMessage(""), 3000);
    };

    const getStatusBadgeClass = (status) => {
        const classes = {
            'draft': 'status-badge-draft',
            'active': 'status-badge-active',
            'completed': 'status-badge-completed',
            'cancelled': 'status-badge-cancelled'
        };
        return `status-badge ${classes[status] || ''}`;
    };

    const getStatusIcon = (status) => {
        const icons = {
            'draft': '📝',
            'active': '🔴',
            'completed': '✅',
            'cancelled': '❌'
        };
        return icons[status] || '•';
    };

    const formatDate = (dateString) => {
        const date = new Date(dateString);
        return date.toLocaleString('en-IN', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    };

    return (
        <div className="manage-elections-container">
            <div className="manage-header">
                <h3>Manage Elections</h3>
                <div className="filter-buttons">
                    <button
                        className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
                        onClick={() => setFilter('all')}
                    >
                        All
                    </button>
                    <button
                        className={`filter-btn ${filter === 'draft' ? 'active' : ''}`}
                        onClick={() => setFilter('draft')}
                    >
                        Drafts
                    </button>
                    <button
                        className={`filter-btn ${filter === 'active' ? 'active' : ''}`}
                        onClick={() => setFilter('active')}
                    >
                        Active
                    </button>
                    <button
                        className={`filter-btn ${filter === 'completed' ? 'active' : ''}`}
                        onClick={() => setFilter('completed')}
                    >
                        Completed
                    </button>
                </div>
            </div>

            {message && (
                <div className={message.startsWith('✓') ? 'success-message' : 'error-message'}>
                    {message}
                </div>
            )}

            {loading ? (
                <div className="loading-message">Loading elections...</div>
            ) : elections.length === 0 ? (
                <div className="no-elections-message">
                    <div className="placeholder-icon">📋</div>
                    <p>No elections found</p>
                    <p className="placeholder-details">
                        {filter === 'all' ? 'Create your first election to get started' : `No ${filter} elections`}
                    </p>
                </div>
            ) : (
                <div className="elections-grid">
                    {elections.map(election => (
                        <div key={election.electionId} className="election-card">
                            <div className="election-card-header">
                                <div>
                                    <h4 className="election-title">{election.title}</h4>
                                    <span className={getStatusBadgeClass(election.status)}>
                                        {getStatusIcon(election.status)} {election.status.toUpperCase()}
                                    </span>
                                </div>
                            </div>

                            <div className="election-card-body">
                                {election.description && (
                                    <p className="election-description">{election.description}</p>
                                )}

                                <div className="election-meta">
                                    <div className="meta-item">
                                        <span className="meta-label">Start:</span>
                                        <span className="meta-value">{formatDate(election.startDate)}</span>
                                    </div>
                                    <div className="meta-item">
                                        <span className="meta-label">End:</span>
                                        <span className="meta-value">{formatDate(election.endDate)}</span>
                                    </div>
                                    <div className="meta-item">
                                        <span className="meta-label">Candidates:</span>
                                        <span className="meta-value">{election.candidateCount}</span>
                                    </div>
                                    <div className="meta-item">
                                        <span className="meta-label">Total Votes:</span>
                                        <span className="meta-value">{election.totalVotes || 0}</span>
                                    </div>
                                </div>
                            </div>

                            <div className="election-card-actions">
                                {election.status === 'draft' && (
                                    <>
                                        <button
                                            onClick={() => handleStatusChange(election.electionId, 'active')}
                                            className="action-btn action-btn-activate"
                                        >
                                            ▶️ Activate
                                        </button>
                                        <button
                                            onClick={() => handleDelete(election.electionId)}
                                            className="action-btn action-btn-delete"
                                        >
                                            🗑️ Delete
                                        </button>
                                    </>
                                )}

                                {election.status === 'active' && (
                                    <>
                                        <button
                                            onClick={() => handleStatusChange(election.electionId, 'completed')}
                                            className="action-btn action-btn-complete"
                                        >
                                            ✅ Complete
                                        </button>
                                        <button
                                            onClick={() => handleStatusChange(election.electionId, 'cancelled')}
                                            className="action-btn action-btn-cancel"
                                        >
                                            ❌ Cancel
                                        </button>
                                    </>
                                )}

                                {(election.status === 'completed' || election.status === 'cancelled') && (
                                    <div className="election-closed-label">
                                        Election {election.status}
                                    </div>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
