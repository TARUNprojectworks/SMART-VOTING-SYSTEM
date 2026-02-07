import { useState, useEffect } from 'react';
import { getPendingUsers, approveUser, rejectUser } from './services';

export default function UserManagement() {
    const [pendingUsers, setPendingUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [processing, setProcessing] = useState(null);

    useEffect(() => {
        loadPendingUsers();
    }, []);

    const loadPendingUsers = async () => {
        setLoading(true);
        setError('');

        try {
            const res = await getPendingUsers();
            if (res.success) {
                setPendingUsers(res.users || []);
            } else {
                setError(res.message || 'Failed to load pending users');
            }
        } catch (err) {
            setError('Network error');
        } finally {
            setLoading(false);
        }
    };

    const handleApprove = async (voterId) => {
        setProcessing(voterId);
        setError('');
        setSuccess('');

        try {
            const res = await approveUser(voterId);
            if (res.success) {
                setSuccess(res.message || 'User approved successfully');
                // Remove from pending list
                setPendingUsers(prev => prev.filter(u => u.voterId !== voterId));
            } else {
                setError(res.message || 'Failed to approve user');
            }
        } catch (err) {
            setError('Network error');
        } finally {
            setProcessing(null);
        }
    };

    const handleReject = async (voterId) => {
        setProcessing(voterId);
        setError('');
        setSuccess('');

        try {
            const res = await rejectUser(voterId);
            if (res.success) {
                setSuccess(res.message || 'User rejected');
                // Remove from pending list
                setPendingUsers(prev => prev.filter(u => u.voterId !== voterId));
            } else {
                setError(res.message || 'Failed to reject user');
            }
        } catch (err) {
            setError('Network error');
        } finally {
            setProcessing(null);
        }
    };

    if (loading) {
        return (
            <div className="user-management-container">
                <h3>Pending User Registrations</h3>
                <div className="loading-message">Loading pending users...</div>
            </div>
        );
    }

    return (
        <div className="user-management-container">
            <div className="section-header">
                <h3>Pending User Registrations</h3>
                <div className="pending-count-badge">{pendingUsers.length} Pending</div>
            </div>

            {error && <div className="error-message">{error}</div>}
            {success && <div className="success-message">{success}</div>}

            {pendingUsers.length === 0 ? (
                <div className="no-pending-users">
                    <div className="placeholder-icon">✅</div>
                    <p>No pending user registrations</p>
                    <p className="placeholder-details">
                        New voter registrations will appear here for approval.
                    </p>
                </div>
            ) : (
                <div className="pending-users-grid">
                    {pendingUsers.map((user) => (
                        <div key={user.voterId} className="pending-user-card">
                            <div className="user-details">
                                <div className="user-name">{user.name}</div>
                                <div className="user-info-row">
                                    <span className="info-label">Voter ID:</span>
                                    <span className="info-value">{user.voterId}</span>
                                </div>
                                <div className="user-info-row">
                                    <span className="info-label">Email:</span>
                                    <span className="info-value">{user.email}</span>
                                </div>
                                <div className="user-info-row">
                                    <span className="info-label">Registered:</span>
                                    <span className="info-value">
                                        {new Date(user.registeredAt).toLocaleDateString()}
                                    </span>
                                </div>
                            </div>
                            <div className="user-actions">
                                <button
                                    className="approve-btn"
                                    onClick={() => handleApprove(user.voterId)}
                                    disabled={processing === user.voterId}
                                >
                                    {processing === user.voterId ? '...' : '✓ Approve'}
                                </button>
                                <button
                                    className="reject-btn"
                                    onClick={() => handleReject(user.voterId)}
                                    disabled={processing === user.voterId}
                                >
                                    {processing === user.voterId ? '...' : '✗ Reject'}
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
