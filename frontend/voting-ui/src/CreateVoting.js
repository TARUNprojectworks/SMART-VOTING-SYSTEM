import { useState } from "react";
import { createElection } from "./services";

export default function CreateVoting({ onElectionCreated }) {
    const [formData, setFormData] = useState({
        title: "",
        description: "",
        startDate: "",
        endDate: "",
        candidates: [
            { name: "", party: "", description: "" },
            { name: "", party: "", description: "" }
        ]
    });
    const [message, setMessage] = useState("");
    const [loading, setLoading] = useState(false);

    const handleInputChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const handleCandidateChange = (index, field, value) => {
        const newCandidates = [...formData.candidates];
        newCandidates[index][field] = value;
        setFormData({ ...formData, candidates: newCandidates });
    };

    const addCandidate = () => {
        setFormData({
            ...formData,
            candidates: [...formData.candidates, { name: "", party: "", description: "" }]
        });
    };

    const removeCandidate = (index) => {
        if (formData.candidates.length > 2) {
            const newCandidates = formData.candidates.filter((_, i) => i !== index);
            setFormData({ ...formData, candidates: newCandidates });
        }
    };

    const validateForm = () => {
        if (!formData.title.trim()) {
            setMessage("✗ Election title is required");
            return false;
        }

        if (!formData.startDate || !formData.endDate) {
            setMessage("✗ Start and end dates are required");
            return false;
        }

        if (new Date(formData.endDate) <= new Date(formData.startDate)) {
            setMessage("✗ End date must be after start date");
            return false;
        }

        const validCandidates = formData.candidates.filter(c => c.name.trim());
        if (validCandidates.length < 2) {
            setMessage("✗ At least 2 candidates are required");
            return false;
        }

        // Check for duplicate candidate names
        const names = validCandidates.map(c => c.name.trim().toLowerCase());
        const uniqueNames = new Set(names);
        if (names.length !== uniqueNames.size) {
            setMessage("✗ Candidate names must be unique");
            return false;
        }

        return true;
    };

    const handleSubmit = async (status) => {
        if (!validateForm()) return;

        setLoading(true);
        setMessage("");

        const electionData = {
            ...formData,
            candidates: formData.candidates.filter(c => c.name.trim()),
            status: status
        };

        const result = await createElection(electionData);

        setLoading(false);

        if (result.success) {
            setMessage(`✓ Election ${status === 'active' ? 'created and activated' : 'saved as draft'} successfully!`);
            // Reset form
            setTimeout(() => {
                setFormData({
                    title: "",
                    description: "",
                    startDate: "",
                    endDate: "",
                    candidates: [
                        { name: "", party: "", description: "" },
                        { name: "", party: "", description: "" }
                    ]
                });
                setMessage("");
                if (onElectionCreated) onElectionCreated(result.election);
            }, 2000);
        } else {
            setMessage(`✗ ${result.message}`);
        }
    };

    return (
        <div className="create-election-container">
            <h3>Create New Election</h3>

            {message && (
                <div className={message.startsWith('✓') ? 'success-message' : 'error-message'}>
                    {message}
                </div>
            )}

            <div className="create-election-form">
                <div className="form-section">
                    <label className="form-label">Election Title *</label>
                    <input
                        type="text"
                        name="title"
                        value={formData.title}
                        onChange={handleInputChange}
                        placeholder="e.g., Student Council Election 2026"
                        className="form-input"
                        maxLength="100"
                    />
                </div>

                <div className="form-section">
                    <label className="form-label">Description</label>
                    <textarea
                        name="description"
                        value={formData.description}
                        onChange={handleInputChange}
                        placeholder="Provide details about this election..."
                        className="form-textarea"
                        rows="3"
                        maxLength="500"
                    />
                </div>

                <div className="date-picker-group">
                    <div className="form-section">
                        <label className="form-label">Start Date & Time *</label>
                        <input
                            type="datetime-local"
                            name="startDate"
                            value={formData.startDate}
                            onChange={handleInputChange}
                            className="form-input"
                        />
                    </div>

                    <div className="form-section">
                        <label className="form-label">End Date & Time *</label>
                        <input
                            type="datetime-local"
                            name="endDate"
                            value={formData.endDate}
                            onChange={handleInputChange}
                            className="form-input"
                        />
                    </div>
                </div>

                <div className="form-section">
                    <div className="candidates-header">
                        <label className="form-label">Candidates * (minimum 2)</label>
                        <button onClick={addCandidate} className="add-candidate-btn">
                            ➕ Add Candidate
                        </button>
                    </div>

                    <div className="candidate-list-builder">
                        {formData.candidates.map((candidate, index) => (
                            <div key={index} className="candidate-builder-card">
                                <div className="candidate-card-header">
                                    <span className="candidate-number">Candidate #{index + 1}</span>
                                    {formData.candidates.length > 2 && (
                                        <button
                                            onClick={() => removeCandidate(index)}
                                            className="remove-candidate-btn"
                                        >
                                            🗑️ Remove
                                        </button>
                                    )}
                                </div>

                                <div className="candidate-builder-fields">
                                    <div className="form-section-inline">
                                        <label className="form-label-small">Full Name *</label>
                                        <input
                                            type="text"
                                            value={candidate.name}
                                            onChange={(e) => handleCandidateChange(index, 'name', e.target.value)}
                                            placeholder="Candidate name"
                                            className="form-input-small"
                                            maxLength="100"
                                        />
                                    </div>

                                    <div className="form-section-inline">
                                        <label className="form-label-small">Party/Affiliation</label>
                                        <input
                                            type="text"
                                            value={candidate.party}
                                            onChange={(e) => handleCandidateChange(index, 'party', e.target.value)}
                                            placeholder="Party or independent"
                                            className="form-input-small"
                                            maxLength="100"
                                        />
                                    </div>

                                    <div className="form-section-inline">
                                        <label className="form-label-small">Description</label>
                                        <textarea
                                            value={candidate.description}
                                            onChange={(e) => handleCandidateChange(index, 'description', e.target.value)}
                                            placeholder="Brief description or manifesto..."
                                            className="form-textarea-small"
                                            rows="2"
                                            maxLength="300"
                                        />
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="form-actions">
                    <button
                        onClick={() => handleSubmit('draft')}
                        className="btn-secondary"
                        disabled={loading}
                    >
                        💾 Save as Draft
                    </button>
                    <button
                        onClick={() => handleSubmit('active')}
                        className="btn-primary"
                        disabled={loading}
                    >
                        {loading ? '⏳ Creating...' : '🚀 Create & Activate'}
                    </button>
                </div>
            </div>
        </div>
    );
}
