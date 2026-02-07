import { useState } from "react";
import { verifyCredentials, requestOTP, verifyOTPLogin, registerUser } from "./services";

export default function Login({ setUser }) {
    const [step, setStep] = useState(1); // 1: role, 2: ID+password, 3: email, 4: OTP
    const [role, setRole] = useState("");
    const [voterId, setVoterId] = useState("");
    const [password, setPassword] = useState("");
    const [email, setEmail] = useState("");
    const [otp, setOtp] = useState("");
    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");
    const [loading, setLoading] = useState(false);

    // Signup mode
    const [isSignupMode, setIsSignupMode] = useState(false);
    const [signupName, setSignupName] = useState("");
    const [signupEmail, setSignupEmail] = useState("");
    const [signupPassword, setSignupPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");

    // Step 1: Handle role selection
    const handleRoleSelection = (selectedRole) => {
        setRole(selectedRole);
        setStep(2);
        setError("");
    };

    // Step 2: Verify credentials (ID + password ONLY) - stops if invalid
    const handleVerifyCredentials = async (e) => {
        e.preventDefault();
        setError("");
        setSuccess("");

        if (!voterId.trim()) {
            setError("Please enter your ID");
            return;
        }

        if (!password.trim()) {
            setError("Please enter your password");
            return;
        }

        setLoading(true);

        try {
            // Verify credentials first
            const credRes = await verifyCredentials(voterId.trim(), password.trim(), role);

            if (!credRes.success) {
                setError(credRes.message || "Invalid credentials. Please try again.");
                setLoading(false);
                return; // STOP HERE if credentials are invalid
            }

            // If valid, move to email step
            setSuccess("Credentials verified! Please enter your email.");
            setStep(3);
        } catch (err) {
            setError("Network error. Please check your connection and try again.");
        } finally {
            setLoading(false);
        }
    };

    // Step 3: Request OTP with email
    const handleRequestOTP = async (e) => {
        e.preventDefault();
        setError("");
        setSuccess("");

        if (!email.trim()) {
            setError("Please enter your email address");
            return;
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            setError("Please enter a valid email address");
            return;
        }

        setLoading(true);

        try {
            const otpRes = await requestOTP(voterId.trim(), password.trim(), email.trim(), role);

            if (otpRes.success) {
                setSuccess("OTP sent to your email!");
                setStep(4); // Move to OTP verification
            } else {
                setError(otpRes.message || "Failed to send OTP. Please try again.");
            }
        } catch (err) {
            setError("Network error. Please check your connection and try again.");
        } finally {
            setLoading(false);
        }
    };

    // Step 4: Verify OTP and login
    const handleVerifyOTP = async (e) => {
        e.preventDefault();
        setError("");

        if (!otp.trim() || otp.length !== 6) {
            setError("Please enter the 6-digit OTP");
            return;
        }

        setLoading(true);

        try {
            const res = await verifyOTPLogin(voterId.trim(), email.trim(), otp.trim());

            if (res.success) {
                localStorage.setItem('sessionToken', res.sessionToken);
                localStorage.setItem('sessionSignature', res.sessionSignature);
                localStorage.setItem('userData', JSON.stringify(res.user));
                setUser(res.user);
            } else {
                setError(res.message || "Invalid OTP. Please try again.");
            }
        } catch (err) {
            setError("Network error. Please check your connection and try again.");
        } finally {
            setLoading(false);
        }
    };

    // Handle signup submission
    const handleSignup = async (e) => {
        e.preventDefault();
        setError("");
        setSuccess("");

        // Validation
        if (!signupName.trim()) {
            setError("Please enter your full name");
            return;
        }

        if (!signupEmail.trim()) {
            setError("Please enter your email");
            return;
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(signupEmail)) {
            setError("Please enter a valid email address");
            return;
        }

        if (!signupPassword.trim()) {
            setError("Please enter a password");
            return;
        }

        if (signupPassword.length < 8) {
            setError("Password must be at least 8 characters long");
            return;
        }

        if (signupPassword !== confirmPassword) {
            setError("Passwords do not match");
            return;
        }

        setLoading(true);

        try {
            const res = await registerUser(signupName.trim(), signupEmail.trim(), signupPassword.trim());

            if (res.success) {
                setSuccess(`Registration successful! Your Voter ID is: ${res.voterId}. Please wait for approval from an Election Officer.`);
                // Clear signup form
                setSignupName("");
                setSignupEmail("");
                setSignupPassword("");
                setConfirmPassword("");
                // Switch back to login after 5 seconds
                setTimeout(() => {
                    setIsSignupMode(false);
                    setSuccess("");
                }, 5000);
            } else {
                setError(res.message || "Registration failed. Please try again.");
            }
        } catch (err) {
            setError("Network error. Please check your connection and try again.");
        } finally {
            setLoading(false);
        }
    };

    const toggleSignupMode = () => {
        setIsSignupMode(!isSignupMode);
        setError("");
        setSuccess("");
        setSignupName("");
        setSignupEmail("");
        setSignupPassword("");
        setConfirmPassword("");
    };

    const goBack = () => {
        setError("");
        setSuccess("");
        if (step === 4) {
            setOtp("");
            setStep(3);
        } else if (step === 3) {
            setEmail("");
            setStep(2);
        } else if (step === 2) {
            setVoterId("");
            setPassword("");
            setStep(1);
        }
    };

    return (
        <div className="fullscreen-login-container">
            {/* Header */}
            <div className="fullscreen-header">
                <div className="logo-container">
                    <div className="logo-icon">🗳️</div>
                    <h1 className="logo-title">Smart Voting</h1>
                </div>
                <p className="subtitle">Secure Digital Democracy</p>
            </div>

            {/* Step 1: Role Selection */}
            {step === 1 && (
                <div className="fullscreen-content">
                    <h3 className="fullscreen-step-title">Select Your Role</h3>
                    <div className="role-buttons-fullscreen">
                        <button
                            className="role-card-fullscreen"
                            onClick={() => handleRoleSelection('voter')}
                        >
                            <div className="role-icon">🗳️</div>
                            <div className="role-name">Voter</div>
                            <div className="role-desc">Cast your vote</div>
                        </button>
                        <button
                            className="role-card-fullscreen"
                            onClick={() => handleRoleSelection('election_officer')}
                        >
                            <div className="role-icon">👔</div>
                            <div className="role-name">Election Officer</div>
                            <div className="role-desc">Manage elections</div>
                        </button>
                        <button
                            className="role-card-fullscreen"
                            onClick={() => handleRoleSelection('admin')}
                        >
                            <div className="role-icon">🔐</div>
                            <div className="role-name">Administrator</div>
                            <div className="role-desc">System management</div>
                        </button>
                    </div>
                </div>
            )}

            {/* Step 2: ID + Password (or Signup if toggled) */}
            {step === 2 && (
                <div className="fullscreen-content">
                    {!isSignupMode ? (
                        <form onSubmit={handleVerifyCredentials} className="fullscreen-form-clean">
                            {error && <div className="modern-error">{error}</div>}
                            {success && <div className="modern-success">{success}</div>}

                            <h3 className="fullscreen-step-title">
                                {role === 'voter' ? 'Voter Login' : role === 'election_officer' ? 'Election Officer Login' : 'Administrator Login'}
                            </h3>

                            <div className="form-field">
                                <label>{role === 'voter' ? 'Voter ID' : role === 'election_officer' ? 'Officer ID' : 'Admin ID'}</label>
                                <div className="input-container">
                                    <span className="input-prefix">🆔</span>
                                    <input
                                        type="text"
                                        value={voterId}
                                        onChange={e => setVoterId(e.target.value)}
                                        placeholder="Enter your ID"
                                        className="modern-input"
                                        disabled={loading}
                                        autoFocus
                                    />
                                </div>
                            </div>

                            <div className="form-field">
                                <label>Password</label>
                                <div className="input-container">
                                    <span className="input-prefix">🔒</span>
                                    <input
                                        type="password"
                                        value={password}
                                        onChange={e => setPassword(e.target.value)}
                                        placeholder="Enter your password"
                                        className="modern-input"
                                        disabled={loading}
                                    />
                                </div>
                            </div>

                            <button type="submit" className="fullscreen-submit" disabled={loading}>
                                {loading ? (
                                    <span className="loading-spinner"></span>
                                ) : (
                                    <>Verify Credentials</>
                                )}
                            </button>

                            {/* Signup link for voters only */}
                            {role === 'voter' && (
                                <div style={{ textAlign: 'center', marginTop: '20px' }}>
                                    <button
                                        type="button"
                                        className="signup-toggle-link"
                                        onClick={toggleSignupMode}
                                        disabled={loading}
                                    >
                                        New user? Sign up here
                                    </button>
                                </div>
                            )}

                            <button
                                type="button"
                                className="fullscreen-back-button"
                                onClick={goBack}
                                disabled={loading}
                            >
                                ← Back
                            </button>
                        </form>
                    ) : (
                        <form onSubmit={handleSignup} className="fullscreen-form-clean">
                            {error && <div className="modern-error">{error}</div>}
                            {success && <div className="modern-success">{success}</div>}

                            <h3 className="fullscreen-step-title">New Voter Registration</h3>
                            <p className="fullscreen-step-description">
                                Create an account to become a registered voter. Your account will require approval from an Election Officer.
                            </p>

                            <div className="form-field">
                                <label>Full Name</label>
                                <div className="input-container">
                                    <span className="input-prefix">👤</span>
                                    <input
                                        type="text"
                                        value={signupName}
                                        onChange={e => setSignupName(e.target.value)}
                                        placeholder="Enter your full name"
                                        className="modern-input"
                                        disabled={loading}
                                        autoFocus
                                    />
                                </div>
                            </div>

                            <div className="form-field">
                                <label>Email Address</label>
                                <div className="input-container">
                                    <span className="input-prefix">📧</span>
                                    <input
                                        type="email"
                                        value={signupEmail}
                                        onChange={e => setSignupEmail(e.target.value)}
                                        placeholder="your@email.com"
                                        className="modern-input"
                                        disabled={loading}
                                    />
                                </div>
                            </div>

                            <div className="form-field">
                                <label>Password</label>
                                <div className="input-container">
                                    <span className="input-prefix">🔒</span>
                                    <input
                                        type="password"
                                        value={signupPassword}
                                        onChange={e => setSignupPassword(e.target.value)}
                                        placeholder="Minimum 8 characters"
                                        className="modern-input"
                                        disabled={loading}
                                    />
                                </div>
                            </div>

                            <div className="form-field">
                                <label>Confirm Password</label>
                                <div className="input-container">
                                    <span className="input-prefix">🔒</span>
                                    <input
                                        type="password"
                                        value={confirmPassword}
                                        onChange={e => setConfirmPassword(e.target.value)}
                                        placeholder="Re-enter password"
                                        className="modern-input"
                                        disabled={loading}
                                    />
                                </div>
                            </div>

                            <button type="submit" className="fullscreen-submit" disabled={loading}>
                                {loading ? (
                                    <span className="loading-spinner"></span>
                                ) : (
                                    <>Register</>
                                )}
                            </button>

                            <div style={{ textAlign: 'center', marginTop: '20px' }}>
                                <button
                                    type="button"
                                    className="signup-toggle-link"
                                    onClick={toggleSignupMode}
                                    disabled={loading}
                                >
                                    Already have an account? Login
                                </button>
                            </div>

                            <button
                                type="button"
                                className="fullscreen-back-button"
                                onClick={goBack}
                                disabled={loading}
                            >
                                ← Back
                            </button>
                        </form>
                    )}
                </div>
            )}

            {/* Step 3: Email Verification */}
            {step === 3 && (
                <div className="fullscreen-content">
                    <form onSubmit={handleRequestOTP} className="fullscreen-form-clean">
                        {error && <div className="modern-error">{error}</div>}
                        {success && <div className="modern-success">{success}</div>}

                        <h3 className="fullscreen-step-title">Verify Your Email</h3>
                        <p className="fullscreen-step-description">
                            Enter your email address to receive a verification code
                        </p>

                        <div className="form-field">
                            <label>Email Address</label>
                            <div className="input-container">
                                <span className="input-prefix">📧</span>
                                <input
                                    type="email"
                                    value={email}
                                    onChange={e => setEmail(e.target.value)}
                                    placeholder="your@email.com"
                                    disabled={loading}
                                    className="modern-input"
                                    autoFocus
                                />
                            </div>
                        </div>

                        <button type="submit" className="fullscreen-submit" disabled={loading}>
                            {loading ? (
                                <span className="loading-spinner"></span>
                            ) : (
                                <>Send OTP</>
                            )}
                        </button>

                        <button
                            type="button"
                            className="fullscreen-back-button"
                            onClick={goBack}
                            disabled={loading}
                        >
                            ← Back
                        </button>
                    </form>
                </div>
            )}

            {/* Step 4: OTP Verification */}
            {step === 4 && (
                <div className="fullscreen-content">
                    <form onSubmit={handleVerifyOTP} className="fullscreen-form-clean">
                        {error && <div className="modern-error">{error}</div>}

                        <div className="otp-info-fullscreen">
                            <p>Enter the 6-digit code sent to:</p>
                            <p className="contact-display">{email}</p>
                        </div>

                        <div className="form-field">
                            <label>One-Time Password</label>
                            <div className="otp-input-container">
                                <input
                                    type="text"
                                    value={otp}
                                    onChange={e => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                    placeholder="000000"
                                    disabled={loading}
                                    className="otp-input"
                                    maxLength="6"
                                    autoFocus
                                />
                            </div>
                        </div>

                        <button type="submit" className="fullscreen-submit" disabled={loading}>
                            {loading ? (
                                <span className="loading-spinner"></span>
                            ) : (
                                <>Verify & Login</>
                            )}
                        </button>

                        <button
                            type="button"
                            className="fullscreen-back-button"
                            onClick={goBack}
                            disabled={loading}
                        >
                            ← Back
                        </button>
                    </form>
                </div>
            )}
        </div>
    );
}
