/**
 * Access Control Matrix for Role-Based Access Control (RBAC)
 * Implements NIST SP 800-63-2 access control requirements
 */

// Define all permissions in the system
const PERMISSIONS = {
    VOTE: 'VOTE',
    VIEW_RESULTS: 'VIEW_RESULTS',
    MANAGE_ELECTION: 'MANAGE_ELECTION',
    CREATE_ELECTION: 'CREATE_ELECTION',
    VIEW_ALL_ELECTIONS: 'VIEW_ALL_ELECTIONS',
    MANAGE_USERS: 'MANAGE_USERS',
    VIEW_AUDIT_LOGS: 'VIEW_AUDIT_LOGS',
    SETUP_MFA: 'SETUP_MFA'
};

// Define roles
const ROLES = {
    VOTER: 'voter',
    ELECTION_OFFICER: 'election_officer',
    ADMIN: 'admin'
};

// Access Control Matrix - Maps roles to their permitted actions
const ACCESS_CONTROL_MATRIX = {
    [ROLES.VOTER]: [
        PERMISSIONS.VOTE,
        PERMISSIONS.VIEW_RESULTS,
        PERMISSIONS.VIEW_ALL_ELECTIONS,
        PERMISSIONS.SETUP_MFA
    ],
    [ROLES.ELECTION_OFFICER]: [
        PERMISSIONS.VIEW_RESULTS,
        PERMISSIONS.CREATE_ELECTION,
        PERMISSIONS.MANAGE_ELECTION,
        PERMISSIONS.VIEW_ALL_ELECTIONS,
        PERMISSIONS.VIEW_AUDIT_LOGS,
        PERMISSIONS.SETUP_MFA
    ],
    [ROLES.ADMIN]: [
        PERMISSIONS.VOTE, // Admins can also vote if they are registered voters
        PERMISSIONS.VIEW_RESULTS,
        PERMISSIONS.CREATE_ELECTION,
        PERMISSIONS.MANAGE_ELECTION,
        PERMISSIONS.VIEW_ALL_ELECTIONS,
        PERMISSIONS.MANAGE_USERS,
        PERMISSIONS.VIEW_AUDIT_LOGS,
        PERMISSIONS.SETUP_MFA
    ]
};

// MFA requirements by role
const MFA_REQUIREMENTS = {
    [ROLES.VOTER]: false, // Optional for voters
    [ROLES.ELECTION_OFFICER]: true, // Mandatory for election officers
    [ROLES.ADMIN]: true // Mandatory for administrators
};

/**
 * Check if a role has permission to perform an action
 * @param {string} role - User role
 * @param {string} action - Permission being checked
 * @returns {boolean} - True if role has permission
 */
exports.checkPermission = (role, action) => {
    if (!ACCESS_CONTROL_MATRIX[role]) {
        return false;
    }
    return ACCESS_CONTROL_MATRIX[role].includes(action);
};

/**
 * Get all permitted actions for a role
 * @param {string} role - User role
 * @returns {Array<string>} - Array of permitted actions
 */
exports.getPermittedActions = (role) => {
    return ACCESS_CONTROL_MATRIX[role] || [];
};

/**
 * Check if MFA is required for a role
 * @param {string} role - User role
 * @returns {boolean} - True if MFA is mandatory
 */
exports.isMFARequired = (role) => {
    return MFA_REQUIREMENTS[role] || false;
};

/**
 * Validate user role
 * @param {string} role - Role to validate
 * @returns {boolean} - True if role is valid
 */
exports.isValidRole = (role) => {
    return Object.values(ROLES).includes(role);
};

// Export constants
exports.PERMISSIONS = PERMISSIONS;
exports.ROLES = ROLES;
