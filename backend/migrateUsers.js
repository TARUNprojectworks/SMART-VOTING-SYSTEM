/**
 * Migration script to add password hashes and MFA fields to existing users
 * Run this once to migrate from plain voter ID authentication to password-based auth
 */
const fs = require('fs');
const path = require('path');
const { hashPassword, generateEncryptionKey } = require('./crypto');

const USER_FILE = path.join(__dirname, 'user.json');
const BACKUP_FILE = path.join(__dirname, 'user.backup.json');

// Default passwords for testing (CHANGE IN PRODUCTION!)
const DEFAULT_PASSWORDS = {
    'voter': 'password123',
    'election_officer': 'officer123',
    'admin': 'adminpass123'
};

async function migrateUsers() {
    console.log('Starting user data migration...\n');

    // Read current user data
    const data = JSON.parse(fs.readFileSync(USER_FILE, 'utf8'));

    // Create backup
    fs.writeFileSync(BACKUP_FILE, JSON.stringify(data, null, 4));
    console.log('✓ Backup created at user.backup.json');

    // Generate encryption key for MFA secrets (store this securely in production!)
    const encryptionKey = generateEncryptionKey();
    console.log('✓ Generated encryption key for MFA secrets');
    console.log(`  Key: ${encryptionKey.substring(0, 16)}... (save this securely!)\n`);

    // Migrate each user
    console.log('Migrating users:');
    for (const user of data.users) {
        // Set default password based on role
        const defaultPassword = DEFAULT_PASSWORDS[user.role] || DEFAULT_PASSWORDS['voter'];

        // Hash password
        user.passwordHash = await hashPassword(defaultPassword);

        // Add MFA fields
        user.mfaEnabled = false;
        user.mfaSecret = null;

        // Add security fields
        user.failedLoginAttempts = 0;
        user.accountLockedUntil = null;
        user.lastPasswordChange = new Date().toISOString();

        // Set authentication level based on role
        if (user.role === 'admin' || user.role === 'election_officer') {
            user.authenticationLevel = 'LOA-3'; // Require MFA for admins and officers
        } else {
            user.authenticationLevel = 'LOA-2'; // Password + brute force protection for voters
        }

        // Add votedAt timestamp if missing
        if (!user.votedAt) {
            user.votedAt = null;
        }

        console.log(`  ✓ ${user.voterId} (${user.role}) - Password: ${defaultPassword}`);
    }

    // Add election officer if not present
    const hasOfficer = data.users.some(u => u.role === 'election_officer');
    if (!hasOfficer) {
        console.log('\n  + Adding election officer account...');
        data.users.push({
            voterId: 'OFFICER001',
            name: 'Election Officer',
            role: 'election_officer',
            registered: true,
            voted: false,
            vote: null,
            lastLogin: null,
            passwordHash: await hashPassword(DEFAULT_PASSWORDS['election_officer']),
            mfaEnabled: false,
            mfaSecret: null,
            failedLoginAttempts: 0,
            accountLockedUntil: null,
            lastPasswordChange: new Date().toISOString(),
            authenticationLevel: 'LOA-3',
            votedAt: null
        });
        console.log(`  ✓ OFFICER001 (election_officer) - Password: ${DEFAULT_PASSWORDS['election_officer']}`);
    }

    // Save migrated data
    fs.writeFileSync(USER_FILE, JSON.stringify(data, null, 4));
    console.log('\n✓ Migration complete! Updated user.json');
    console.log('\n⚠️  SECURITY REMINDER:');
    console.log('   - These are TEST passwords for development only');
    console.log('   - In production, enforce strong password policies');
    console.log('   - Store the encryption key securely (environment variable)');
    console.log('   - Enable MFA for admin and officer accounts\n');
}

// Run migration
migrateUsers().catch(error => {
    console.error('Migration failed:', error);
    process.exit(1);
});
