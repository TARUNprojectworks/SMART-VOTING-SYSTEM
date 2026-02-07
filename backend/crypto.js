const crypto = require("crypto");
const bcrypt = require("bcrypt");
const speakeasy = require("speakeasy");

// Configuration constants
const BCRYPT_ROUNDS = 10; // Recommended salt rounds for bcrypt
const ENCRYPTION_ALGORITHM = "aes-256-gcm";
const ENCRYPTION_KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16; // 128 bits for GCM
const AUTH_TAG_LENGTH = 16; // 128 bits for GCM

/**
 * Hash password using bcrypt with salt
 * NIST SP 800-63-2 compliant password storage
 * @param {string} password - Plain text password
 * @returns {Promise<string>} - Bcrypt hash with salt
 */
exports.hashPassword = async (password) => {
    return await bcrypt.hash(password, BCRYPT_ROUNDS);
};

/**
 * Verify password against bcrypt hash
 * @param {string} password - Plain text password
 * @param {string} hash - Stored bcrypt hash
 * @returns {Promise<boolean>} - True if password matches
 */
exports.verifyPassword = async (password, hash) => {
    return await bcrypt.compare(password, hash);
};

/**
 * Generate MFA secret for TOTP-based two-factor authentication
 * @param {string} userIdentifier - Unique user identifier (voter ID)
 * @returns {object} - Secret and otpauth URL
 */
exports.generateMFASecret = (userIdentifier) => {
    const secret = speakeasy.generateSecret({
        name: `Smart Voting System (${userIdentifier})`,
        issuer: "Smart Voting System",
        length: 32
    });

    return {
        secret: secret.base32,
        otpauthUrl: secret.otpauth_url
    };
};

/**
 * Verify TOTP token for MFA
 * @param {string} secret - User's MFA secret
 * @param {string} token - 6-digit TOTP code
 * @returns {boolean} - True if token is valid
 */
exports.verifyMFAToken = (secret, token) => {
    return speakeasy.totp.verify({
        secret: secret,
        encoding: 'base32',
        token: token,
        window: 2 // Allow 2 time steps before/after for clock skew (60 seconds tolerance)
    });
};

/**
 * Encrypt sensitive data using AES-256-GCM
 * @param {string} data - Data to encrypt
 * @param {string} key - Encryption key (32 bytes hex)
 * @returns {object} - Encrypted data with IV and auth tag
 */
exports.encryptData = (data, key) => {
    // Generate random IV
    const iv = crypto.randomBytes(IV_LENGTH);

    // Create cipher
    const cipher = crypto.createCipheriv(
        ENCRYPTION_ALGORITHM,
        Buffer.from(key, 'hex'),
        iv
    );

    // Encrypt data
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Get authentication tag
    const authTag = cipher.getAuthTag();

    return {
        encrypted: encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex')
    };
};

/**
 * Decrypt data encrypted with AES-256-GCM
 * @param {object} encryptedData - Object with encrypted, iv, and authTag
 * @param {string} key - Decryption key (32 bytes hex)
 * @returns {string} - Decrypted data
 */
exports.decryptData = (encryptedData, key) => {
    try {
        // Create decipher
        const decipher = crypto.createDecipheriv(
            ENCRYPTION_ALGORITHM,
            Buffer.from(key, 'hex'),
            Buffer.from(encryptedData.iv, 'hex')
        );

        // Set authentication tag
        decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));

        // Decrypt data
        let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (error) {
        throw new Error('Decryption failed - data may be tampered');
    }
};

/**
 * Generate encryption key
 * @returns {string} - 32-byte hex key
 */
exports.generateEncryptionKey = () => {
    return crypto.randomBytes(ENCRYPTION_KEY_LENGTH).toString('hex');
};

/**
 * Generate digital signature for data integrity
 * @param {string} data - Data to sign
 * @param {string} privateKey - Private key for signing
 * @returns {string} - Signature in hex format
 */
exports.generateSignature = (data, privateKey) => {
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(data);
    sign.end();
    return sign.sign(privateKey, 'hex');
};

/**
 * Verify digital signature
 * @param {string} data - Original data
 * @param {string} signature - Signature to verify
 * @param {string} publicKey - Public key for verification
 * @returns {boolean} - True if signature is valid
 */
exports.verifySignature = (data, signature, publicKey) => {
    const verify = crypto.createVerify('RSA-SHA256');
    verify.update(data);
    verify.end();
    return verify.verify(publicKey, signature, 'hex');
};

/**
 * Hash vote for anonymization (existing function)
 * @param {string} vote - Vote to hash
 * @returns {string} - SHA-256 hash
 */
exports.hashVote = (vote) => {
    return crypto.createHash("sha256").update(vote).digest("hex");
};

/**
 * Generate HMAC for session token integrity
 * @param {string} sessionToken - Session token
 * @param {string} secret - HMAC secret key
 * @returns {string} - HMAC signature
 */
exports.generateHMAC = (sessionToken, secret) => {
    return crypto.createHmac('sha256', secret)
        .update(sessionToken)
        .digest('hex');
};

/**
 * Verify HMAC signature
 * @param {string} sessionToken - Session token
 * @param {string} signature - HMAC signature to verify
 * @param {string} secret - HMAC secret key
 * @returns {boolean} - True if HMAC is valid
 */
exports.verifyHMAC = (sessionToken, signature, secret) => {
    const expectedSignature = exports.generateHMAC(sessionToken, secret);
    return crypto.timingSafeEqual(
        Buffer.from(signature, 'hex'),
        Buffer.from(expectedSignature, 'hex')
    );
};

/**
 * Generate secure random token
 * @param {number} bytes - Number of random bytes (default 32)
 * @returns {string} - Random token in hex
 */
exports.generateSecureToken = (bytes = 32) => {
    return crypto.randomBytes(bytes).toString('hex');
};

// ============================================================================
// SECURE KEY EXCHANGE - Elliptic Curve Diffie-Hellman (ECDH)
// ============================================================================

/**
 * Generate ECDH key pair for secure key exchange
 * Uses secp256k1 curve (same as Bitcoin)
 * @returns {object} - Public and private keys
 */
exports.generateECDHKeyPair = () => {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.generateKeys();

    return {
        publicKey: ecdh.getPublicKey('hex'),
        privateKey: ecdh.getPrivateKey('hex'),
        ecdh: ecdh // Keep instance for shared secret computation
    };
};

/**
 * Compute shared secret from ECDH key exchange
 * @param {string} privateKey - Your private key (hex)
 * @param {string} otherPublicKey - Other party's public key (hex)
 * @returns {string} - Shared secret (hex)
 */
exports.computeECDHSharedSecret = (privateKey, otherPublicKey) => {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(Buffer.from(privateKey, 'hex'));

    const sharedSecret = ecdh.computeSecret(
        Buffer.from(otherPublicKey, 'hex')
    );

    // Derive 256-bit key from shared secret using SHA-256
    return crypto.createHash('sha256')
        .update(sharedSecret)
        .digest('hex');
};

// ============================================================================
// RSA KEY PAIR GENERATION (for Hybrid Encryption)
// ============================================================================

/**
 * Generate RSA key pair for asymmetric encryption
 * @returns {object} - Public and private keys in PEM format
 */
exports.generateRSAKeyPair = () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048, // 2048-bit key
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });

    return { publicKey, privateKey };
};

/**
 * Encrypt data with RSA public key
 * @param {string} data - Data to encrypt
 * @param {string} publicKey - RSA public key (PEM format)
 * @returns {string} - Encrypted data (base64)
 */
exports.encryptWithRSA = (data, publicKey) => {
    const encrypted = crypto.publicEncrypt(
        {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        Buffer.from(data, 'utf8')
    );

    return encrypted.toString('base64');
};

/**
 * Decrypt data with RSA private key
 * @param {string} encryptedData - Encrypted data (base64)
 * @param {string} privateKey - RSA private key (PEM format)
 * @returns {string} - Decrypted data
 */
exports.decryptWithRSA = (encryptedData, privateKey) => {
    const decrypted = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        Buffer.from(encryptedData, 'base64')
    );

    return decrypted.toString('utf8');
};

// ============================================================================
// HYBRID ENCRYPTION (RSA + AES)
// ============================================================================

/**
 * Hybrid encryption: Encrypt data using RSA + AES
 * - Generate random AES key
 * - Encrypt data with AES-256-GCM
 * - Encrypt AES key with RSA public key
 * @param {string} data - Data to encrypt
 * @param {string} rsaPublicKey - RSA public key for encrypting AES key
 * @returns {object} - Encrypted data, encrypted key, IV, and auth tag
 */
exports.hybridEncrypt = (data, rsaPublicKey) => {
    // Step 1: Generate random AES key
    const aesKey = exports.generateEncryptionKey();

    // Step 2: Encrypt data with AES-256-GCM
    const { encrypted, iv, authTag } = exports.encryptData(data, aesKey);

    // Step 3: Encrypt AES key with RSA public key
    const encryptedKey = exports.encryptWithRSA(aesKey, rsaPublicKey);

    return {
        encryptedData: encrypted,
        encryptedKey: encryptedKey,
        iv: iv,
        authTag: authTag
    };
};

/**
 * Hybrid decryption: Decrypt data using RSA + AES
 * @param {object} hybridEncryptedData - Data from hybridEncrypt
 * @param {string} rsaPrivateKey - RSA private key for decrypting AES key
 * @returns {string} - Decrypted data
 */
exports.hybridDecrypt = (hybridEncryptedData, rsaPrivateKey) => {
    // Step 1: Decrypt AES key with RSA private key
    const aesKey = exports.decryptWithRSA(
        hybridEncryptedData.encryptedKey,
        rsaPrivateKey
    );

    // Step 2: Decrypt data with AES
    const decrypted = exports.decryptData({
        encrypted: hybridEncryptedData.encryptedData,
        iv: hybridEncryptedData.iv,
        authTag: hybridEncryptedData.authTag
    }, aesKey);

    return decrypted;
};

// ============================================================================
// VOTE ENCRYPTION UTILITIES
// ============================================================================

/**
 * Encrypt vote data for secure storage
 * @param {object} voteData - Vote data object
 * @param {string} encryptionKey - Encryption key (hex)
 * @returns {object} - Encrypted vote with metadata
 */
exports.encryptVote = (voteData, encryptionKey) => {
    const voteString = JSON.stringify(voteData);
    const encrypted = exports.encryptData(voteString, encryptionKey);

    return {
        ...encrypted,
        timestamp: new Date().toISOString(),
        algorithm: 'AES-256-GCM'
    };
};

/**
 * Decrypt vote data from storage
 * @param {object} encryptedVote - Encrypted vote object
 * @param {string} encryptionKey - Decryption key (hex)
 * @returns {object} - Decrypted vote data
 */
exports.decryptVote = (encryptedVote, encryptionKey) => {
    const decrypted = exports.decryptData({
        encrypted: encryptedVote.encrypted,
        iv: encryptedVote.iv,
        authTag: encryptedVote.authTag
    }, encryptionKey);

    return JSON.parse(decrypted);
};

