const crypto = require('./crypto');

console.log('╔══════════════════════════════════════════════════════════════╗');
console.log('║     SMART VOTING SYSTEM - CRYPTOGRAPHIC DEMONSTRATION       ║');
console.log('╚══════════════════════════════════════════════════════════════╝\n');

async function demonstrateCrypto() {
    // 1. PASSWORD HASHING (Bcrypt)
    console.log('1️⃣  PASSWORD HASHING (Bcrypt with Salt)\n');
    console.log('─'.repeat(60));
    const password = 'MySecurePass123';
    const hash = await crypto.hashPassword(password);
    console.log('   Original Password: ', password);
    console.log('   Bcrypt Hash:       ', hash);
    console.log('   Hash Length:       ', hash.length, 'characters');
    console.log('   Algorithm:          $2b$ = Bcrypt');
    console.log('   Cost Factor:        $10$ = 10 rounds (2^10 iterations)');
    console.log('   Salt:              ', hash.substring(7, 29), '(embedded)');
    console.log('   Hash Value:        ', hash.substring(29), '\n');

    // 2. VOTE HASHING (SHA-256)
    console.log('2️⃣  VOTE HASHING (SHA-256)\n');
    console.log('─'.repeat(60));
    const vote = 'CANDIDATE-Alice-001';
    const voteHash = crypto.hashVote(vote);
    console.log('   Vote Data:         ', vote);
    console.log('   SHA-256 Hash:      ', voteHash);
    console.log('   Hash Length:       ', voteHash.length, 'hex characters (64)');
    console.log('   Purpose:            Anonymization & Integrity\n');

    // 3. AES-256-GCM ENCRYPTION
    console.log('3️⃣  AES-256-GCM ENCRYPTION (Authenticated Encryption)\n');
    console.log('─'.repeat(60));
    const key = crypto.generateEncryptionKey();
    const voteData = JSON.stringify({
        candidate: 'Alice Johnson',
        candidateId: 'CAND-001',
        timestamp: Date.now()
    });
    const encrypted = crypto.encryptData(voteData, key);
    console.log('   Original Vote Data:', voteData);
    console.log('   Encryption Key:    ', key);
    console.log('   Encrypted Data:    ', encrypted.encrypted.substring(0, 50) + '...');
    console.log('   IV (Init Vector):  ', encrypted.iv);
    console.log('   Auth Tag:          ', encrypted.authTag);
    console.log('   Algorithm:          AES-256-GCM (256-bit key, GCM mode)\n');

    // 4. HMAC-SHA256 SIGNATURE
    console.log('4️⃣  HMAC-SHA256 SIGNATURE (Session Integrity)\n');
    console.log('─'.repeat(60));
    const sessionToken = crypto.generateSecureToken(32);
    const secret = 'voting-system-secret-key';
    const hmac = crypto.generateHMAC(sessionToken, secret);
    console.log('   Session Token:     ', sessionToken.substring(0, 40) + '...');
    console.log('   HMAC Secret:       ', secret);
    console.log('   HMAC Signature:    ', hmac);
    console.log('   Algorithm:          HMAC-SHA256\n');

    // 5. RSA KEY PAIR GENERATION
    console.log('5️⃣  RSA KEY PAIR (2048-bit)\n');
    console.log('─'.repeat(60));
    const rsaKeys = crypto.generateRSAKeyPair();
    console.log('   Public Key (PEM):');
    console.log('   ' + rsaKeys.publicKey.split('\n').slice(0, 3).join('\n   '));
    console.log('   ...(truncated)');
    console.log('\n   Private Key (PEM):');
    console.log('   ' + rsaKeys.privateKey.split('\n').slice(0, 3).join('\n   '));
    console.log('   ...(truncated)');
    console.log('\n   Modulus Length:     2048 bits');
    console.log('   Padding:            OAEP with SHA-256\n');

    // 6. DIGITAL SIGNATURE (RSA-SHA256)
    console.log('6️⃣  DIGITAL SIGNATURE (RSA-SHA256)\n');
    console.log('─'.repeat(60));
    const dataToSign = 'Vote Record: V1001 voted for CAND-001';
    const signature = crypto.generateSignature(dataToSign, rsaKeys.privateKey);
    const isValid = crypto.verifySignature(dataToSign, signature, rsaKeys.publicKey);
    console.log('   Data to Sign:      ', dataToSign);
    console.log('   Signature (hex):   ', signature.substring(0, 50) + '...');
    console.log('   Signature Length:  ', signature.length, 'hex characters');
    console.log('   Verification:      ', isValid ? '✅ VALID' : '❌ INVALID');
    console.log('   Algorithm:          RSA-SHA256\n');

    // 7. BASE32 ENCODING (MFA Secret)
    console.log('7️⃣  BASE32 ENCODING (MFA/TOTP)\n');
    console.log('─'.repeat(60));
    const mfaData = crypto.generateMFASecret('V1001');
    console.log('   User ID:           ', 'V1001');
    console.log('   Base32 Secret:     ', mfaData.secret);
    console.log('   Encoding:           Base32 (A-Z, 2-7)');
    console.log('   Purpose:            Google Authenticator compatibility');
    console.log('   OTP Auth URL:       otpauth://totp/...\n');

    // 8. HYBRID ENCRYPTION (RSA + AES)
    console.log('8️⃣  HYBRID ENCRYPTION (RSA + AES-256-GCM)\n');
    console.log('─'.repeat(60));
    const sensitiveData = 'Voter: V1001, Candidate: Alice, Time: ' + new Date().toISOString();
    const hybridEncrypted = crypto.hybridEncrypt(sensitiveData, rsaKeys.publicKey);
    console.log('   Original Data:     ', sensitiveData);
    console.log('   Step 1:             Generate random AES-256 key');
    console.log('   Step 2:             Encrypt data with AES-256-GCM');
    console.log('   Step 3:             Encrypt AES key with RSA public key');
    console.log('\n   Encrypted Data:    ', hybridEncrypted.encryptedData.substring(0, 40) + '...');
    console.log('   Encrypted AES Key: ', hybridEncrypted.encryptedKey.substring(0, 40) + '...');
    console.log('   IV:                 ', hybridEncrypted.iv);
    console.log('   Auth Tag:           ', hybridEncrypted.authTag, '\n');

    // 9. SUMMARY TABLE
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║                    CRYPTOGRAPHIC SUMMARY                      ║');
    console.log('╠══════════════════════════════════════════════════════════════╣');
    console.log('║ Technique            │ Algorithm         │ Output Encoding  ║');
    console.log('╠══════════════════════════════════════════════════════════════╣');
    console.log('║ Password Hashing     │ Bcrypt (10 rounds)│ Bcrypt format    ║');
    console.log('║ Vote Hashing         │ SHA-256           │ Hexadecimal      ║');
    console.log('║ Session Integrity    │ HMAC-SHA256       │ Hexadecimal      ║');
    console.log('║ Symmetric Encryption │ AES-256-GCM       │ Hexadecimal      ║');
    console.log('║ Asymmetric Encryption│ RSA-2048-OAEP     │ Base64           ║');
    console.log('║ Digital Signature    │ RSA-SHA256        │ Hexadecimal      ║');
    console.log('║ MFA Secret           │ TOTP              │ Base32           ║');
    console.log('║ Hybrid Encryption    │ RSA + AES-256     │ Mixed            ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');

    console.log('✅ Demonstration Complete!\n');
    console.log('📁 Check user.json for real bcrypt password hashes');
    console.log('🔐 All cryptographic functions are production-ready\n');
}

// Run demonstration
demonstrateCrypto().catch(console.error);
