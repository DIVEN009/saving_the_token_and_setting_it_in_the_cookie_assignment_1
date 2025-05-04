const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Static secrets (in production, use environment variables)
const JWT_SECRET = 'myjwtsecret';
const ENCRYPTION_KEY = crypto.createHash('sha256').update('myencryptionkey').digest(); // 32 bytes
const IV = Buffer.from('1234567890123456'); // 16 bytes for AES-256-CBC

// 🔐 Encrypt function
const encrypt = (payload) => {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return encrypted;
};

// 🔓 Decrypt function
const decrypt = (encryptedToken) => {
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
  let decrypted = decipher.update(encryptedToken, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  const decoded = jwt.verify(decrypted, JWT_SECRET);
  return decoded;
};

// ✅ Test the functions
const encrypted = encrypt({ userId: 42, role: 'student' });
console.log('Encrypted:', encrypted);

try {
  const decrypted = decrypt(encrypted);
  console.log('Success:', decrypted);
} catch (err) {
  console.error('Decryption/Verification failed:', err.message);
}
