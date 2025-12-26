// utils/keyProtection.js
const crypto = require("crypto");

function deriveKey(password, salt) {
  // 200k iteration: demo için güçlü, ama yavaş gelirse 100k yapabilirsin
  return crypto.pbkdf2Sync(password, salt, 200000, 32, "sha256");
}

function encryptPrivateKey(privateKeyPem, password) {
  const salt = crypto.randomBytes(16);
  const key = deriveKey(password, salt);
  const iv = crypto.randomBytes(12); // GCM için 12 byte önerilir

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(privateKeyPem, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return {
    encPrivateKey: ciphertext.toString("base64"),
    privKeySalt: salt.toString("base64"),
    privKeyIv: iv.toString("base64"),
    privKeyTag: tag.toString("base64"),
  };
}

function decryptPrivateKey(userDoc, password) {
  if (!userDoc?.encPrivateKey || !userDoc?.privKeySalt || !userDoc?.privKeyIv || !userDoc?.privKeyTag) {
    throw new Error("Encrypted private key fields are missing.");
  }

  const salt = Buffer.from(userDoc.privKeySalt, "base64");
  const iv = Buffer.from(userDoc.privKeyIv, "base64");
  const tag = Buffer.from(userDoc.privKeyTag, "base64");
  const ciphertext = Buffer.from(userDoc.encPrivateKey, "base64");

  const key = deriveKey(password, salt);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString("utf8"); // PEM
}

module.exports = { encryptPrivateKey, decryptPrivateKey };
