const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const User = require("../models/User");
const Message = require("../models/Message");
const { decryptPrivateKey } = require("../utils/cryptoKeys");

console.log("✅ Messages route dosyası yüklendi!");

// SEND
router.post("/send", async (req, res) => {
  console.log("--- 1. MESAJ GÖNDERME İSTEĞİ GELDİ ---");
  console.log("Gelen Veri:", req.body);

  try {
    const { senderUsername, senderPassword, recipientUsername, content } = req.body;

    if (!senderUsername || !senderPassword || !recipientUsername || !content) {
      return res.status(400).send("senderUsername, senderPassword, recipientUsername, content are required.");
    }

    // Sender: encrypted private key alanları lazım
    const sender = await User.findOne({ username: senderUsername })
      .select("+encPrivateKey +privKeySalt +privKeyIv +privKeyTag");

    const recipient = await User.findOne({ username: recipientUsername });

    if (!sender) return res.status(404).send("Sender not found.");
    if (!recipient) return res.status(404).send("Recipient not found.");
    if (!recipient.publicKey) return res.status(400).send("Recipient has no public key. Cannot encrypt.");

    // ✅ Sender private key'i RAM'de çöz
    let senderPrivateKeyPem;
    try {
      senderPrivateKeyPem = decryptPrivateKey(sender, senderPassword);
    } catch (e) {
      return res.status(401).send("Sender password is wrong or private key cannot be decrypted.");
    }

    // CONFIDENTIALITY: AES-256-CBC
    const symmetricKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv("aes-256-cbc", symmetricKey, iv);
    let encryptedContent = cipher.update(content, "utf8", "hex");
    encryptedContent += cipher.final("hex");

    const finalEncryptedMessage = iv.toString("hex") + ":" + encryptedContent;

    // AES key'i alıcının public key'i ile şifrele (RSA-OAEP-SHA256)
    const encryptedSymmetricKey = crypto.publicEncrypt(
      {
        key: recipient.publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      symmetricKey
    ).toString("base64");

    // INTEGRITY: hash
    const hash = crypto.createHash("sha256").update(content, "utf8").digest("hex");

    // AUTHENTICATION: hash'i imzala
    const sign = crypto.createSign("RSA-SHA256");
    sign.update(hash, "utf8");
    sign.end();
    const signature = sign.sign(senderPrivateKeyPem, "base64");

    // Save
    const newMessage = new Message({
      sender: sender._id,
      recipient: recipient._id,
      encryptedMessage: finalEncryptedMessage,
      encryptedSymmetricKey,
      messageHash: hash,
      digitalSignature: signature,
    });

    const savedMessage = await newMessage.save();
    res.json({ success: true, messageId: savedMessage._id });
  } catch (error) {
    console.error("❌ SUNUCU HATASI:", error);
    res.status(500).send("Error sending message: " + error.message);
  }
});

// INBOX
router.get("/inbox", async (req, res) => {
  try {
    const { username } = req.query;
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: "User not found" });

    const messages = await Message.find({ recipient: user._id })
      .populate("sender", "username publicKey")
      .sort({ createdAt: -1 });

    res.json(messages);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});

// DECRYPT
router.post("/decrypt", async (req, res) => {
  try {
    const { messageId, username, password } = req.body;

    if (!messageId || !username || !password) {
      return res.status(400).json({ error: "messageId, username, password are required." });
    }

    const message = await Message.findById(messageId).populate("sender", "username publicKey");

    const recipient = await User.findOne({ username })
      .select("+encPrivateKey +privKeySalt +privKeyIv +privKeyTag");

    if (!message || !recipient) {
      return res.status(404).json({ error: "Message or User not found" });
    }

    // ✅ Recipient private key'i RAM'de çöz
    let recipientPrivateKeyPem;
    try {
      recipientPrivateKeyPem = decryptPrivateKey(recipient, password);
    } catch (e) {
      return res.status(401).json({ error: "Password is wrong or private key cannot be decrypted." });
    }

    // AES key decrypt
    const encryptedKeyBuffer = Buffer.from(message.encryptedSymmetricKey, "base64");
    const symmetricKey = crypto.privateDecrypt(
      {
        key: recipientPrivateKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      encryptedKeyBuffer
    );

    // Content decrypt
    const parts = message.encryptedMessage.split(":");
    if (parts.length !== 2) return res.status(400).json({ error: "Invalid encrypted message format." });

    const iv = Buffer.from(parts[0], "hex");
    const encryptedText = parts[1];

    const decipher = crypto.createDecipheriv("aes-256-cbc", symmetricKey, iv);
    let decryptedContent = decipher.update(encryptedText, "hex", "utf8");
    decryptedContent += decipher.final("utf8");

    // Integrity hash
    const currentHash = crypto.createHash("sha256").update(decryptedContent, "utf8").digest("hex");

    // Signature verify (hash üzerinden!)
    const verify = crypto.createVerify("RSA-SHA256");
    verify.update(currentHash, "utf8");
    verify.end();
    const isVerified = verify.verify(message.sender.publicKey, message.digitalSignature, "base64");

    res.json({
      content: decryptedContent,
      sender: message.sender.username,
      isSignatureValid: isVerified,
      isIntegrityIntact: currentHash === message.messageHash,
      originalDate: message.createdAt,
    });
  } catch (error) {
    console.error("Decryption error:", error);
    res.status(500).json({ error: "Decryption failed." });
  }
});

module.exports = router;
