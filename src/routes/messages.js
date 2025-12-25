const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const User = require("../models/User");
const Message = require("../models/Message");

console.log("✅ Messages route dosyası yüklendi!");
// DEBUG MODE
router.post("/send", async (req, res) => {
  console.log("--- 1. MESAJ GÖNDERME İSTEĞİ GELDİ ---");
  console.log("Gelen Veri:", req.body);

  try {
    const { senderUsername, recipientUsername, content } = req.body;

    // 1.Find Sender and Recipient
    const sender = await User.findOne({ username: senderUsername }).select("+privateKey");
    const recipient = await User.findOne({ username: recipientUsername });

    if (!sender) {
      console.log("HATA: Gönderici bulunamadı:", senderUsername);
      return res.status(404).send("Sender not found.");
    }
    if (!recipient) {
      console.log("HATA: Alıcı bulunamadı:", recipientUsername);
      return res.status(404).send("Recipient not found.");
    }

    console.log("--- 2. KULLANICILAR BULUNDU ---");
    console.log("Gönderici:", sender.username);
    console.log("Alıcı:", recipient.username);

    // Control: Recipient has Public Key
    if (!recipient.publicKey) {
      console.log("KRİTİK HATA: Alıcının Public Key'i (Açık Anahtarı) YOK!");
      return res.status(400).send("Recipient has no public key. Cannot encrypt.");
    }

    // CONFIDENTIALITY
    console.log("--- 3. ŞİFRELEME BAŞLIYOR ---");

    // 2. Create Symmetric Key (AES) 
    const symmetricKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16); 

    // 3. Decrypt Message with Symmetric Key (AES)
    const cipher = crypto.createCipheriv("aes-256-cbc", symmetricKey, iv);
    let encryptedContent = cipher.update(content, "utf8", "hex");
    encryptedContent += cipher.final("hex");
    
    const finalEncryptedMessage = iv.toString("hex") + ":" + encryptedContent;

    // 4. Decrypt Symeetric Key with Recipient's Public Key (RSA)
    const encryptedSymmetricKey = crypto.publicEncrypt(
      {
        key: recipient.publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      symmetricKey
    ).toString("base64");

    // Signature and Hashing
    console.log("--- 4. İMZALAMA BAŞLIYOR ---");

    // 5. Hashing
    const hash = crypto.createHash("sha256").update(content).digest("hex");

    // 6. Signature
    const sign = crypto.createSign("SHA256");
    sign.update(content);
    sign.end();
    const signature = sign.sign(sender.privateKey, "base64");

    console.log("--- 5. VERİTABANI MODELİ OLUŞTURULUYOR ---");

    // 7. Save to Database 
    const newMessage = new Message({
      sender: sender._id,
      recipient: recipient._id,
      encryptedMessage: finalEncryptedMessage,
      encryptedSymmetricKey: encryptedSymmetricKey,
      messageHash: hash,
      digitalSignature: signature,
    });

    console.log("--- 6. SAVE() ÇAĞRILIYOR ---");
    const savedMessage = await newMessage.save();
    console.log("✅ BAŞARILI! Mesaj ID:", savedMessage._id);

    res.json({ success: true, messageId: savedMessage._id });

  } catch (error) {
    console.error("❌ SUNUCU HATASI (DETAYLI):", error);
    res.status(500).send("Error sending message: " + error.message);
  }
});

//  Inbox
router.get("/inbox", async (req, res) => {
  try {
    const { username } = req.query;
    console.log(`Inbox isteniyor: ${username}`);
    
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: "User not found" });

    const messages = await Message.find({ recipient: user._id })
      .populate("sender", "username publicKey")
      .sort({ createdAt: -1 });

    console.log(`Bulunan mesaj sayısı: ${messages.length}`);
    res.json(messages);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});

//  Read Message
router.post("/decrypt", async (req, res) => {
  try {
    const { messageId, username } = req.body;
    const message = await Message.findById(messageId).populate("sender", "username publicKey");
    const recipient = await User.findOne({ username }).select("+privateKey");

    if (!message || !recipient) {
      return res.status(404).json({ error: "Message or User not found" });
    }

    const encryptedKeyBuffer = Buffer.from(message.encryptedSymmetricKey, "base64");
    
    // Decrypt Key
    const symmetricKey = crypto.privateDecrypt(
      {
        key: recipient.privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      encryptedKeyBuffer
    );

    // Decrypt Content
    const parts = message.encryptedMessage.split(":");
    const iv = Buffer.from(parts[0], "hex");
    const encryptedText = parts[1];

    const decipher = crypto.createDecipheriv("aes-256-cbc", symmetricKey, iv);
    let decryptedContent = decipher.update(encryptedText, "hex", "utf8");
    decryptedContent += decipher.final("utf8");

    // Verify
    const verify = crypto.createVerify("SHA256");
    verify.update(decryptedContent);
    verify.end();
    const isVerified = verify.verify(message.sender.publicKey, message.digitalSignature, "base64");
    
    const currentHash = crypto.createHash("sha256").update(decryptedContent).digest("hex");

    res.json({
      content: decryptedContent,
      sender: message.sender.username,
      isSignatureValid: isVerified,
      isIntegrityIntact: (currentHash === message.messageHash),
      originalDate: message.createdAt
    });

  } catch (error) {
    console.error("Decryption error:", error);
    res.status(500).json({ error: "Decryption failed." });
  }
});

module.exports = router;