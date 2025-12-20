const mongoose = require("mongoose");

const MessageSchema = new mongoose.Schema({
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },

  encryptedMessage: String,     // AES ile şifrelenmiş mesaj
  encryptedSymmetricKey: String,// RSA ile şifrelenmiş AES key

  messageHash: String,          // SHA-256 hash
  digitalSignature: String,     // Sender private key ile atılmış imza

  createdAt: {
    type: Date,
    default: Date.now
  }
});
