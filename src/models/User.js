const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },

  // bcrypt hash
  password: { type: String, required: true },

  createdAt: { type: Date, default: Date.now },

  publicKey: { type: String, default: "" },

  // ✅ encrypted private key pack (AES-256-GCM)
  encPrivateKey: { type: String, default: "", select: false },
  privKeySalt:   { type: String, default: "", select: false },
  privKeyIv:     { type: String, default: "", select: false },
  privKeyTag:    { type: String, default: "", select: false },
});

module.exports = mongoose.model("User", userSchema);
