const express = require("express");
const router = express.Router();
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { encryptPrivateKey } = require("../utils/cryptoKeys");

// Generate RSA public/private key pair
function generateRsaKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

function alertAndRedirect(res, message, path) {
  return res.send(
    `<script>alert(${JSON.stringify(message)}); window.location.href=${JSON.stringify(
      path
    )};</script>`
  );
}

// REGISTER
router.post("/register", async (req, res) => {
  console.log("--> REGISTER request. Body:", req.body);
  const { username, password, confirmPassword } = req.body;

  try {
    if (!username || !password || !confirmPassword) {
      return alertAndRedirect(
        res,
        "Username, password and confirm password are required.",
        "/register.html"
      );
    }

    if (password !== confirmPassword) {
      return alertAndRedirect(res, "Passwords do not match.", "/register.html");
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return alertAndRedirect(res, "This username is already taken.", "/register.html");
    }

    // Hash password (bcrypt)
    const hashedPassword = await bcrypt.hash(password, 10);

    // RSA keypair üret
    const { publicKey, privateKey } = generateRsaKeyPair();

    // ✅ Private key'i şifrele (AES-256-GCM, PBKDF2(password))
    const encPack = encryptPrivateKey(privateKey, password);

    // DB'ye publicKey + encrypted private key pack kaydet
    const newUser = new User({
      username,
      password: hashedPassword,
      publicKey,
      encPrivateKey: encPack.encPrivateKey,
      privKeySalt: encPack.privKeySalt,
      privKeyIv: encPack.privKeyIv,
      privKeyTag: encPack.privKeyTag,
    });

    await newUser.save();
    console.log("--> SUCCESS! Saved user:", newUser.username);

    return res.redirect("/login.html");
  } catch (err) {
    console.error("--> SERVER ERROR:", err);
    return alertAndRedirect(res, "An unexpected error occurred.", "/register.html");
  }
});

// LOGIN (burada private key'e gerek yok artık)
router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  console.log("--> LOGIN request:", username);

  try {
    if (!username || !password) {
      return alertAndRedirect(res, "Username and password are required.", "/login.html");
    }

    const user = await User.findOne({ username }); // +privateKey yok

    if (!user) {
      return alertAndRedirect(res, "User not found.", "/login.html");
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return alertAndRedirect(res, "Invalid username or password.", "/login.html");
    }

    return res.redirect(303, `/home.html?u=${encodeURIComponent(user.username)}`);
  } catch (err) {
    console.error("--> SERVER ERROR:", err);
    return alertAndRedirect(res, "An unexpected error occurred.", "/login.html");
  }
});

module.exports = router;
