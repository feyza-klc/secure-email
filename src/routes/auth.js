const express = require("express");
const router = express.Router();
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

// Generate RSA public/private key pair
function generateRsaKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

// Helper: send alert + redirect (HTML response)
function alertAndRedirect(res, message, path) {
  return res.send(
    `<script>alert(${JSON.stringify(message)}); window.location.href=${JSON.stringify(
      path
    )};</script>`
  );
}

// ================= REGISTER =================
router.post("/register", async (req, res) => {
  console.log("--> REGISTER request. Body:", req.body);

  const { username, password, confirmPassword } = req.body;

  try {
    // Basic validation
    if (!username || !password || !confirmPassword) {
      return alertAndRedirect(
        res,
        "Username, password and confirm password are required.",
        "/register.html"
      );
    }

    // Password match check
    if (password !== confirmPassword) {
      console.log("--> ERROR: Passwords do not match.");
      return alertAndRedirect(res, "Passwords do not match.", "/register.html");
    }

    // Check if username exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      console.log("--> ERROR: Username already taken:", username);
      return alertAndRedirect(res, "This username is already taken.", "/register.html");
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate RSA keys for this user
    const { publicKey, privateKey } = generateRsaKeyPair();

    // Create user (store keys in DB)
    const newUser = new User({
      username,
      password: hashedPassword,
      publicKey,
      privateKey,
    });

    console.log("--> Saving user to database...");
    const savedUser = await newUser.save();
    console.log("--> SUCCESS! Saved user:", savedUser.username);

    // Redirect to login page after successful registration
    return res.redirect("/login.html");
  } catch (err) {
    console.error("--> SERVER ERROR:", err);
    return alertAndRedirect(res, "An unexpected error occurred.", "/register.html");
  }
});

// ================= LOGIN =================
router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  console.log("--> LOGIN request:", username);

  try {
    if (!username || !password) {
      return alertAndRedirect(res, "Username and password are required.", "/login.html");
    }

    const user = await User.findOne({ username }).select("+privateKey");

    if (!user) {
      console.log("--> ERROR: User not found.");
      return alertAndRedirect(res, "User not found.", "/login.html");
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log("--> ERROR: Wrong password.");
      return alertAndRedirect(res, "Invalid username or password.", "/login.html");
    }

    console.log("--> LOGIN SUCCESS.");

 
return res.redirect(303, `/home.html?u=${encodeURIComponent(user.username)}`);
    

  } catch (err) {
    console.error("--> SERVER ERROR:", err);
    return alertAndRedirect(res, "An unexpected error occurred.", "/login.html");
  }
});

module.exports = router;
