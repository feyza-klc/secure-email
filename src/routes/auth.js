const express = require("express");
const router = express.Router();
const User = require("../models/User");
const bcrypt = require("bcryptjs");

// Register route
router.post("/register", async (req, res) => {
  // 1. Log: İstek geldi mi?
  console.log("--> REGISTER İSTEĞİ GELDİ. Body:", req.body);
  
  const { username, password, confirmPassword } = req.body;

  try {
    // Şifre eşleşme kontrolü
    if (password !== confirmPassword) {
        console.log("--> HATA: Şifreler uyuşmadı.");
        return res.send('<script>alert("Şifreler uyuşmuyor!"); window.location.href="/register.html";</script>');
    }

    // Kullanıcı zaten var mı?
    const existingUser = await User.findOne({ username });
    if (existingUser) {
        console.log("--> HATA: Kullanıcı zaten var:", username);
        return res.send('<script>alert("Bu kullanıcı adı zaten alınmış."); window.location.href="/register.html";</script>');
    }

    // Şifreleme
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Model oluşturma
    const newUser = new User({ username, password: hashedPassword });
    
    // 2. Log: Kayıt öncesi
    console.log("--> Veritabanına kaydediliyor...");
    
    // KAYIT İŞLEMİ
    const savedUser = await newUser.save();

    // 3. Log: Kayıt başarılı
    console.log("--> BAŞARILI! Kaydedilen Kullanıcı:", savedUser);

    // Login sayfasına yönlendir
    res.redirect("/login.html");

  } catch (err) {
    console.error("--> SUNUCU HATASI:", err);
    res.status(500).send("Server error: " + err.message);
  }
});

// Login route
router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  console.log("--> LOGIN İSTEĞİ GELDİ:", username);

  try {
    const user = await User.findOne({ username });
    
    if (!user) {
        console.log("--> HATA: Kullanıcı bulunamadı.");
        return res.send('<script>alert("Kullanıcı bulunamadı!"); window.location.href="/login.html";</script>');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        console.log("--> HATA: Yanlış şifre.");
        return res.send('<script>alert("Şifre hatalı!"); window.location.href="/login.html";</script>');
    }

    console.log("--> LOGIN BAŞARILI.");
    res.send(`<h1>Hoşgeldin ${username}!</h1><p>Giriş başarılı.</p>`);
    
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

module.exports = router;