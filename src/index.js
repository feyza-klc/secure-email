require("dotenv").config();
const express = require("express");
const path = require("path");
const connectDB = require("./config/db");
const authRoutes = require("./routes/auth"); // Auth route
const bodyParser = require("body-parser");

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB bağlantısı
connectDB();

// Body parser
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Statik dosyalar (HTML/CSS)
app.use(express.static(path.join(__dirname, "..", "public")));

// Auth route
app.use("/api/auth", authRoutes);

// Ana route
app.get("/", (req, res) => {
  res.redirect("/login.html");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
