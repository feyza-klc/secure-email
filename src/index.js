require("dotenv").config();
const express = require("express");
const path = require("path");
const connectDB = require("./config/db");

const app = express();
const PORT = 3000;

// MongoDB bağlantısı
connectDB();

// Serve static HTML/CSS
app.use(express.static(path.join(__dirname, "..", "public")));

app.get("/", (req, res) => {
  res.redirect("/login.html");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
