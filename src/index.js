require("dotenv").config();
const express = require("express");
const path = require("path");
const connectDB = require("./config/db");
const authRoutes = require("./routes/auth");
const messageRoutes = require("./routes/messages"); 

const app = express();
const PORT = process.env.PORT || 3000;

connectDB();

// Parse form data and JSON once
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Serve static files
app.use(express.static(path.join(__dirname, "..", "public")));

// Auth routes
app.use("/api/auth", authRoutes);

// Message routes
app.use("/api/messages", messageRoutes); // <-- YENİ EKLENEN: Mesaj API'sini aktif ettik

// Default route
app.get("/", (req, res) => {
  res.redirect("/login.html");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
process.on("uncaughtException", (err) => {
  console.error("🔥 uncaughtException:", err);
});

process.on("unhandledRejection", (reason) => {
  console.error("🔥 unhandledRejection:", reason);
});
