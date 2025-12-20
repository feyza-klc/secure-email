require("dotenv").config();
const express = require("express");
const path = require("path");
const connectDB = require("./config/db");
const authRoutes = require("./routes/auth");

const app = express();
const PORT = process.env.PORT || 3000;

connectDB();

// Parse form data and JSON once
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Serve static files from /public
app.use(express.static(path.join(__dirname, "..", "public")));

// Auth routes
app.use("/api/auth", authRoutes);

// Default route
app.get("/", (req, res) => {
  res.redirect("/login.html");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
