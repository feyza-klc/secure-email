const express = require("express");
const path = require("path");

const app = express();
const PORT = 3000;

// Serve static HTML/CSS
app.use(express.static(path.join(__dirname, "..", "public")));

app.get("/", (req, res) => {
  res.redirect("/login.html");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
