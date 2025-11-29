const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const fs = require("fs");

const app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static("public"));

// Load users (plaintext password vulnerability)
let users = JSON.parse(fs.readFileSync("users.json", "utf8"));

// --- Middleware to check login (but weak) ---
function requireLogin(req, res, next) {
  // Vulnerability: No session validation, just checks cookie value
  if (req.cookies.session === "loggedin") {
    next();
  } else {
    next(); // <-- Big vulnerability: allows access without login!
  }
}

// --- Routes ---
app.get("/", (req, res) => {
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.render("login", { error: "" });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Weak authentication (plaintext file compare)
  if (users[username] && users[username] === password) {
    res.cookie("session", "loggedin"); // Vulnerable cookie (no secure/httponly)
    res.redirect("/messages");
  } else {
    res.render("login", { error: "Invalid credentials" });
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("session");
  res.redirect("/login");
});

// --- Message Board ---
app.get("/messages", requireLogin, (req, res) => {
  let messages = [];
  if (fs.existsSync("messages.txt")) {
    messages = fs.readFileSync("messages.txt", "utf8").split("\n").filter(Boolean);
  }

  // Vulnerability: Stored XSS - messages are not sanitized
  res.render("messages", { messages });
});

app.post("/messages", (req, res) => {
  const { msg } = req.body;

  // Vulnerability: No input validation, directly saved
  fs.appendFileSync("messages.txt", msg + "\n");

  res.redirect("/messages");
});

// --- Start Server ---
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
