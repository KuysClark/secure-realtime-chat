const express = require("express");
const helmet = require("helmet");
const pool = require("./db/pool");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const authRouters = require("./routers/authRouters");

const app = express();

// --- MIDDLEWARES ---
app.use(express.json()); // Accept JSON data
app.use(cors()); // Connect frontend even if different domain
app.use(helmet()); // Security headers
app.use(cookieParser()); // Remember session
app.use(express.urlencoded({ extended: true })); // Accept HTML form data

// --- ROUTES ---
app.use("/api/authRouters", authRouters);

// --- TEST ROUTE ---
app.get("/", (req, res) => {
  res.json({ message: "Hello world" });
});

pool.connect((err, client, release) => {
  if (err) {
    console.error("Error connecting to PostgreSQL:", err.stack);
  } else {
    console.log("PostgreSQL connected successfully!");
    release();
  }
});

// --- START SERVER ---
app.listen(process.env.PORT || 3000, () => {
  console.log("Server listening to port " + (process.env.PORT || 3000));
});
