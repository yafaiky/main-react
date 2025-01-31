const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const PORT = 5000;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Konfigurasi database
const db = mysql.createConnection({
  host: "localhost",        // Host database
  user: "root",             // User database Anda
  password: "",             // Password database Anda
  database: "login_system", // Nama database
});

// Cek koneksi database
db.connect((err) => {
  if (err) {
    console.error("Gagal terhubung ke database:", err.message);
    return;
  }
  console.log("Terhubung ke database!");
});

// Endpoint untuk registrasi
app.post("/register", (req, res) => {
  const { name, email, password } = req.body;

  // Hash password sebelum menyimpan ke database
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ message: "Error hashing password." });

    const query = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
    db.query(query, [name, email, hashedPassword], (err, results) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") {
          return res.status(400).json({ message: "Email sudah terdaftar." });
        }
        return res.status(500).json({ message: "Error saat menyimpan data." });
      }
      res.status(201).json({ message: "Registrasi berhasil!" });
    });
  });
});

// Endpoint untuk login
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const query = "SELECT * FROM users WHERE email = ?";
  db.query(query, [email], (err, results) => {
    if (err) return res.status(500).json({ message: "Error query database." });
    if (results.length === 0) return res.status(404).json({ message: "Email tidak ditemukan." });

    const user = results[0];

    // Verifikasi password
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) return res.status(500).json({ message: "Error memverifikasi password." });
      if (!isMatch) return res.status(401).json({ message: "Password salah." });

      // Jika login berhasil, buat token JWT
      const token = jwt.sign({ id: user.id }, "secret_key", { expiresIn: "1h" });
      res.status(200).json({ message: "Login berhasil!", token });
    });
  });
});

// Jalankan server
app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});
