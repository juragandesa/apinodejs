const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

// Data sementara untuk menyimpan pengguna
let users = [];

// Fungsi untuk membuat token JWT
const generateToken = (user) => {
    return jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, {
        expiresIn: '1h',
    });
};

// Registrasi pengguna
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Validasi input
    if (!username || !password) {
        return res.status(400).json({ message: 'Username dan password diperlukan.' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Simpan pengguna
    const user = { id: users.length + 1, username, password: hashedPassword };
    users.push(user);

    res.status(201).json({ message: 'Pengguna berhasil terdaftar.' });
});

// Login pengguna
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Cari pengguna berdasarkan username
    const user = users.find((u) => u.username === username);
    if (!user) {
        return res.status(404).json({ message: 'Pengguna tidak ditemukan.' });
    }

    // Periksa password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(401).json({ message: 'Password salah.' });
    }

    // Buat token JWT
    const token = generateToken(user);

    res.status(200).json({ message: 'Login berhasil.', token });
});

// Middleware untuk verifikasi token JWT
const authenticate = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ message: 'Token diperlukan.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token tidak valid.' });
        }

        req.user = decoded;
        next();
    });
};

// Endpoint yang membutuhkan autentikasi
app.get('/profile', authenticate, (req, res) => {
    res.status(200).json({ message: 'Profil pengguna.', user: req.user });
});

// Jalankan server
app.listen(process.env.PORT, () => {
    console.log(`Server berjalan di http://localhost:${process.env.PORT}`);
});
