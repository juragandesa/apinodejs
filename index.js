const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

// Konfigurasi koneksi database
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

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

    try {
        // Periksa apakah username sudah ada
        const [existingUser] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
        if (existingUser.length > 0) {
            return res.status(400).json({ message: 'Username sudah digunakan.' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Simpan pengguna ke database
        await db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);

        res.status(201).json({ message: 'Pengguna berhasil terdaftar.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Terjadi kesalahan server.' });
    }
});

// Login pengguna
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Cari pengguna berdasarkan username
        const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
        const user = rows[0];

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
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Terjadi kesalahan server.' });
    }
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
app.get('/profile', authenticate, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT id, username FROM users WHERE id = ?', [req.user.id]);
        const user = rows[0];

        if (!user) {
            return res.status(404).json({ message: 'Pengguna tidak ditemukan.' });
        }

        res.status(200).json({ message: 'Profil pengguna.', user });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Terjadi kesalahan server.' });
    }
});

// Update pengguna
app.put('/update', authenticate, async (req, res) => {
    const { username, password } = req.body;

    // Validasi input
    if (!username && !password) {
        return res.status(400).json({ message: 'Username atau password harus diisi untuk diperbarui.' });
    }

    try {
        // Siapkan nilai-nilai yang akan diperbarui
        const updates = [];
        const params = [];

        if (username) {
            // Periksa apakah username sudah digunakan
            const [existingUser] = await db.query('SELECT * FROM users WHERE username = ? AND id != ?', [username, req.user.id]);
            if (existingUser.length > 0) {
                return res.status(400).json({ message: 'Username sudah digunakan.' });
            }
            updates.push('username = ?');
            params.push(username);
        }

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            updates.push('password = ?');
            params.push(hashedPassword);
        }

        // Tambahkan ID pengguna untuk kondisi WHERE
        params.push(req.user.id);

        // Perbarui pengguna
        const query = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;
        await db.query(query, params);

        res.status(200).json({ message: 'Data pengguna berhasil diperbarui.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Terjadi kesalahan server.' });
    }
});

// Delete pengguna
app.delete('/delete', authenticate, async (req, res) => {
    try {
        // Hapus pengguna berdasarkan ID
        await db.query('DELETE FROM users WHERE id = ?', [req.user.id]);

        res.status(200).json({ message: 'Pengguna berhasil dihapus.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Terjadi kesalahan server.' });
    }
});

// Mendapatkan daftar semua pengguna
app.get('/users', authenticate, async (req, res) => {
    try {
        // Ambil semua data pengguna dari database
        const [rows] = await db.query('SELECT id, username, created_at FROM users');
        res.status(200).json({ message: 'Daftar pengguna.', users: rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Terjadi kesalahan server.' });
    }
});


// Jalankan server
app.listen(process.env.PORT, () => {
    console.log(`Server berjalan di http://localhost:${process.env.PORT}`);
});
