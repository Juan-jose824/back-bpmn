const express = require('express');
const cors = require('cors');
const pool = require('./db');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

// --- LOGIN ---
app.post('/api/login', async (req, res) => {
    const {email, pass} = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado'});
        
        const usuario = result.rows[0];
        const validPassword = await bcrypt.compare(pass, usuario.pass);

        if (!validPassword) return res.status(401).json({error: 'Contraseña incorrecta'});

        const { pass: _, ...datosUsuario} = usuario;
        res.json(datosUsuario);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error en el servidor'});
    }
});

// --- REGISTRAR USUARIO ---
app.post('/api/register', async (req, res) => {
    const { username, email, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (user_name, email, pass, rol) VALUES ($1, $2, $3, $4) RETURNING user_name, email, rol';
        const result = await pool.query(query, [username, email, hashedPassword, role]);
        res.status(201).json({ message: 'Usuario creado', user: result.rows[0] });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'Email ya registrado' });
        res.status(500).json({ error: 'Error al registrar' });
    }
});

// --- OBTENER USUARIOS ---
app.get('/api/users', async (req, res) => {
    try {
        const result = await pool.query('SELECT user_name, email, rol, fecha_registro FROM users ORDER BY fecha_registro DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener usuarios' });
    }
});

// --- ELIMINAR USUARIO (NUEVO) ---
app.delete('/api/users/:username', async (req, res) => {
    const { username } = req.params;
    try {
        const result = await pool.query('DELETE FROM users WHERE user_name = $1', [username]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        res.json({ message: 'Usuario eliminado con éxito' });
    } catch (err) {
        res.status(500).json({ error: 'Error al eliminar usuario' });
    }
});

// --- ACTUALIZAR USUARIO (NUEVO) ---
app.put('/api/users/:username', async (req, res) => {
    const { username } = req.params; // El nombre original para buscarlo
    const { new_username, role } = req.body; // Los nuevos datos
    try {
        const query = 'UPDATE users SET user_name = $1, rol = $2 WHERE user_name = $3 RETURNING *';
        const result = await pool.query(query, [new_username || username, role, username]);
        res.json({ message: 'Usuario actualizado', user: result.rows[0] });
    } catch (err) {
        res.status(500).json({ error: 'Error al actualizar usuario' });
    }
});

app.listen(3000, () => console.log('Servidor en http://localhost:3000'));