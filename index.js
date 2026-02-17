const express = require('express');
const cors = require('cors');
const pool = require('./db');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json({limit: '10mb'}));

// Crear la carpeta 'uploads' si no existe
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir);
}

// + Hacer pública la carpeta para que el navegador acceda a las fotos
app.use('/uploads', express.static(uploadDir));



// LOGIN
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

// REGISTRAR USUARIO
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

// OBTENER USUARIOS
app.get('/api/users', async (req, res) => {
    try {
        const result = await pool.query('SELECT user_name, email, rol, fecha_registro FROM users ORDER BY fecha_registro DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener usuarios' });
    }
});

// ELIMINAR USUARIO
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

// ACTUALIZAR USUARIO
app.put('/api/users/:username', async (req, res) => {
    const { username } = req.params;
    const { new_username, role } = req.body;
    try {
        const query = 'UPDATE users SET user_name = $1, rol = $2 WHERE user_name = $3 RETURNING *';
        const result = await pool.query(query, [new_username || username, role, username]);
        res.json({ message: 'Usuario actualizado', user: result.rows[0] });
    } catch (err) {
        res.status(500).json({ error: 'Error al actualizar usuario' });
    }
});

// ACTUALIZAR IMAGEN DE PERFIL
app.put('/api/users/profile-image/:username', async (req, res) => {
    const { username } = req.params;
    const { imageBase64 } = req.body; 

    try {
        const base64Data = imageBase64.replace(/^data:image\/\w+;base64,/, "");
        const buffer = Buffer.from(base64Data, 'base64');

        const fileName = `profile-${username}-${Date.now()}.png`;
        const filePath = path.join(uploadDir, fileName);

        fs.writeFileSync(filePath, buffer);

        const query = 'UPDATE users SET profile_image = $1 WHERE user_name = $2 RETURNING profile_image';
        const result = await pool.query(query, [fileName, username]);
        
        if (result.rowCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

        res.json({ message: 'Imagen guardada', fileName: result.rows[0].profile_image });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al procesar imagen' });
    }
});

app.listen(3000, () => console.log('Servidor en http://localhost:3000'));