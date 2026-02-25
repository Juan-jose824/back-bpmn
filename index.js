require('dotenv').config();
const express = require('express');
const cors = require('cors');
const pool = require('./db');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'access_secret_super_seguro';
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'refresh_secret_super_seguro';
const ACCESS_EXPIRES = process.env.JWT_ACCESS_EXPIRES || '15m';
const REFRESH_EXPIRES = process.env.JWT_REFRESH_EXPIRES || '30m';
// Convierte "30m", "1h", "7d" a milisegundos para la cookie
function expiresToMs(s) {
    const n = parseInt(s, 10);
    if (s.endsWith('m')) return n * 60 * 1000;
    if (s.endsWith('h')) return n * 60 * 60 * 1000;
    if (s.endsWith('d')) return n * 24 * 60 * 60 * 1000;
    return 30 * 60 * 1000;
}
const REFRESH_COOKIE_MAX_AGE = expiresToMs(REFRESH_EXPIRES);

const app = express();
app.use(cors({
    origin: 'http://localhost:4200',
    credentials: true
}));
app.use(express.json({limit: '10mb'}));
app.use(cookieParser());

// Crear la carpeta 'uploads' si no existe
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir);
}

// + Hacer pública la carpeta para que el navegador acceda a las fotos
app.use('/uploads', express.static(uploadDir));



// LOGIN (devuelve accessToken + user; refreshToken en cookie httpOnly)
app.post('/api/login', async (req, res) => {
    const { email, pass } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

        const usuario = result.rows[0];
        const validPassword = await bcrypt.compare(pass, usuario.pass);
        if (!validPassword) return res.status(401).json({ error: 'Contraseña incorrecta' });

        const payload = {
            id: usuario.id || usuario.user_name,
            username: usuario.user_name,
            rol: usuario.rol
        };

        const accessToken = jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES });
        const refreshToken = jwt.sign(payload, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES });

        const cookieOptions = { httpOnly: true, secure: false, sameSite: 'strict', maxAge: REFRESH_COOKIE_MAX_AGE };
        res.cookie('refreshToken', refreshToken, cookieOptions);

        res.json({
            accessToken,
            user: payload
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// REFRESH (lee refreshToken de la cookie; devuelve nuevo accessToken y renueva cookie = "actividad")
app.post('/api/refresh', (req, res) => {
    const token = req.cookies.refreshToken;
    if (!token) return res.status(401).json({ error: 'Refresh token no proporcionado' });

    jwt.verify(token, REFRESH_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Sesión expirada por inactividad' });
        const payload = { id: user.id, username: user.username, rol: user.rol };
        const newAccessToken = jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES });
        const newRefreshToken = jwt.sign(payload, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES });
        const cookieOptions = { httpOnly: true, secure: false, sameSite: 'strict', maxAge: REFRESH_COOKIE_MAX_AGE };
        res.cookie('refreshToken', newRefreshToken, cookieOptions);
        res.json({ accessToken: newAccessToken });
    });
});

// LOGOUT (borra la cookie refreshToken)
app.post('/api/logout', (req, res) => {
    const cookieOptions = { httpOnly: true, secure: false, sameSite: 'strict' };
    res.clearCookie('refreshToken', cookieOptions);
    res.sendStatus(204);
});

// Middleware: verifica JWT en header Authorization: Bearer <token>
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token no proporcionado' });
    jwt.verify(token, ACCESS_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido o expirado' });
        req.user = user;
        next();
    });
}

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

// OBTENER USUARIOS (protegido)
app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT user_name, email, rol, fecha_registro FROM users ORDER BY fecha_registro DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener usuarios' });
    }
});

// ELIMINAR USUARIO (protegido)
app.delete('/api/users/:username', authenticateToken, async (req, res) => {
    const { username } = req.params;
    try {
        const result = await pool.query('DELETE FROM users WHERE user_name = $1', [username]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        res.json({ message: 'Usuario eliminado con éxito' });
    } catch (err) {
        res.status(500).json({ error: 'Error al eliminar usuario' });
    }
});

// ACTUALIZAR USUARIO (protegido)
app.put('/api/users/:username', authenticateToken, async (req, res) => {
    const { username } = req.params;
    const { new_username, email, role, password } = req.body;

    try {
        let query;
        let params;

        if (password && password.trim() !== '') {
            const hashedPassword = await bcrypt.hash(password, 10);
            query = `UPDATE users 
                     SET user_name = $1, email = $2, rol = $3, pass = $4 
                     WHERE user_name = $5`;
            params = [new_username, email, role, hashedPassword, username];
        } else {
            query = `UPDATE users 
                     SET user_name = $1, email = $2, rol = $3 
                     WHERE user_name = $4`;
            params = [new_username, email, role, username];
        }

        const result = await pool.query(query, params);

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        res.json({ message: 'Usuario actualizado correctamente' });
    } catch (err) {
        console.error('--- ERROR DETALLADO ---');
        console.error(err); 
        res.status(500).json({ error: 'Error interno: ' + err.message });
    }
});

// ACTUALIZAR IMAGEN DE PERFIL (protegido)
app.put('/api/users/profile-image/:username', authenticateToken, async (req, res) => {
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Servidor en http://localhost:' + PORT));