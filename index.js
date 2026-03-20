require('dotenv').config();
const express = require('express');
const cors = require('cors');
const pool = require('./db');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

// --- LIBRERÍAS PARA EL PUENTE DE IA ---
const axios = require('axios');
const FormData = require('form-data');
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });

// --- CONFIGURACIÓN DE SEGURIDAD (8 HORAS) ---
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'access_secret_super_seguro';
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'refresh_secret_super_seguro';

const ACCESS_EXPIRES = '8h'; 
const REFRESH_EXPIRES = '8h'; 

function expiresToMs(s) {
    const n = parseInt(s, 10);
    if (s.endsWith('m')) return n * 60 * 1000;
    if (s.endsWith('h')) return n * 60 * 60 * 1000;
    if (s.endsWith('d')) return n * 24 * 60 * 60 * 1000;
    return 8 * 60 * 60 * 1000; 
}
const REFRESH_COOKIE_MAX_AGE = expiresToMs(REFRESH_EXPIRES);

const app = express();

// --- MIDDLEWARES ---
app.use(cors({
    origin: 'http://localhost',
    credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(cookieParser());

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
app.use('/uploads', express.static(uploadDir));

// --- MIDDLEWARE DE AUTENTICACIÓN ---
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

// ==========================================
// 1. RUTA PUENTE IA
// ==========================================
app.post('/api/ai/analyze', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No se recibió el archivo PDF' });
        const form = new FormData();
        form.append('file', req.file.buffer, { filename: req.file.originalname, contentType: req.file.mimetype });

        const aiResponse = await axios.post('http://ai-service:4000/analyze', form, {
            headers: { ...form.getHeaders() },
            timeout: 0,
            maxContentLength: Infinity,
            maxBodyLength: Infinity
        });
        res.json(aiResponse.data);
    } catch (error) {
        res.status(500).json({ error: 'Error en servicio de IA' });
    }
});

// ==========================================
// 2. RUTAS DE AUTENTICACIÓN
// ==========================================
app.post('/api/login', async (req, res) => {
    const { email, pass } = req.body;
    try {
        const result = await pool.query('SELECT id_user, user_name, email, pass, rol, profile_image FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

        const usuario = result.rows[0];
        const validPassword = await bcrypt.compare(pass, usuario.pass);
        if (!validPassword) return res.status(401).json({ error: 'Contraseña incorrecta' });

        const payload = { 
            id: usuario.id_user, 
            username: usuario.user_name, 
            rol: usuario.rol,
            profile_image: usuario.profile_image 
        };
        const accessToken = jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES });
        const refreshToken = jwt.sign(payload, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES });

        res.cookie('refreshToken', refreshToken, { 
            httpOnly: true, secure: false, sameSite: 'strict', maxAge: REFRESH_COOKIE_MAX_AGE 
        });

        res.json({ accessToken, user: payload });
    } catch (err) {
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// Ruta para refrescar token
app.post('/api/refresh', (req, res) => {
    const token = req.cookies.refreshToken;
    if (!token) return res.status(401).json({ error: 'No refresh token' });

    jwt.verify(token, REFRESH_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Sesión expirada' });
        const payload = { id: user.id, username: user.username, rol: user.rol, profile_image: user.profile_image };
        const newAccessToken = jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES });
        res.json({ accessToken: newAccessToken });
    });
});

// Ruta para logout
app.post('/api/logout', (req, res) => {
    res.clearCookie('refreshToken', { httpOnly: true, secure: false, sameSite: 'strict' });
    res.sendStatus(204);
});

// ==========================================
// 3. GESTIÓN DE USUARIOS (CORREGIDO)
// ==========================================
app.post('/api/register', async (req, res) => {
    const { username, email, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (user_name, email, pass, rol) VALUES ($1, $2, $3, $4) RETURNING user_name, email, rol',
            [username, email, hashedPassword, role]
        );
        res.status(201).json({ message: 'Usuario creado', user: result.rows[0] });
    } catch (err) {
        res.status(500).json({ error: 'Error al registrar' });
    }
});

// Ruta para obtener todos los usuarios
app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT id_user, user_name, email, rol, fecha_registro FROM users ORDER BY fecha_registro DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener usuarios' });
    }
});

// Ruta para actualizar usuario (Soluciona error al editar)
app.put('/api/users/:username', authenticateToken, async (req, res) => {
    const { username } = req.params;
    const { new_username, email, role, password } = req.body;

    try {
        let query = 'UPDATE users SET user_name = $1, email = $2, rol = $3';
        let params = [new_username, email, role, username];

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            query += ', pass = $5 WHERE user_name = $4';
            params.push(hashedPassword);
        } else {
            query += ' WHERE user_name = $4';
        }

        const result = await pool.query(query, params);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        
        res.json({ message: 'Usuario actualizado correctamente' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al actualizar usuario' });
    }
});

//Ruta para eliminar usuario (Soluciona el error 404 del log)
app.delete('/api/users/:identifier', authenticateToken, async (req, res) => {
    const { identifier } = req.params;
    try {
        // Borra por ID o por nombre de usuario
        const result = await pool.query(
            'DELETE FROM users WHERE id_user::text = $1 OR user_name = $1 RETURNING *',
            [identifier]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        res.json({ message: 'Usuario eliminado correctamente' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al eliminar usuario' });
    }
});

// ==========================================
// 4. HISTORIAL Y ELIMINACIÓN DE ANÁLISIS
// ==========================================
app.post('/api/delete-analysis', authenticateToken, async (req, res) => {
    const { ids } = req.body; 
    const userId = req.user.id;
    if (!ids || !Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'No se enviaron IDs válidos' });

    try {
        const result = await pool.query('DELETE FROM ai_analysis WHERE id_analysis = ANY($1) AND id_user = $2', [ids, userId]);
        res.json({ message: 'Eliminado correctamente', rowCount: result.rowCount });
    } catch (err) {
        res.status(500).json({ error: 'Error interno al eliminar' });
    }
});

// Ruta para guardar análisis
app.post('/api/save-analysis', authenticateToken, async (req, res) => {
    const { file_name, markdown_content, bpmn_xml } = req.body;
    const user_id = req.user.id; 
    try {
        const query = `INSERT INTO ai_analysis (id_user, file_name, markdown_content, bpmn_xml) VALUES ($1, $2, $3, $4) RETURNING *`;
        const result = await pool.query(query, [user_id, file_name, markdown_content, bpmn_xml]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Error al guardar' });
    }
});

// Ruta para obtener historial de análisis
app.get('/api/my-history', authenticateToken, async (req, res) => {
    const user_id = req.user.id;
    try {
        const query = `SELECT * FROM ai_analysis WHERE id_user = $1 ORDER BY fecha_creacion DESC`;
        const result = await pool.query(query, [user_id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener historial' });
    }
});

// ============================================================
// ACTUALIZACIÓN DE IMAGEN DE PERFIL
// ============================================================
app.put('/api/users/:username/profile-image', authenticateToken, async (req, res) => {
    const { username } = req.params;
    const { image } = req.body;

    if (!image) return res.status(400).json({ error: 'No se recibió ninguna imagen' });

    try {
        const matches = image.match(/^data:image\/([A-Za-z-+\/]+);base64,(.+)$/);
        if (!matches || matches.length !== 3) return res.status(400).json({ error: 'Formato inválido' });

        const extension = matches[1] === 'jpeg' ? 'jpg' : matches[1];
        const imageData = Buffer.from(matches[2], 'base64');
        const fileName = `profile_${username}_${Date.now()}.${extension}`;
        const filePath = path.join(uploadDir, fileName);

        fs.writeFileSync(filePath, imageData);

        const result = await pool.query(
            'UPDATE users SET profile_image = $1 WHERE user_name = $2 RETURNING profile_image',
            [fileName, username]
        );

        if (result.rowCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

        res.json({ message: 'Éxito', fileName: fileName });
    } catch (err) {
        res.status(500).json({ error: 'Error en servidor' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend Bridge iniciado en puerto ${PORT}`));