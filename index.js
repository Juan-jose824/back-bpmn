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

// --- CONFIGURACIÓN DE SEGURIDAD (8 Horas) ---
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'access_secret_super_seguro';
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'refresh_secret_super_seguro';

// Definimos 8 horas para los tokens (8h)
const ACCESS_EXPIRES = '8h'; 
const REFRESH_EXPIRES = '8h'; 

function expiresToMs(s) {
    const n = parseInt(s, 10);
    if (s.endsWith('m')) return n * 60 * 1000;
    if (s.endsWith('h')) return n * 60 * 60 * 1000;
    if (s.endsWith('d')) return n * 24 * 60 * 60 * 1000;
    return 8 * 60 * 60 * 1000; // Por defecto 8 horas
}
const REFRESH_COOKIE_MAX_AGE = expiresToMs(REFRESH_EXPIRES);

const app = express();

// --- MIDDLEWARES ---
app.use(cors({
    origin: 'http://localhost', // Origen de tu frontend en Docker
    credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(cookieParser());

// Carpeta de archivos estáticos
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
// 1. RUTA PUENTE (PROXY) PARA LA IA
// ==========================================
app.post('/api/ai/analyze', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No se recibió el archivo PDF' });

        const form = new FormData();
        form.append('file', req.file.buffer, {
            filename: req.file.originalname,
            contentType: req.file.mimetype,
        });

        const aiResponse = await axios.post('http://ai-service:4000/analyze', form, {
            headers: { ...form.getHeaders() },
            timeout: 0,
            maxContentLength: Infinity,
            maxBodyLength: Infinity
        });

        res.json(aiResponse.data);
    } catch (error) {
        console.error('Error en el puente de IA');
        const status = error.response?.status || 500;
        res.status(status).json(error.response?.data || { error: 'Error en servicio de IA' });
    }
});

// ==========================================
// 2. RUTAS DE AUTENTICACIÓN
// ==========================================
app.post('/api/login', async (req, res) => {
    const { email, pass } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

        const usuario = result.rows[0];
        const validPassword = await bcrypt.compare(pass, usuario.pass);
        if (!validPassword) return res.status(401).json({ error: 'Contraseña incorrecta' });

        const payload = { id: usuario.id_user, username: usuario.user_name, rol: usuario.rol };
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

// CORREGIDO: Ruta /api/refresh para coincidir con el Frontend
app.post('/api/refresh', (req, res) => {
    const token = req.cookies.refreshToken;
    if (!token) return res.status(401).json({ error: 'No refresh token' });

    jwt.verify(token, REFRESH_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Sesión expirada' });
        const payload = { id: user.id, username: user.username, rol: user.rol };
        const newAccessToken = jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES });
        res.json({ accessToken: newAccessToken });
    });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('refreshToken', { httpOnly: true, secure: false, sameSite: 'strict' });
    res.sendStatus(204);
});

// ==========================================
// 3. GESTIÓN DE USUARIOS
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

app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT id_user, user_name, email, rol, fecha_registro FROM users ORDER BY fecha_registro DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener usuarios' });
    }
});

// ==========================================
// 4. HISTORIAL Y ELIMINACIÓN
// ==========================================

// RUTA PARA ELIMINAR ANÁLISIS (Usa id_analysis y id_user del token)
app.post('/api/delete-analysis', authenticateToken, async (req, res) => {
    const { ids } = req.body; 
    const userId = req.user.id;

    if (!ids || !Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ error: 'No se enviaron IDs válidos' });
    }

    try {
        const query = 'DELETE FROM ai_analysis WHERE id_analysis = ANY($1) AND id_user = $2';
        await pool.query(query, [ids, userId]);
        res.json({ message: 'Eliminado correctamente' });
    } catch (err) {
        console.error('Error en delete-analysis:', err);
        res.status(500).json({ error: 'Error interno al eliminar' });
    }
});app.post('/api/delete-analysis', authenticateToken, async (req, res) => {
    const { ids } = req.body; 
    const userId = req.user.id;

    console.log(`Intentando borrar IDs: ${ids} para el usuario: ${userId}`);

    try {
        // Ejecutamos la consulta
        const result = await pool.query(
            'DELETE FROM ai_analysis WHERE id_analysis = ANY($1) AND id_user = $2',
            [ids, userId]
        );
        
        console.log(`Filas eliminadas en la DB: ${result.rowCount}`);

        if (result.rowCount === 0) {
            return res.status(200).json({ 
                message: 'No se borró nada. Verifica si los IDs pertenecen al usuario.',
                rowCount: 0 
            });
        }

        res.json({ message: 'Eliminado correctamente', rowCount: result.rowCount });
    } catch (err) {
        console.error('Error en el query de eliminación:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.post('/api/save-analysis', authenticateToken, async (req, res) => {
    const { file_name, markdown_content, bpmn_xml } = req.body;
    const user_id = req.user.id; 
    try {
        const query = `
            INSERT INTO ai_analysis (id_user, file_name, markdown_content, bpmn_xml)
            VALUES ($1, $2, $3, $4) RETURNING *`;
        const result = await pool.query(query, [user_id, file_name, markdown_content, bpmn_xml]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Error al guardar' });
    }
});

app.get('/api/my-history', authenticateToken, async (req, res) => {
    const user_name = req.user.username;
    try {
        const query = `
            SELECT a.* FROM ai_analysis a
            JOIN users u ON a.id_user = u.id_user
            WHERE u.user_name = $1
            ORDER BY a.fecha_creacion DESC`;
        const result = await pool.query(query, [user_name]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener historial' });
    }
});

// Inicio del servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend Bridge iniciado en puerto ${PORT}`));