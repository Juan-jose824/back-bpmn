const express = require('express');
const cors = require('cors');
const pool = require('./db');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());
app.post('/api/login', async (req, res) => {
    const {email, pass} = req.body;

    try{
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado'});
        }

        const usuario = result.rows[0];

        const validPassword = await bcrypt.compare(pass, usuario.pass);

        if (!validPassword){
            return res.status(401).json({error: 'Contraseña incorrecta'});
        }

        const { pass: _, ...datosUsuario} = usuario;
        res.json(datosUsuario);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error en el servidor'});
    }
});

app.get('/', (req, res) => res.send('Servidor BPMN funcionando'));

app.listen(3000, () => console.log('Servidor en http://localhost:3000'));