const express = require('express');
const cors = require('cors');
const pool = require('./db');

const app = express();
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => res.send('Servidor BPMN funcionando'));

app.listen(3000, () => console.log('Servidor en http://localhost:3000'));