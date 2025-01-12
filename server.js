require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const cors = require('cors');
const morgan = require('morgan');

// Configuracion de la base de datos, se ocupan las credenciales que aparecen el el archivo .env
const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

const app = express();
app.use(express.json()); 
app.use(cors());
app.use(morgan('dev'));

function verificarToken(req, res, next) {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(403).json({ message: 'Acceso denegado, no se proporciona token' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ message: 'Token inválido o expirado' });
  }
}


// Ruta para registrar usuario
app.post('/usuarios', async (req, res) => {
  const { email, password, rol, lenguage } = req.body;
  if (!email || !password || !rol || !lenguage) {
    return res.status(400).json({ message: 'Todos los campos son obligatorios' });
  }

  try {
    const userExist = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (userExist.rows.length > 0) {
      return res.status(400).json({ message: 'El usuario ya existe :O' });
    }

    // bcrypt para encriptar la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await pool.query(
      'INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING *',
      [email, hashedPassword, rol, lenguage]
    );
    res.status(201).json({ message: 'Usuario registrado exitosamente :)', user: newUser.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al registrar el usuario :C' });
  }
});

// Ruta para hacer login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email y contraseña son obligatorios :O' });
  }

  try {
    const user = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(400).json({ message: 'Usuario no encontrado D:' });
    }

    // Verificar la contraseña que se encriptó
    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Contraseña incorrecta :O' });
    }

    // Firma dl token
    const token = jwt.sign({ email: user.rows[0].email }, process.env.JWT_SECRET, {
      expiresIn: '1h', // Puse que el token expira en 1 hora, pero puede cambiarse
    });

    res.status(200).json({ message: 'Login exitoso', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error en el login' });
  }
});


app.get('/usuarios', verificarToken, async (req, res) => {
  try {
    const user = await pool.query('SELECT * FROM usuarios WHERE email = $1', [req.user.email]);
    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado :O' });
    }

    res.status(200).json(user.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al obtener los datos del usuario D:' });
  }
});


app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: 'Algo salió mal en el servidor :O' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
