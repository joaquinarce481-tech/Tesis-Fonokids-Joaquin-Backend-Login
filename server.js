const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());

// Configuración PostgreSQL
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// Verificar conexión
pool.on('connect', () => {
  console.log('🗄️ Conectado a PostgreSQL - FonoKids');
});

pool.on('error', (err) => {
  console.error('❌ Error en PostgreSQL:', err);
});

// ✅ CONFIGURACIÓN CORREGIDA DE NODEMAILER
const emailTransporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // true para port 465, false para otros puertos
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  },
  tls: {
    rejectUnauthorized: false
  },
  connectionTimeout: 10000, // 10 segundos
  greetingTimeout: 10000,
  socketTimeout: 10000
});

// Verificar configuración de email al iniciar
emailTransporter.verify(function(error, success) {
  if (error) {
    console.log('❌ Error en configuración de email:', error);
  } else {
    console.log('✅ Servidor de email listo para enviar mensajes');
  }
});

// Función para generar código de 6 dígitos
function generateResetCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

const JWT_SECRET = process.env.JWT_SECRET || 'fonokids-super-secret-key-2024';
const SALT_ROUNDS = 10;

// Helper para ejecutar queries
async function executeQuery(query, params = []) {
  const client = await pool.connect();
  try {
    const result = await client.query(query, params);
    return result;
  } finally {
    client.release();
  }
}

// Middleware de autenticación JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token de acceso requerido' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
}

// 🔐 RUTAS DE AUTENTICACIÓN

// 1️⃣ LOGIN - Autenticar usuario
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log(`🔐 Intento de login: ${username}`);

    if (!username || !password) {
      return res.status(400).json({ 
        error: 'Usuario y contraseña son requeridos' 
      });
    }

    // Buscar usuario (podemos usar email o username)
    const query = `
      SELECT id_paciente, username, password_hash, email, nombre_completo 
      FROM pacientes 
      WHERE username = $1 OR email = $1
    `;
    const result = await executeQuery(query, [username]);

    if (result.rows.length === 0) {
      return res.status(401).json({ 
        error: 'Credenciales inválidas' 
      });
    }

    const user = result.rows[0];
    
    // Verificar contraseña
    if (!user.password_hash) {
      return res.status(401).json({ 
        error: 'Usuario sin contraseña configurada' 
      });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ 
        error: 'Credenciales inválidas' 
      });
    }

    // Generar token JWT
    const token = jwt.sign(
      { 
        userId: user.id_paciente, 
        username: user.username,
        email: user.email 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log(`✅ Login exitoso: ${user.username}`);
    
    res.json({
      message: 'Login exitoso',
      token,
      user: {
        id: user.id_paciente,
        username: user.username,
        email: user.email,
        name: user.nombre_completo
      }
    });

  } catch (error) {
    console.error('❌ Error en login:', error);
    res.status(500).json({ 
      error: 'Error interno del servidor' 
    });
  }
});

// 2️⃣ FORGOT PASSWORD - Solicitar código de recuperación
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    console.log(`🔑 Solicitud de recuperación para: ${email}`);

    if (!email) {
      return res.status(400).json({ 
        error: 'Email es requerido' 
      });
    }

    // Verificar que el usuario existe
    const userQuery = 'SELECT id_paciente, nombre_completo, email FROM pacientes WHERE email = $1';
    const userResult = await executeQuery(userQuery, [email]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({ 
        error: 'No se encontró una cuenta con ese email' 
      });
    }

    const user = userResult.rows[0];
    const resetCode = generateResetCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutos

    // Primero eliminar códigos anteriores del usuario
    const deleteOldCodesQuery = 'DELETE FROM password_reset_codes WHERE user_id = $1';
    await executeQuery(deleteOldCodesQuery, [user.id_paciente]);
    
    // Luego insertar el nuevo código
    const insertCodeQuery = `
      INSERT INTO password_reset_codes (user_id, email, reset_code, expires_at, used)
      VALUES ($1, $2, $3, $4, false)
    `;
    
    await executeQuery(insertCodeQuery, [user.id_paciente, email, resetCode, expiresAt]);

    // Enviar email con código
    const emailTemplate = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 15px;">
        <div style="background: white; padding: 30px; border-radius: 10px; text-align: center;">
          <h1 style="color: #4A90E2; margin-bottom: 20px;"> ¡FonoKids - Recuperar Contraseña! </h1>
          <p style="font-size: 18px; color: #333; margin-bottom: 20px;">
            ¡Hola <strong>${user.nombre_completo}</strong> 👋🏻!
          </p>
          <p style="color: #666; margin-bottom: 30px;">
            Recibimos una solicitud para restablecer tu contraseña. Usa el siguiente código:
          </p>
          
          <div style="background: #f0f8ff; border: 2px solid #4A90E2; border-radius: 10px; padding: 20px; margin: 20px 0;">
            <h2 style="color: #4A90E2; font-size: 32px; margin: 0; letter-spacing: 5px;">
              ${resetCode}
            </h2>
          </div>
          
          <p style="color: #e74c3c; font-weight: bold;">
            ⏰ Este código expira en 10 minutos
          </p>
          
          <p style="color: #666; font-size: 14px; margin-top: 30px;">
            Si no solicitaste este cambio, ignora este mensaje.
          </p>
          
          <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
            <p style="color: #999; font-size: 12px;">
              © 2024 FonoKids - Sistema de Fonoaudiología
            </p>
          </div>
        </div>
      </div>
    `;

    await emailTransporter.sendMail({
      from: `"FonoKids " <${process.env.EMAIL_USER}>`,
      to: email,
      subject: ' Código de Recuperación - FonoKids',
      html: emailTemplate
    });

    console.log(`✅ Código enviado a: ${email} (Código: ${resetCode})`);
    
    res.json({
      message: 'Código de recuperación enviado a tu email',
      expires_in_minutes: 10
    });

  } catch (error) {
    console.error('❌ Error enviando código:', error);
    res.status(500).json({ 
      error: 'Error enviando código de recuperación' 
    });
  }
});

// 3️⃣ VERIFY CODE - Verificar código de recuperación
app.post('/api/auth/verify-reset-code', async (req, res) => {
  try {
    const { email, code } = req.body;
    console.log(`🔍 Verificando código para: ${email}`);

    if (!email || !code) {
      return res.status(400).json({ 
        error: 'Email y código son requeridos' 
      });
    }

    // Verificar código
    const query = `
      SELECT * FROM password_reset_codes 
      WHERE email = $1 AND reset_code = $2 AND used = false 
      AND expires_at > NOW()
    `;
    
    const result = await executeQuery(query, [email, code]);

    if (result.rows.length === 0) {
      return res.status(400).json({ 
        error: 'Código inválido o expirado' 
      });
    }

    console.log('✅ Código verificado correctamente');
    
    res.json({
      message: 'Código verificado correctamente',
      valid: true
    });

  } catch (error) {
    console.error('❌ Error verificando código:', error);
    res.status(500).json({ 
      error: 'Error verificando código' 
    });
  }
});

// 4️⃣ RESET PASSWORD - Restablecer contraseña
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    console.log(`🔄 Restableciendo contraseña para: ${email}`);

    if (!email || !code || !newPassword) {
      return res.status(400).json({ 
        error: 'Todos los campos son requeridos' 
      });
    }

    // Verificar código nuevamente
    const verifyQuery = `
      SELECT user_id FROM password_reset_codes 
      WHERE email = $1 AND reset_code = $2 AND used = false 
      AND expires_at > NOW()
    `;
    
    const verifyResult = await executeQuery(verifyQuery, [email, code]);

    if (verifyResult.rows.length === 0) {
      return res.status(400).json({ 
        error: 'Código inválido o expirado' 
      });
    }

    const userId = verifyResult.rows[0].user_id;

    // Hashear nueva contraseña
    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

    // Actualizar contraseña
    const updateQuery = 'UPDATE pacientes SET password_hash = $1 WHERE id_paciente = $2';
    await executeQuery(updateQuery, [hashedPassword, userId]);

    // Marcar código como usado
    const markUsedQuery = 'UPDATE password_reset_codes SET used = true WHERE email = $1 AND reset_code = $2';
    await executeQuery(markUsedQuery, [email, code]);

    console.log(`✅ Contraseña actualizada para: ${email}`);
    
    res.json({
      message: 'Contraseña actualizada exitosamente',
      success: true
    });

  } catch (error) {
    console.error('❌ Error restableciendo contraseña:', error);
    res.status(500).json({ 
      error: 'Error al restablecer la contraseña' 
    });
  }
});

// 5️⃣ CREATE USER - Crear nuevo usuario
app.post('/api/auth/create-user', async (req, res) => {
  try {
    const { username, email, password, nombre_completo } = req.body;
    console.log(`👤 Creando usuario: ${username}`);

    if (!username || !email || !password || !nombre_completo) {
      return res.status(400).json({ 
        error: 'Todos los campos son requeridos' 
      });
    }

    // Verificar si ya existe
    const checkQuery = 'SELECT id_paciente FROM pacientes WHERE username = $1 OR email = $2';
    const checkResult = await executeQuery(checkQuery, [username, email]);

    if (checkResult.rows.length > 0) {
      return res.status(400).json({ 
        error: 'El usuario o email ya existe' 
      });
    }

    // Hashear contraseña
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Insertar usuario
    const insertQuery = `
      INSERT INTO pacientes (username, email, password_hash, nombre_completo, activo, fecha_registro)
      VALUES ($1, $2, $3, $4, true, CURRENT_TIMESTAMP)
      RETURNING id_paciente, username, email, nombre_completo
    `;
    
    const result = await executeQuery(insertQuery, [username, email, hashedPassword, nombre_completo]);
    const newUser = result.rows[0];

    console.log(`✅ Usuario creado: ${username}`);
    
    res.status(201).json({
      message: 'Usuario creado exitosamente',
      user: {
        id: newUser.id_paciente,
        username: newUser.username,
        email: newUser.email,
        name: newUser.nombre_completo
      }
    });

  } catch (error) {
    console.error('❌ Error creando usuario:', error);
    res.status(500).json({ 
      error: 'Error creando usuario' 
    });
  }
});

// 🔐 RUTAS PROTEGIDAS (requieren autenticación)

// Perfil del usuario
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const query = 'SELECT id_paciente, username, email, nombre_completo FROM pacientes WHERE id_paciente = $1';
    const result = await executeQuery(query, [req.user.userId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error('❌ Error obteniendo perfil:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// 📋 RUTAS EXISTENTES (pacientes, ejercicios, etc.)

// Ejemplo de ruta existente de pacientes (mantenemos las que ya tienes)
app.get('/api/pacientes', async (req, res) => {
  try {
    const result = await executeQuery('SELECT * FROM pacientes ORDER BY id_paciente');
    res.json(result.rows);
  } catch (error) {
    console.error('Error obteniendo pacientes:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// 🚀 INICIAR SERVIDOR
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Servidor FonoKids ejecutándose en puerto ${PORT}`);
  console.log(`📧 Email configurado: ${process.env.EMAIL_USER}`);
});
// 📋 RUTAS DE PERFIL SIMPLIFICADAS - Agregar después de las rutas de autenticación

// OBTENER PERFIL DEL USUARIO
app.get('/api/perfil', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    console.log(`📋 Obteniendo perfil del usuario ID: ${userId}`);

    const query = `
      SELECT 
        id_paciente,
        nombre_completo,
        fecha_nacimiento,
        edad,
        sexo,
        numero_documento,
        direccion,
        telefono_principal,
        telefono_secundario,
        username,
        email,
        fecha_registro,
        fecha_actualizacion,
        activo
      FROM pacientes 
      WHERE id_paciente = $1
    `;
    
    const result = await executeQuery(query, [userId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ 
        success: false,
        error: 'Perfil no encontrado' 
      });
    }

    const perfil = result.rows[0];
    
    console.log(`✅ Perfil obtenido para: ${perfil.username}`);
    
    res.json({
      success: true,
      data: perfil
    });

  } catch (error) {
    console.error('❌ Error obteniendo perfil:', error);
    res.status(500).json({ 
      success: false,
      error: 'Error obteniendo perfil' 
    });
  }
});

// ACTUALIZAR PERFIL DEL USUARIO
app.put('/api/perfil', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const {
      nombre_completo,
      fecha_nacimiento,
      sexo,
      numero_documento,
      direccion,
      telefono_principal,
      telefono_secundario,
      email
    } = req.body;
    
    console.log(`✏️ Actualizando perfil del usuario ID: ${userId}`);

    // Construir query dinámicamente
    let updateFields = [];
    let values = [];
    let paramCount = 1;

    // Solo actualizar campos que fueron enviados
    if (nombre_completo !== undefined) {
      updateFields.push(`nombre_completo = $${paramCount++}`);
      values.push(nombre_completo);
    }
    if (fecha_nacimiento !== undefined) {
      updateFields.push(`fecha_nacimiento = $${paramCount++}`);
      values.push(fecha_nacimiento);
      
      // Calcular edad automáticamente
      const birthDate = new Date(fecha_nacimiento);
      const today = new Date();
      let edad = today.getFullYear() - birthDate.getFullYear();
      const monthDiff = today.getMonth() - birthDate.getMonth();
      if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
        edad--;
      }
      updateFields.push(`edad = $${paramCount++}`);
      values.push(edad);
    }
    if (sexo !== undefined) {
      updateFields.push(`sexo = $${paramCount++}`);
      values.push(sexo);
    }
    if (numero_documento !== undefined) {
      updateFields.push(`numero_documento = $${paramCount++}`);
      values.push(numero_documento);
    }
    if (direccion !== undefined) {
      updateFields.push(`direccion = $${paramCount++}`);
      values.push(direccion);
    }
    if (telefono_principal !== undefined) {
      updateFields.push(`telefono_principal = $${paramCount++}`);
      values.push(telefono_principal);
    }
    if (telefono_secundario !== undefined) {
      updateFields.push(`telefono_secundario = $${paramCount++}`);
      values.push(telefono_secundario);
    }
    if (email !== undefined) {
      updateFields.push(`email = $${paramCount++}`);
      values.push(email);
    }

    // Siempre actualizar fecha_actualizacion y updated_at
    updateFields.push(`fecha_actualizacion = CURRENT_TIMESTAMP`);
    updateFields.push(`updated_at = CURRENT_TIMESTAMP`);

    if (updateFields.length === 2) { // Solo timestamps
      return res.status(400).json({ 
        success: false,
        error: 'No hay campos para actualizar' 
      });
    }

    // Agregar userId al final
    values.push(userId);

    const updateQuery = `
      UPDATE pacientes 
      SET ${updateFields.join(', ')}
      WHERE id_paciente = $${paramCount}
      RETURNING 
        id_paciente, 
        nombre_completo, 
        email, 
        fecha_nacimiento,
        edad,
        sexo,
        numero_documento,
        direccion,
        telefono_principal,
        telefono_secundario
    `;

    const result = await executeQuery(updateQuery, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ 
        success: false,
        error: 'Usuario no encontrado' 
      });
    }

    console.log(`✅ Perfil actualizado para ID: ${userId}`);

    res.json({
      success: true,
      message: 'Perfil actualizado correctamente',
      data: result.rows[0]
    });

  } catch (error) {
    console.error('❌ Error actualizando perfil:', error);
    res.status(500).json({ 
      success: false,
      error: 'Error actualizando perfil' 
    });
  }
});

// OBTENER PERFIL POR ID (para terapeutas/admin)
app.get('/api/perfil/:id', authenticateToken, async (req, res) => {
  try {
    const pacienteId = req.params.id;
    console.log(`📋 Obteniendo perfil del paciente ID: ${pacienteId}`);

    const query = `
      SELECT 
        id_paciente,
        nombre_completo,
        fecha_nacimiento,
        edad,
        sexo,
        numero_documento,
        direccion,
        telefono_principal,
        telefono_secundario,
        username,
        email,
        fecha_registro,
        activo
      FROM pacientes 
      WHERE id_paciente = $1
    `;
    
    const result = await executeQuery(query, [pacienteId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ 
        success: false,
        error: 'Paciente no encontrado' 
      });
    }

    res.json({
      success: true,
      data: result.rows[0]
    });

  } catch (error) {
    console.error('❌ Error obteniendo perfil del paciente:', error);
    res.status(500).json({ 
      success: false,
      error: 'Error obteniendo perfil' 
    });
  }
});