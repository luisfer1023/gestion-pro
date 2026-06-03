require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');

const PDFDocument = require('pdfkit');
const app  = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'gestionpro_secret_2024';

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.options('*', cors()); // ✅ preflight explícito (móvil-safe)

app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'gestion-app-v2.html'));
});

const MONGO_URI = process.env.MONGO_URI;
const DB_NAME   = process.env.DB_NAME || 'gestion_pro';
let db;

async function connectDB() {
  if (db) return db;
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  db = client.db(DB_NAME);
  console.log(`✅ Conectado a MongoDB Atlas — DB: ${DB_NAME}`);
  return db;
}

// ── Middleware: verificar JWT ────────────────────────
function authRequired(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No autorizado' });
  }
  try {
    const token = header.split(' ')[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// ── Serializa ObjectId y Date ────────────────────────
function serializeDoc(doc) {
  if (!doc) return doc;
  const out = { ...doc };
  if (out._id instanceof ObjectId) out._id = { $oid: out._id.toHexString() };
  for (const [k, v] of Object.entries(out)) {
    if (v instanceof Date) out[k] = { $date: { $numberLong: v.getTime().toString() } };
  }
  return out;
}

function parseFilter(filter) {
  if (!filter || typeof filter !== 'object') return filter || {};
  const out = {};
  for (const [k, v] of Object.entries(filter)) {
    if (k === '_id' && v && v.$oid) { out._id = new ObjectId(v.$oid); continue; }
    if (k === 'fecha' && typeof v === 'object' && v !== null) {
      const dateCond = {};
      for (const [op, val] of Object.entries(v)) {
        if (typeof val === 'string' || typeof val === 'number') dateCond[op] = new Date(val);
        else if (val instanceof Date) dateCond[op] = val;
      }
      out.fecha = dateCond; continue;
    }
    if (typeof v === 'object' && v !== null && !Array.isArray(v)) out[k] = parseFilter(v);
    else out[k] = v;
  }
  return out;
}

function parseUpdate(update) {
  const out = {};
  for (const [op, fields] of Object.entries(update)) out[op] = parseFilter(fields);
  return out;
}

function convertDates(obj) {
  if (obj === null || obj === undefined) return obj;
  if (Array.isArray(obj)) return obj.map(convertDates);
  if (typeof obj === 'object') {
    if (obj.$date && obj.$date.$numberLong !== undefined) return new Date(parseInt(obj.$date.$numberLong));
    const out = {};
    for (const [k, v] of Object.entries(obj)) out[k] = convertDates(v);
    return out;
  }
  return obj;
}

// ══════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════

// Verificar si ya hay un admin registrado
app.get('/auth/status', async (req, res) => {
  try {
    const database = await connectDB();
    const count = await database.collection('usuarios').countDocuments({ role: 'admin' });
    res.json({ hasAdmin: count > 0 });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Registro del primer admin (solo si no existe ninguno)
app.post('/auth/register', async (req, res) => {
  try {
    const database = await connectDB();
    const existing = await database.collection('usuarios').countDocuments({ role: 'admin' });
    if (existing > 0) return res.status(403).json({ error: 'Ya existe un administrador registrado' });

    const { usuario, password } = req.body;
    if (!usuario || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    if (password.length < 6) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });

    const hash = await bcrypt.hash(password, 12);
    await database.collection('usuarios').insertOne({
      usuario: usuario.trim().toLowerCase(),
      password: hash,
      role: 'admin',
      createdAt: new Date()
    });
    res.json({ ok: true, message: 'Administrador creado exitosamente' });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const database = await connectDB();
    const { usuario, password } = req.body;
    if (!usuario || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });

    const user = await database.collection('usuarios').findOne({ usuario: usuario.trim().toLowerCase() });
    if (!user) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });

    const token = jwt.sign({ id: user._id.toHexString(), usuario: user.usuario, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ ok: true, token, usuario: user.usuario, role: user.role });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Verificar token
app.get('/auth/verify', authRequired, (req, res) => {
  res.json({ ok: true, user: req.user });
});

// ── Health ───────────────────────────────────────────
app.get('/health', async (req, res) => {
  try {
    await connectDB();
    res.json({ ok: true, db: DB_NAME });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});



// ── Configuracion de la app (publica para leer, protegida para escribir) ──
app.get('/config', async (req, res) => {
  try {
    const database = await connectDB();
    const cfg = await database.collection('configuracion').findOne({});
    if (!cfg) return res.json({});
    const { _id, ...rest } = cfg;
    res.json(rest);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/config', authRequired, async (req, res) => {
  try {
    const database = await connectDB();
    const body = req.body || {};
    const safe = {
      empresa:       body.empresa       || '',
      emailService:  body.emailService  || '',
      emailTemplate: body.emailTemplate || '',
      emailPubKey:   body.emailPubKey   || '',
      updatedAt:     new Date()
    };
    await database.collection('configuracion').updateOne(
      {},
      { $set: safe },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════
//  API ROUTES (protegidas con JWT)
// ══════════════════════════════════════════════════════

app.post('/api/:collection/find', authRequired, async (req, res) => {
  try {
    const database = await connectDB();
    const col = database.collection(req.params.collection);
    const { filter = {}, sort = {}, limit = 200, projection } = req.body;
    let cursor = col.find(parseFilter(filter));
    if (Object.keys(sort).length) cursor = cursor.sort(sort);
    if (limit) cursor = cursor.limit(limit);
    if (projection) cursor = cursor.project(projection);
    const docs = await cursor.toArray();
    res.json({ documents: docs.map(serializeDoc) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/:collection/findOne', authRequired, async (req, res) => {
  try {
    const database = await connectDB();
    const col = database.collection(req.params.collection);
    const { filter = {}, projection } = req.body;
    const doc = await col.findOne(parseFilter(filter), { projection });
    res.json({ document: serializeDoc(doc) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/:collection/insertOne', authRequired, async (req, res) => {
  try {
    const database = await connectDB();
    const col = database.collection(req.params.collection);
    const { document: doc } = req.body;
    const result = await col.insertOne(convertDates(doc));
    res.json({ insertedId: { $oid: result.insertedId.toHexString() } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/:collection/updateOne', authRequired, async (req, res) => {
  try {
    const database = await connectDB();
    const col = database.collection(req.params.collection);
    const { filter = {}, update = {}, upsert = false } = req.body;
    const result = await col.updateOne(parseFilter(filter), parseUpdate(update), { upsert });
    res.json({ matchedCount: result.matchedCount, modifiedCount: result.modifiedCount });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/:collection/deleteOne', authRequired, async (req, res) => {
  try {
    const database = await connectDB();
    const col = database.collection(req.params.collection);
    const { filter = {} } = req.body;
    const result = await col.deleteOne(parseFilter(filter));
    res.json({ deletedCount: result.deletedCount });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/:collection/aggregate', authRequired, async (req, res) => {
  try {
    const database = await connectDB();
    const col = database.collection(req.params.collection);
    const { pipeline = [] } = req.body;
    const docs = await col.aggregate(pipeline).toArray();
    res.json({ documents: docs.map(serializeDoc) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});


// ══════════════════════════════════════════════════════
//  PDF — Guardar y servir facturas
// ══════════════════════════════════════════════════════

// Guardar PDF base64 desde el frontend


// ── PDF Helpers (generación server-side con PDFKit) ─────────────────
const moneyCO = new Intl.NumberFormat('es-CO', { minimumFractionDigits: 0, maximumFractionDigits: 0 });
function formatCOP(n) {
  const num = Number(n || 0);
  return '$' + moneyCO.format(Math.round(num));
}

async function generateInvoicePdfBuffer(factura, empresa = 'Mi Empresa') {
  return await new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ size: 'A4', margin: 50 });
      const chunks = [];
      doc.on('data', (d) => chunks.push(d));
      doc.on('end', () => resolve(Buffer.concat(chunks)));

      // Header
      doc.rect(0, 0, doc.page.width, 110).fill('#6c63ff');
      doc.fillColor('#ffffff');
      doc.fontSize(20).font('Helvetica-Bold').text(empresa, 40, 32, { width: doc.page.width - 80 });
      doc.fontSize(11).font('Helvetica').fillColor('rgba(255,255,255,0.85)')
        .text('Factura electrónica', 40, 58);

      doc.fillColor('#ffffff');
      doc.fontSize(12).font('Helvetica-Bold')
        .text('FACTURA', doc.page.width - 160, 34, { width: 120, align: 'right' });
      doc.fontSize(11).font('Helvetica')
        .text(String(factura.numeroFactura || ''), doc.page.width - 240, 56, { width: 200, align: 'right' });

      // Fecha
      const fecha = factura.fecha instanceof Date
        ? factura.fecha
        : (factura.fecha && factura.fecha.$date && factura.fecha.$date.$numberLong)
          ? new Date(parseInt(factura.fecha.$date.$numberLong))
          : new Date();
      doc.fillColor('#333333');
      doc.fontSize(10).font('Helvetica')
        .text('Fecha: ' + fecha.toLocaleDateString('es-CO', { timeZone: process.env.TZ || 'America/Bogota' }) + ' ' + fecha.toLocaleTimeString('es-CO', { timeZone: process.env.TZ || 'America/Bogota', hour: '2-digit', minute: '2-digit' }), 40, 125);

      // Cliente box
      let y = 150;
      doc.roundedRect(40, y, doc.page.width - 80, 70, 8).fill('#f0f0fa');
      doc.fillColor('#333333');
      doc.fontSize(11).font('Helvetica-Bold').text('Cliente', 55, y + 12);
      doc.fontSize(10).font('Helvetica').fillColor('#555555');
      const c = factura.cliente || {};
      const leftX = 55;
      const midX = doc.page.width / 2;
      doc.text('Nombre: ' + (c.nombre || '—'), leftX, y + 30, { width: midX - 70 });
      doc.text('Cédula/NIT: ' + (c.cedula || '—'), leftX, y + 46, { width: midX - 70 });
      doc.text('Teléfono: ' + (c.telefono || '—'), midX, y + 30, { width: doc.page.width - midX - 55 });
      doc.text('Correo: ' + (c.email || '—'), midX, y + 46, { width: doc.page.width - midX - 55 });

      // Tabla de items
      y += 95;
      const tableLeft = 40;
      const tableRight = doc.page.width - 40;
      const colDesc = tableLeft;
      const colCant = tableLeft + 300;
      const colPrecio = tableLeft + 360;
      const colSub = tableLeft + 455;

      const headerH = 22;
      doc.fillColor('#1a1a2e');
      doc.roundedRect(tableLeft, y, tableRight - tableLeft, headerH, 6).fill('#f0f0fa');
      doc.fillColor('#555555').fontSize(9).font('Helvetica-Bold');
      doc.text('DESCRIPCIÓN', colDesc + 10, y + 6, { width: 280 });
      doc.text('CANT.', colCant, y + 6, { width: 50, align: 'center' });
      doc.text('PRECIO', colPrecio, y + 6, { width: 90, align: 'right' });
      doc.text('SUBTOTAL', colSub, y + 6, { width: 90, align: 'right' });
      y += headerH + 6;

      const items = Array.isArray(factura.items) ? factura.items : [];
      const rows = [...items];
      if (factura.manoDeObra && Number(factura.manoDeObra.valor || 0) > 0) {
        rows.push({
          nombre: factura.manoDeObra.descripcion || 'Mano de obra',
          cantidad: 1,
          precioUnit: Number(factura.manoDeObra.valor || 0),
          subtotal: Number(factura.manoDeObra.valor || 0)
        });
      }

      doc.font('Helvetica').fontSize(10).fillColor('#222222');

      function ensureSpace(needed) {
        if (y + needed > doc.page.height - 130) {
          doc.addPage();
          y = 40;
          doc.roundedRect(tableLeft, y, tableRight - tableLeft, headerH, 6).fill('#f0f0fa');
          doc.fillColor('#555555').fontSize(9).font('Helvetica-Bold');
          doc.text('DESCRIPCIÓN', colDesc + 10, y + 6, { width: 280 });
          doc.text('CANT.', colCant, y + 6, { width: 50, align: 'center' });
          doc.text('PRECIO', colPrecio, y + 6, { width: 90, align: 'right' });
          doc.text('SUBTOTAL', colSub, y + 6, { width: 90, align: 'right' });
          y += headerH + 6;
          doc.font('Helvetica').fontSize(10).fillColor('#222222');
        }
      }

      rows.forEach((it) => {
        const desc = String(it.nombre || it.descripcion || 'Ítem');
        const cant = Number(it.cantidad || 0);
        const precio = Number(it.precioUnit || it.precio || 0);
        const sub = (it.subtotal !== undefined) ? Number(it.subtotal || 0) : cant * precio;

        const descHeight = doc.heightOfString(desc, { width: 280 });
        const rowH = Math.max(18, descHeight + 4);
        ensureSpace(rowH + 6);

        doc.fillColor('#222222').font('Helvetica').fontSize(10);
        doc.text(desc, colDesc + 10, y, { width: 280 });
        doc.text(String(cant), colCant, y, { width: 50, align: 'center' });
        doc.text(formatCOP(precio), colPrecio, y, { width: 90, align: 'right' });
        doc.text(formatCOP(sub), colSub, y, { width: 90, align: 'right' });

        doc.strokeColor('#eeeeee').lineWidth(1);
        doc.moveTo(tableLeft, y + rowH + 4).lineTo(tableRight, y + rowH + 4).stroke();
        y += rowH + 10;
      });

      // Totales
      ensureSpace(90);
      const subtotal = Number(factura.subtotal || 0);
      const mo = Number(factura.manoDeObra?.valor || 0);
      const descMonto = Number(factura.descuento?.monto || 0);
      const total = Number(factura.total || 0);

      const totalsX = doc.page.width - 260;
      doc.fillColor('#555555').font('Helvetica').fontSize(10);
      doc.text('Subtotal:', totalsX, y + 10, { width: 120, align: 'left' });
      doc.text(formatCOP(subtotal), totalsX + 120, y + 10, { width: 100, align: 'right' });
      if (mo > 0) {
        doc.text('Mano de obra:', totalsX, y + 26, { width: 120, align: 'left' });
        doc.text(formatCOP(mo), totalsX + 120, y + 26, { width: 100, align: 'right' });
      }
      if (descMonto > 0) {
        const label = 'Descuento' + (factura.descuento?.tipo === 'porcentaje' ? ` (${factura.descuento?.valor || 0}%)` : '') + ':';
        doc.fillColor('#e24b4a');
        doc.text(label, totalsX, y + 42, { width: 120, align: 'left' });
        doc.text('-' + formatCOP(descMonto), totalsX + 120, y + 42, { width: 100, align: 'right' });
        doc.fillColor('#555555');
      }

      doc.strokeColor('#6c63ff').lineWidth(2);
      doc.moveTo(totalsX, y + 62).lineTo(doc.page.width - 40, y + 62).stroke();

      doc.fillColor('#6c63ff').font('Helvetica-Bold').fontSize(13);
      doc.text('TOTAL:', totalsX, y + 70, { width: 120, align: 'left' });
      doc.text(formatCOP(total), totalsX + 120, y + 70, { width: 100, align: 'right' });

      // Footer
      doc.fillColor('#999999').font('Helvetica').fontSize(9);
      doc.text('Gracias por su compra — ' + empresa, 40, doc.page.height - 60, { width: doc.page.width - 80, align: 'center' });

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

app.post('/facturas/pdf', authRequired, async (req, res) => {
  try {
    const database = await connectDB();
    const { numeroFactura, pdfBase64 } = req.body;
    if (!numeroFactura || !pdfBase64) return res.status(400).json({ error: 'Faltan datos' });

    await database.collection('facturas_pdf').updateOne(
      { numeroFactura },
      { $set: { numeroFactura, pdfBase64, createdAt: new Date() } },
      { upsert: true }
    );
    const url = `${req.protocol}://${req.get('host')}/facturas/pdf/${numeroFactura}`;
    res.json({ ok: true, url });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Generar PDF server-side (PDFKit) y guardarlo en MongoDB — devuelve URL pública
app.post('/facturas/pdf/generate', authRequired, async (req, res) => {
  try {
    const database = await connectDB();
    const { numeroFactura } = req.body || {};
    if (!numeroFactura) return res.status(400).json({ error: 'numeroFactura requerido' });

    const factura = await database.collection('facturas').findOne({ numeroFactura });
    if (!factura) return res.status(404).json({ error: 'Factura no encontrada' });

    const cfg = await database.collection('configuracion').findOne({});
    const empresa = (cfg && cfg.empresa) ? cfg.empresa : 'Mi Empresa';

    const buffer = await generateInvoicePdfBuffer(factura, empresa);
    const pdfBase64 = buffer.toString('base64');

    await database.collection('facturas_pdf').updateOne(
      { numeroFactura },
      { $set: { numeroFactura, pdfBase64, createdAt: new Date() } },
      { upsert: true }
    );

    const url = `${req.protocol}://${req.get('host')}/facturas/pdf/${encodeURIComponent(numeroFactura)}`;
    res.json({ ok: true, url });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


// Servir PDF público (sin auth)

// Servir PDF público (sin auth) — si no existe, se genera automáticamente desde la factura
app.get('/facturas/pdf/:numeroFactura', async (req, res) => {
  try {
    const database = await connectDB();
    const numeroFactura = req.params.numeroFactura;

    // 1) Buscar en caché (colección facturas_pdf)
    const cached = await database.collection('facturas_pdf').findOne({ numeroFactura });
    if (cached && cached.pdfBase64) {
      const buffer = Buffer.from(cached.pdfBase64, 'base64');
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${numeroFactura}.pdf"`);
      return res.send(buffer);
    }

    // 2) Si no existe, buscar la factura y generarlo
    const factura = await database.collection('facturas').findOne({ numeroFactura });
    if (!factura) return res.status(404).json({ error: 'Factura no encontrada' });

    const cfg = await database.collection('configuracion').findOne({});
    const empresa = (cfg && cfg.empresa) ? cfg.empresa : 'Mi Empresa';

    const buffer = await generateInvoicePdfBuffer(factura, empresa);
    const pdfBase64 = buffer.toString('base64');

    await database.collection('facturas_pdf').updateOne(
      { numeroFactura },
      { $set: { numeroFactura, pdfBase64, createdAt: new Date() } },
      { upsert: true }
    );

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${numeroFactura}.pdf"`);
    res.send(buffer);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


app.listen(PORT, () => {
  console.log(`🚀 GestiónPro corriendo en http://localhost:${PORT}`);
});

// ══════════════════════════════════════════════════════
//  GESTIÓN DE USUARIOS (solo admin)
// ══════════════════════════════════════════════════════

function adminRequired(req, res, next) {
  authRequired(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Solo el administrador puede hacer esto' });
    next();
  });
}

// Listar usuarios
app.get('/auth/users', adminRequired, async (req, res) => {
  try {
    const database = await connectDB();
    const users = await database.collection('usuarios')
      .find({}, { projection: { password: 0 } })
      .toArray();
    res.json({ users: users.map(u => ({ ...u, _id: u._id.toHexString() })) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Crear usuario (admin crea usuarios con role 'usuario')
app.post('/auth/users', adminRequired, async (req, res) => {
  try {
    const database = await connectDB();
    const { usuario, password } = req.body;
    if (!usuario || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    if (password.length < 6) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });

    const exists = await database.collection('usuarios').findOne({ usuario: usuario.trim().toLowerCase() });
    if (exists) return res.status(409).json({ error: 'Ya existe un usuario con ese nombre' });

    const hash = await bcrypt.hash(password, 12);
    const result = await database.collection('usuarios').insertOne({
      usuario: usuario.trim().toLowerCase(),
      password: hash,
      role: 'usuario',
      createdAt: new Date()
    });
    res.json({ ok: true, id: result.insertedId.toHexString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Eliminar usuario (admin no puede eliminarse a sí mismo)
app.delete('/auth/users/:id', adminRequired, async (req, res) => {
  try {
    const database = await connectDB();
    if (req.params.id === req.user.id) return res.status(400).json({ error: 'No puedes eliminarte a ti mismo' });
    const result = await database.collection('usuarios').deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ deletedCount: result.deletedCount });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
