// ═══════════════════════════════════════════════════
//  GestiónPro — Backend Express + MongoDB Atlas
//  Reemplaza la Data API de Atlas con endpoints REST
// ═══════════════════════════════════════════════════

require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const { MongoClient, ObjectId } = require('mongodb');

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Middleware ──────────────────────────────────────
app.use(cors());
app.use(express.json());

// ── Servir el frontend desde la misma carpeta ───────
app.use(express.static(path.join(__dirname)));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'gestion-app-v2.html'));
});

// ── Conexión MongoDB ────────────────────────────────
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

// ── Helper: convertir $oid strings a ObjectId ───────
function parseFilter(filter) {
  if (!filter || typeof filter !== 'object') return filter || {};
  const out = {};
  for (const [k, v] of Object.entries(filter)) {
    if (k === '_id' && v && v.$oid) {
      out._id = new ObjectId(v.$oid);
    } else if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
      out[k] = parseFilter(v);
    } else {
      out[k] = v;
    }
  }
  return out;
}

function parseUpdate(update) {
  const out = {};
  for (const [op, fields] of Object.entries(update)) {
    out[op] = parseFilter(fields);
  }
  return out;
}

function serializeDoc(doc) {
  if (!doc) return doc;
  const out = { ...doc };
  if (out._id instanceof ObjectId) {
    out._id = { $oid: out._id.toHexString() };
  }
  return out;
}

// ── Health check ────────────────────────────────────
app.get('/health', async (req, res) => {
  try {
    await connectDB();
    res.json({ ok: true, db: DB_NAME });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ═══════════════════════════════════════════════════
//  RUTAS REST — POST /api/:collection/:action
// ═══════════════════════════════════════════════════

app.post('/api/:collection/find', async (req, res) => {
  try {
    const database = await connectDB();
    const col = database.collection(req.params.collection);
    const { filter = {}, sort = {}, limit = 100, projection } = req.body;

    let cursor = col.find(parseFilter(filter));
    if (Object.keys(sort).length) cursor = cursor.sort(sort);
    if (limit)                    cursor = cursor.limit(limit);
    if (projection)               cursor = cursor.project(projection);

    const docs = await cursor.toArray();
    res.json({ documents: docs.map(serializeDoc) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/:collection/findOne', async (req, res) => {
  try {
    const database = await connectDB();
    const col = database.collection(req.params.collection);
    const { filter = {}, projection } = req.body;
    const doc = await col.findOne(parseFilter(filter), { projection });
    res.json({ document: serializeDoc(doc) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/:collection/insertOne', async (req, res) => {
  try {
    const database = await connectDB();
    const col = database.collection(req.params.collection);
    const { document: doc } = req.body;
    const cleanDoc = convertDates(doc);
    const result = await col.insertOne(cleanDoc);
    res.json({ insertedId: { $oid: result.insertedId.toHexString() } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/:collection/updateOne', async (req, res) => {
  try {
    const database = await connectDB();
    const col = database.collection(req.params.collection);
    const { filter = {}, update = {}, upsert = false } = req.body;
    const result = await col.updateOne(parseFilter(filter), parseUpdate(update), { upsert });
    res.json({ matchedCount: result.matchedCount, modifiedCount: result.modifiedCount });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/:collection/deleteOne', async (req, res) => {
  try {
    const database = await connectDB();
    const col = database.collection(req.params.collection);
    const { filter = {} } = req.body;
    const result = await col.deleteOne(parseFilter(filter));
    res.json({ deletedCount: result.deletedCount });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/:collection/aggregate', async (req, res) => {
  try {
    const database = await connectDB();
    const col = database.collection(req.params.collection);
    const { pipeline = [] } = req.body;
    const docs = await col.aggregate(pipeline).toArray();
    res.json({ documents: docs.map(serializeDoc) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Convierte { $date: { $numberLong: '...' } } → Date ──
function convertDates(obj) {
  if (obj === null || obj === undefined) return obj;
  if (Array.isArray(obj)) return obj.map(convertDates);
  if (typeof obj === 'object') {
    if (obj.$date && obj.$date.$numberLong !== undefined) {
      return new Date(parseInt(obj.$date.$numberLong));
    }
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
      out[k] = convertDates(v);
    }
    return out;
  }
  return obj;
}

// ── Arranque ────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 GestiónPro corriendo en http://localhost:${PORT}`);
  console.log(`   Abre http://localhost:${PORT} en el navegador`);
});
