const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const dataDir = path.join(__dirname, 'data');
const uploadDir = path.join(__dirname, 'uploads');
fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });
const db = new Database(path.join(dataDir, 'inventory.db'));
db.pragma('foreign_keys = ON');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-before-deploying',
  resave: false,
  saveUninitialized: false,
  cookie: { sameSite: 'lax', secure: process.env.NODE_ENV === 'production' }
}));
app.use('/uploads', express.static(uploadDir));
app.use(express.static(path.join(__dirname, 'public')));

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) => cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${path.extname(file.originalname)}`)
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (_, file, cb) => cb(null, /^image\//.test(file.mimetype))
});

function columns(table) { return db.prepare(`PRAGMA table_info(${table})`).all().map(x => x.name); }
function addColumn(table, name, type) { if (!columns(table).includes(name)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`); }
function now() { return new Date().toISOString().replace('T', ' ').slice(0, 19); }

function init() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS organizations (
      id INTEGER PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      short_name TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      org_id INTEGER NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'staff',
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(org_id) REFERENCES organizations(id)
    );
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY,
      org_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      spec TEXT,
      vendor TEXT,
      stock INTEGER NOT NULL DEFAULT 0,
      min_stock INTEGER NOT NULL DEFAULT 0,
      last_inbound TEXT,
      created_by INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(org_id) REFERENCES organizations(id),
      FOREIGN KEY(created_by) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS purchases (
      id INTEGER PRIMARY KEY,
      org_id INTEGER NOT NULL,
      vendor TEXT NOT NULL,
      inbound_date TEXT NOT NULL,
      product_id INTEGER NOT NULL,
      qty INTEGER NOT NULL,
      unit_price INTEGER NOT NULL DEFAULT 0,
      total INTEGER NOT NULL DEFAULT 0,
      image_url TEXT,
      created_by INTEGER NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(org_id) REFERENCES organizations(id),
      FOREIGN KEY(product_id) REFERENCES products(id),
      FOREIGN KEY(created_by) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS outbounds (
      id INTEGER PRIMARY KEY,
      org_id INTEGER NOT NULL,
      outbound_date TEXT NOT NULL,
      product_id INTEGER NOT NULL,
      qty INTEGER NOT NULL,
      memo TEXT,
      created_by INTEGER NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(org_id) REFERENCES organizations(id),
      FOREIGN KEY(product_id) REFERENCES products(id),
      FOREIGN KEY(created_by) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY,
      org_id INTEGER NOT NULL,
      user_id INTEGER,
      user_name TEXT,
      action TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_name TEXT,
      detail TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(org_id) REFERENCES organizations(id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

  const orgs = [
    ['블랑여성의원', '블랑여성의원'],
    ['닥터플로셀', '닥터플로셀']
  ];
  const getOrg = db.prepare('SELECT * FROM organizations WHERE name=?');
  const addOrg = db.prepare('INSERT INTO organizations(name,short_name) VALUES(?,?)');
  for (const org of orgs) if (!getOrg.get(org[0])) addOrg.run(...org);

  const blanc = getOrg.get('블랑여성의원');
  const flow = getOrg.get('닥터플로셀');
  const userCount = db.prepare('SELECT COUNT(*) c FROM users').get().c;
  if (!userCount) {
    const addUser = db.prepare('INSERT INTO users(org_id,username,password,name,role) VALUES(?,?,?,?,?)');
    addUser.run(blanc.id, 'blancadmin', bcrypt.hashSync('1234', 10), '블랑 관리자', 'admin');
    addUser.run(flow.id, 'flowcelladmin', bcrypt.hashSync('1234', 10), '플로셀 관리자', 'admin');
  }
}
init();

function auth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ message: '로그인이 필요합니다.' });
  next();
}
function adminOnly(req, res, next) {
  if (req.session.user.role !== 'admin') return res.status(403).json({ message: '관리자만 사용할 수 있습니다.' });
  next();
}
function userInfo(row) { return { id: row.id, orgId: row.org_id, orgName: row.org_name, username: row.username, name: row.name, role: row.role }; }
function productRow(row) { return { ...row, status: row.stock === 0 ? 'none' : row.stock <= row.min_stock ? 'low' : 'good' }; }
function log(req, action, targetType, targetName, detail = '') {
  const u = req.session.user;
  db.prepare('INSERT INTO audit_logs(org_id,user_id,user_name,action,target_type,target_name,detail,created_at) VALUES(?,?,?,?,?,?,?,?)')
    .run(u.orgId, u.id, u.name, action, targetType, targetName, detail, now());
}
function ownProduct(productId, orgId) { return db.prepare('SELECT * FROM products WHERE id=? AND org_id=?').get(productId, orgId); }

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const row = db.prepare(`SELECT u.*, o.name AS org_name FROM users u JOIN organizations o ON o.id=u.org_id WHERE u.username=? AND u.active=1`).get(username);
  if (!row || !bcrypt.compareSync(password || '', row.password)) return res.status(401).json({ message: '아이디 또는 비밀번호가 올바르지 않습니다.' });
  req.session.user = userInfo(row);
  res.json({ user: req.session.user });
});
app.post('/api/logout', auth, (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', (req, res) => res.json({ user: req.session.user || null }));

app.get('/api/dashboard', auth, (req, res) => {
  const org = req.session.user.orgId;
  const total = db.prepare('SELECT COUNT(*) c FROM products WHERE org_id=?').get(org).c;
  const low = db.prepare('SELECT COUNT(*) c FROM products WHERE org_id=? AND stock<=min_stock').get(org).c;
  const today = new Date().toISOString().slice(0, 10);
  const todayIn = db.prepare('SELECT COALESCE(SUM(qty),0) c FROM purchases WHERE org_id=? AND inbound_date=?').get(org, today).c;
  const recent = db.prepare(`SELECT p.inbound_date,p.vendor,pr.name,p.qty,p.total,u.name AS user_name
    FROM purchases p JOIN products pr ON pr.id=p.product_id JOIN users u ON u.id=p.created_by
    WHERE p.org_id=? ORDER BY p.id DESC LIMIT 5`).all(org);
  const lowRows = db.prepare('SELECT * FROM products WHERE org_id=? AND stock<=min_stock ORDER BY stock ASC,name').all(org).map(productRow);
  res.json({ total, low, todayIn, recent, lowRows });
});

app.get('/api/products', auth, (req, res) => {
  const rows = db.prepare('SELECT * FROM products WHERE org_id=? ORDER BY name').all(req.session.user.orgId).map(productRow);
  res.json(rows);
});
app.post('/api/products', auth, (req, res) => {
  const { name, spec = '', vendor = '', stock = 0, minStock = 0 } = req.body;
  if (!name?.trim()) return res.status(400).json({ message: '제품명을 입력하세요.' });
  const r = db.prepare('INSERT INTO products(org_id,name,spec,vendor,stock,min_stock,created_by) VALUES(?,?,?,?,?,?,?)')
    .run(req.session.user.orgId, name.trim(), spec.trim(), vendor.trim(), Math.max(0, Number(stock) || 0), Math.max(0, Number(minStock) || 0), req.session.user.id);
  log(req, '제품 추가', '제품', name.trim(), `초기 재고 ${Number(stock) || 0}개`);
  res.json(db.prepare('SELECT * FROM products WHERE id=?').get(r.lastInsertRowid));
});
app.put('/api/products/:id', auth, adminOnly, (req, res) => {
  const product = ownProduct(req.params.id, req.session.user.orgId);
  if (!product) return res.status(404).json({ message: '제품을 찾을 수 없습니다.' });
  const { name, spec = '', vendor = '', stock = 0, minStock = 0 } = req.body;
  db.prepare('UPDATE products SET name=?,spec=?,vendor=?,stock=?,min_stock=? WHERE id=? AND org_id=?')
    .run(name, spec, vendor, Math.max(0, Number(stock) || 0), Math.max(0, Number(minStock) || 0), product.id, req.session.user.orgId);
  log(req, '제품 수정', '제품', name, `재고 ${product.stock}개 → ${Math.max(0, Number(stock) || 0)}개`);
  res.json({ ok: true });
});
app.delete('/api/products/:id', auth, adminOnly, (req, res) => {
  const product = ownProduct(req.params.id, req.session.user.orgId);
  if (!product) return res.status(404).json({ message: '제품을 찾을 수 없습니다.' });
  const used = db.prepare('SELECT 1 FROM purchases WHERE product_id=? UNION SELECT 1 FROM outbounds WHERE product_id=?').get(product.id, product.id);
  if (used) return res.status(400).json({ message: '입출고 기록이 있는 제품은 삭제할 수 없습니다.' });
  db.prepare('DELETE FROM products WHERE id=? AND org_id=?').run(product.id, req.session.user.orgId);
  log(req, '제품 삭제', '제품', product.name);
  res.json({ ok: true });
});

app.post('/api/purchases', auth, upload.single('image'), (req, res) => {
  const { vendor, inboundDate, productId, qty, unitPrice } = req.body;
  const product = ownProduct(productId, req.session.user.orgId);
  const q = Number(qty), price = Number(unitPrice) || 0;
  if (!product || !vendor || !inboundDate || q <= 0) return res.status(400).json({ message: '필수 항목을 확인하세요.' });
  const total = q * price;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
  db.transaction(() => {
    db.prepare('INSERT INTO purchases(org_id,vendor,inbound_date,product_id,qty,unit_price,total,image_url,created_by) VALUES(?,?,?,?,?,?,?,?,?)')
      .run(req.session.user.orgId, vendor, inboundDate, productId, q, price, total, imageUrl, req.session.user.id);
    db.prepare('UPDATE products SET stock=stock+?, vendor=?, last_inbound=? WHERE id=? AND org_id=?')
      .run(q, vendor, inboundDate, productId, req.session.user.orgId);
  })();
  log(req, '매입 등록', '매입', product.name, `${q}개 입고 · ${vendor}`);
  res.json({ ok: true });
});
app.post('/api/outbounds', auth, (req, res) => {
  const { outboundDate, productId, qty, memo = '' } = req.body;
  const product = ownProduct(productId, req.session.user.orgId);
  const q = Number(qty);
  if (!product || !outboundDate || q <= 0) return res.status(400).json({ message: '필수 항목을 확인하세요.' });
  if (product.stock < q) return res.status(400).json({ message: `현재 재고(${product.stock})보다 많이 출고할 수 없습니다.` });
  db.transaction(() => {
    db.prepare('INSERT INTO outbounds(org_id,outbound_date,product_id,qty,memo,created_by) VALUES(?,?,?,?,?,?)')
      .run(req.session.user.orgId, outboundDate, productId, q, memo, req.session.user.id);
    db.prepare('UPDATE products SET stock=stock-? WHERE id=? AND org_id=?').run(q, productId, req.session.user.orgId);
  })();
  log(req, '출고 등록', '출고', product.name, `${q}개 출고 · ${memo}`);
  res.json({ ok: true });
});

app.get('/api/purchases', auth, (req, res) => res.json(db.prepare(`SELECT p.*,pr.name product_name,u.name user_name
  FROM purchases p JOIN products pr ON pr.id=p.product_id JOIN users u ON u.id=p.created_by
  WHERE p.org_id=? ORDER BY p.inbound_date DESC,p.id DESC`).all(req.session.user.orgId)));
app.get('/api/outbounds', auth, (req, res) => res.json(db.prepare(`SELECT o.*,pr.name product_name,u.name user_name
  FROM outbounds o JOIN products pr ON pr.id=o.product_id JOIN users u ON u.id=o.created_by
  WHERE o.org_id=? ORDER BY o.outbound_date DESC,o.id DESC`).all(req.session.user.orgId)));
app.get('/api/audit-logs', auth, adminOnly, (req, res) => res.json(db.prepare('SELECT * FROM audit_logs WHERE org_id=? ORDER BY id DESC LIMIT 150').all(req.session.user.orgId)));

app.get('/api/users', auth, adminOnly, (req, res) => res.json(db.prepare('SELECT id,username,name,role,active,created_at FROM users WHERE org_id=? ORDER BY role DESC,name').all(req.session.user.orgId)));
app.post('/api/users', auth, adminOnly, (req, res) => {
  const { username, password, name, role = 'staff' } = req.body;
  if (!username?.trim() || !password || !name?.trim()) return res.status(400).json({ message: '이름, 아이디, 비밀번호를 모두 입력하세요.' });
  if (password.length < 4) return res.status(400).json({ message: '비밀번호는 4자리 이상 입력하세요.' });
  try {
    db.prepare('INSERT INTO users(org_id,username,password,name,role) VALUES(?,?,?,?,?)')
      .run(req.session.user.orgId, username.trim(), bcrypt.hashSync(password, 10), name.trim(), role === 'admin' ? 'admin' : 'staff');
    log(req, '직원 계정 추가', '직원', name.trim(), username.trim());
    res.json({ ok: true });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(400).json({ message: '이미 사용 중인 아이디입니다.' });
    throw e;
  }
});
app.patch('/api/users/:id/toggle', auth, adminOnly, (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id=? AND org_id=?').get(req.params.id, req.session.user.orgId);
  if (!target) return res.status(404).json({ message: '직원을 찾을 수 없습니다.' });
  if (target.id === req.session.user.id) return res.status(400).json({ message: '내 계정은 비활성화할 수 없습니다.' });
  const active = target.active ? 0 : 1;
  db.prepare('UPDATE users SET active=? WHERE id=?').run(active, target.id);
  log(req, active ? '직원 계정 활성화' : '직원 계정 비활성화', '직원', target.name);
  res.json({ ok: true });
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) return res.status(400).json({ message: '사진은 8MB 이하로 업로드하세요.' });
  console.error(err);
  res.status(500).json({ message: '처리 중 오류가 발생했습니다.' });
});
app.listen(PORT, () => console.log(`재고관리 실행: http://localhost:${PORT}`));
