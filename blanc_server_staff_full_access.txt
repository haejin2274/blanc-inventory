const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const uploadDir = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL 환경변수가 없습니다. Render Environment에 Supabase 주소를 저장하세요.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-before-deploying',
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: { sameSite: 'lax', secure: false }
}));
app.use('/uploads', express.static(uploadDir));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) => cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${path.extname(file.originalname)}`)
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (_, file, cb) => cb(null, /^image\//.test(file.mimetype))
});

const q = (text, params = []) => pool.query(text, params);
const one = async (text, params = []) => (await q(text, params)).rows[0];
const all = async (text, params = []) => (await q(text, params)).rows;
const today = () => new Date().toISOString().slice(0, 10);

async function init() {
  // 기존 Supabase 테이블에도 새 항목을 안전하게 추가합니다.
  await q(`alter table products add column if not exists expiry_date date`);
  await q(`alter table products add column if not exists note text not null default ''`);

  await q(`
    insert into organizations (name, short_name)
    values ('블랑여성의원','블랑여성의원'), ('닥터플로셀','닥터플로셀')
    on conflict (name) do nothing
  `);

  const blanc = await one('select * from organizations where name=$1', ['블랑여성의원']);
  const flow = await one('select * from organizations where name=$1', ['닥터플로셀']);
  const count = await one('select count(*)::int as c from users');

  // 처음 설치할 때는 관리자 계정 하나만 만듭니다.
  if (!count.c) {
    const hash = bcrypt.hashSync('1234', 10);
    const admin = await one(
      `insert into users(org_id,username,password,name,role) values($1,$2,$3,$4,'admin') returning id`,
      [blanc.id, 'blancadmin', hash, '채혜진']
    );
    await q('insert into user_organizations(user_id,org_id) values($1,$2) on conflict do nothing', [admin.id, blanc.id]);
    await q('insert into user_organizations(user_id,org_id) values($1,$2) on conflict do nothing', [admin.id, flow.id]);
  }

  // 관리자와 직원 모두 블랑여성의원·닥터플로셀을 전환할 수 있게 연결합니다.
  const allUsers = await all(`select id from users where active=true`);
  for (const user of allUsers) {
    await q('insert into user_organizations(user_id,org_id) values($1,$2) on conflict do nothing', [user.id, blanc.id]);
    await q('insert into user_organizations(user_id,org_id) values($1,$2) on conflict do nothing', [user.id, flow.id]);
  }

  // 이전에 자동으로 만들어진 닥터플로셀 관리자 계정은 로그인·목록에서 제외합니다.
  await q(`update users set active=false where username='flowcelladmin'`);
}

function auth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ message: '로그인이 필요합니다.' });
  next();
}
function adminOnly(req, res, next) {
  if (req.session.user?.role !== 'admin') return res.status(403).json({ message: '관리자만 사용할 수 있습니다.' });
  next();
}
async function orgsForUser(userId) {
  return all(`select o.id,o.name from user_organizations uo join organizations o on o.id=uo.org_id where uo.user_id=$1 order by o.id`, [userId]);
}
async function userInfo(row, activeOrgId) {
  const orgs = await orgsForUser(row.id);
  const org = orgs.find(x => Number(x.id) === Number(activeOrgId)) || orgs[0];
  return { id: row.id, orgId: org?.id, orgName: org?.name, organizations: orgs, username: row.username, name: row.name, role: row.role };
}
function productRow(row) {
  return { ...row, status: Number(row.stock) === 0 ? 'none' : Number(row.stock) <= Number(row.min_stock) ? 'low' : 'good' };
}
async function log(req, action, targetType, targetName, detail = '') {
  const u = req.session.user;
  await q(`insert into audit_logs(org_id,user_id,user_name,action,target_type,target_name,detail) values($1,$2,$3,$4,$5,$6,$7)`, [u.orgId, u.id, u.name, action, targetType, targetName, detail]);
}
async function ownProduct(productId, orgId) {
  return one('select * from products where id=$1 and org_id=$2', [productId, orgId]);
}

app.post('/api/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const row = await one('select * from users where username=$1 and active=true', [username]);
    if (!row || !bcrypt.compareSync(password || '', row.password)) return res.status(401).json({ message: '아이디 또는 비밀번호가 올바르지 않습니다.' });
    const user = await userInfo(row);
    if (!user.orgId) return res.status(403).json({ message: '사용 가능한 사업장이 없습니다. 관리자에게 문의하세요.' });
    req.session.user = user;
    req.session.save(() => res.json({ user }));
  } catch (e) { next(e); }
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', (req, res) => res.json({ user: req.session.user || null }));
app.post('/api/switch-org', auth, async (req, res, next) => {
  try {
    const orgId = Number(req.body.orgId);
    const row = await one('select * from users where id=$1 and active=true', [req.session.user.id]);
    const allowed = (await orgsForUser(row.id)).some(x => Number(x.id) === orgId);
    if (!allowed) return res.status(403).json({ message: '접근 권한이 없는 사업장입니다.' });
    req.session.user = await userInfo(row, orgId);
    req.session.save(() => res.json({ user: req.session.user }));
  } catch (e) { next(e); }
});

app.get('/api/dashboard', auth, async (req, res, next) => {
  try {
    const org = req.session.user.orgId;
    const low = (await one('select count(*)::int as c from products where org_id=$1 and stock<=min_stock', [org])).c;
    const todayIn = (await one('select coalesce(sum(qty),0)::int as c from purchases where org_id=$1 and inbound_date=$2', [org, today()])).c;
    const todayOut = (await one('select coalesce(sum(qty),0)::int as c from outbounds where org_id=$1 and outbound_date=$2', [org, today()])).c;
    const recent = await all(`select p.inbound_date,p.vendor,pr.name,p.qty,p.total,u.name as user_name
      from purchases p join products pr on pr.id=p.product_id join users u on u.id=p.created_by
      where p.org_id=$1 order by p.id desc limit 5`, [org]);
    const lowRows = (await all('select * from products where org_id=$1 and stock<=min_stock order by stock asc,name', [org])).map(productRow);
    res.json({ low, todayIn, todayOut, recent, lowRows });
  } catch (e) { next(e); }
});

app.get('/api/products', auth, async (req, res, next) => {
  try { res.json((await all('select * from products where org_id=$1 order by name', [req.session.user.orgId])).map(productRow)); } catch (e) { next(e); }
});
app.post('/api/products', auth, async (req, res, next) => {
  try {
    const { name, spec = '', vendor = '', stock = 0, minStock = 0, expiryDate = null, note = '' } = req.body;
    if (!name?.trim()) return res.status(400).json({ message: '제품명을 입력하세요.' });
    const row = await one(`insert into products(org_id,name,spec,vendor,stock,min_stock,expiry_date,note,created_by) values($1,$2,$3,$4,$5,$6,$7,$8,$9) returning *`,
      [req.session.user.orgId, name.trim(), spec.trim(), vendor.trim(), Math.max(0, Number(stock) || 0), Math.max(0, Number(minStock) || 0), expiryDate || null, note.trim(), req.session.user.id]);
    await log(req, '제품 추가', '제품', name.trim(), `초기 재고 ${Number(stock) || 0}개`);
    res.json(row);
  } catch (e) { next(e); }
});
app.put('/api/products/:id', auth, async (req, res, next) => {
  try {
    const product = await ownProduct(req.params.id, req.session.user.orgId);
    if (!product) return res.status(404).json({ message: '제품을 찾을 수 없습니다.' });
    const { name, spec = '', vendor = '', stock = 0, minStock = 0, expiryDate = null, note = '' } = req.body;
    await q('update products set name=$1,spec=$2,vendor=$3,stock=$4,min_stock=$5,expiry_date=$6,note=$7 where id=$8 and org_id=$9',
      [name, spec, vendor, Math.max(0, Number(stock) || 0), Math.max(0, Number(minStock) || 0), expiryDate || null, note.trim(), product.id, req.session.user.orgId]);
    await log(req, '제품 수정', '제품', name, `재고 ${product.stock}개 → ${Math.max(0, Number(stock) || 0)}개`);
    res.json({ ok: true });
  } catch (e) { next(e); }
});
app.delete('/api/products/:id', auth, async (req, res, next) => {
  try {
    const product = await ownProduct(req.params.id, req.session.user.orgId);
    if (!product) return res.status(404).json({ message: '제품을 찾을 수 없습니다.' });
    const used = await one('select 1 from purchases where product_id=$1 union select 1 from outbounds where product_id=$1 limit 1', [product.id]);
    if (used) return res.status(400).json({ message: '입출고 기록이 있는 제품은 삭제할 수 없습니다.' });
    await q('delete from products where id=$1 and org_id=$2', [product.id, req.session.user.orgId]);
    await log(req, '제품 삭제', '제품', product.name);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.post('/api/purchases', auth, upload.single('image'), async (req, res, next) => {
  const client = await pool.connect();
  try {
    const { vendor, inboundDate, productId, qty, unitPrice } = req.body;
    const product = await ownProduct(productId, req.session.user.orgId);
    const amount = Number(qty), price = Number(unitPrice) || 0;
    if (!product || !vendor || !inboundDate || amount <= 0) return res.status(400).json({ message: '필수 항목을 확인하세요.' });
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
    await client.query('begin');
    await client.query(`insert into purchases(org_id,vendor,inbound_date,product_id,qty,unit_price,total,image_url,created_by) values($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [req.session.user.orgId, vendor, inboundDate, productId, amount, price, amount * price, imageUrl, req.session.user.id]);
    await client.query('update products set stock=stock+$1,vendor=$2,last_inbound=$3 where id=$4 and org_id=$5', [amount, vendor, inboundDate, productId, req.session.user.orgId]);
    await client.query('commit');
    await log(req, '매입 등록', '매입', product.name, `${amount}개 입고 · ${vendor}`);
    res.json({ ok: true });
  } catch (e) { await client.query('rollback'); next(e); } finally { client.release(); }
});
app.post('/api/outbounds', auth, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const { outboundDate, productId, qty, memo = '' } = req.body;
    const product = await ownProduct(productId, req.session.user.orgId);
    const amount = Number(qty);
    if (!product || !outboundDate || amount <= 0) return res.status(400).json({ message: '필수 항목을 확인하세요.' });
    if (Number(product.stock) < amount) return res.status(400).json({ message: `현재 재고(${product.stock})보다 많이 출고할 수 없습니다.` });
    await client.query('begin');
    await client.query(`insert into outbounds(org_id,outbound_date,product_id,qty,memo,created_by) values($1,$2,$3,$4,$5,$6)`, [req.session.user.orgId, outboundDate, productId, amount, memo, req.session.user.id]);
    await client.query('update products set stock=stock-$1 where id=$2 and org_id=$3', [amount, productId, req.session.user.orgId]);
    await client.query('commit');
    await log(req, '출고 등록', '출고', product.name, `${amount}개 출고 · ${memo}`);
    res.json({ ok: true });
  } catch (e) { await client.query('rollback'); next(e); } finally { client.release(); }
});

app.get('/api/purchases', auth, async (req, res, next) => { try { res.json(await all(`select p.*,pr.name product_name,u.name user_name from purchases p join products pr on pr.id=p.product_id join users u on u.id=p.created_by where p.org_id=$1 order by p.inbound_date desc,p.id desc`, [req.session.user.orgId])); } catch (e) { next(e); } });
app.get('/api/outbounds', auth, async (req, res, next) => { try { res.json(await all(`select o.*,pr.name product_name,u.name user_name from outbounds o join products pr on pr.id=o.product_id join users u on u.id=o.created_by where o.org_id=$1 order by o.outbound_date desc,o.id desc`, [req.session.user.orgId])); } catch (e) { next(e); } });
app.get('/api/audit-logs', auth, async (req, res, next) => {
  try { res.json(await all('select * from audit_logs where org_id=$1 order by id desc limit 150', [req.session.user.orgId])); } catch (e) { next(e); }
});

app.get('/api/users', auth, adminOnly, async (req, res, next) => {
  try { res.json(await all(`select u.id,u.username,u.name,u.role,u.active,u.created_at,string_agg(o.name,' · ' order by o.id) as organizations from users u join user_organizations uo on uo.user_id=u.id join organizations o on o.id=uo.org_id where u.active=true group by u.id order by u.role desc,u.name`)); } catch (e) { next(e); }
});
app.post('/api/users', auth, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const { username, password, name, role = 'staff' } = req.body;
    // 직원은 직원 계정만 만들 수 있고, 관리자만 관리자 계정을 만들 수 있습니다.
    const newRole = req.session.user.role === 'admin' && role === 'admin' ? 'admin' : 'staff';
    // 새 계정은 기본으로 두 사업장을 모두 사용할 수 있습니다.
    const ids = (await all(`select id from organizations where name in ('블랑여성의원','닥터플로셀') order by id`)).map(x => Number(x.id));
    if (!username?.trim() || !password || !name?.trim()) return res.status(400).json({ message: '이름, 아이디, 비밀번호를 모두 입력하세요.' });
    if (password.length < 4) return res.status(400).json({ message: '비밀번호는 4자리 이상 입력하세요.' });
    if (!ids.length) return res.status(400).json({ message: '사용 사업장을 하나 이상 선택하세요.' });
    const valid = (await client.query('select count(*)::int as c from organizations where id = any($1::bigint[])', [ids])).rows[0].c;
    if (valid !== ids.length) return res.status(400).json({ message: '사업장 선택이 올바르지 않습니다.' });
    await client.query('begin');
    const created = await client.query(`insert into users(org_id,username,password,name,role) values($1,$2,$3,$4,$5) returning id`, [ids[0], username.trim(), bcrypt.hashSync(password, 10), name.trim(), newRole]);
    for (const orgId of ids) await client.query('insert into user_organizations(user_id,org_id) values($1,$2)', [created.rows[0].id, orgId]);
    await client.query('commit');
    await log(req, newRole === 'admin' ? '관리자 계정 추가' : '직원 계정 추가', newRole === 'admin' ? '관리자' : '직원', name.trim(), `${username.trim()} · 블랑여성의원 · 닥터플로셀 사용`);
    res.json({ ok: true });
  } catch (e) {
    await client.query('rollback');
    if (e.code === '23505') return res.status(400).json({ message: '이미 사용 중인 아이디입니다.' });
    next(e);
  } finally { client.release(); }
});
app.patch('/api/users/:id/toggle', auth, adminOnly, async (req, res, next) => {
  try {
    const target = await one('select * from users where id=$1', [req.params.id]);
    if (!target) return res.status(404).json({ message: '직원을 찾을 수 없습니다.' });
    if (Number(target.id) === Number(req.session.user.id)) return res.status(400).json({ message: '내 계정은 비활성화할 수 없습니다.' });
    const active = !target.active;
    await q('update users set active=$1 where id=$2', [active, target.id]);
    await log(req, active ? '직원 계정 활성화' : '직원 계정 비활성화', '직원', target.name);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// 계정 삭제: 기존 매입·출고·기록은 보존하고, 해당 계정만 로그인/목록에서 제거합니다.
app.delete('/api/users/:id', auth, adminOnly, async (req, res, next) => {
  try {
    const target = await one('select * from users where id=$1', [req.params.id]);
    if (!target) return res.status(404).json({ message: '계정을 찾을 수 없습니다.' });
    if (Number(target.id) === Number(req.session.user.id)) {
      return res.status(400).json({ message: '현재 로그인한 내 계정은 삭제할 수 없습니다. 새 관리자 계정으로 로그인한 뒤 삭제하세요.' });
    }
    await q('update users set active=false where id=$1', [target.id]);
    await log(req, '계정 삭제', target.role === 'admin' ? '관리자' : '직원', target.name, `${target.username} 계정을 삭제 처리`);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) return res.status(400).json({ message: '사진은 8MB 이하로 업로드하세요.' });
  console.error(err);
  res.status(500).json({ message: '처리 중 오류가 발생했습니다.' });
});

init().then(() => app.listen(PORT, () => console.log(`재고관리 실행: http://localhost:${PORT}`))).catch(err => { console.error(err); process.exit(1); });
