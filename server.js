const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database(path.join(__dirname, 'data', 'blanc.db'));
const uploadDir = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: process.env.SESSION_SECRET || 'change-this-before-deploying', resave:false, saveUninitialized:false, cookie:{sameSite:'lax', secure:false} }));
app.use('/uploads', express.static(uploadDir));
app.use(express.static(__dirname));

const storage = multer.diskStorage({
 destination: (_,__,cb)=>cb(null,uploadDir),
 filename: (_,file,cb)=>cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${path.extname(file.originalname)}`)
});
const upload = multer({ storage, limits:{fileSize:8*1024*1024}, fileFilter:(_,file,cb)=> cb(null, /^image\//.test(file.mimetype)) });

function init(){
 db.exec(`
 CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, name TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT NOT NULL, spec TEXT, vendor TEXT, stock INTEGER NOT NULL DEFAULT 0, min_stock INTEGER NOT NULL DEFAULT 0, last_inbound TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
 CREATE TABLE IF NOT EXISTS purchases (id INTEGER PRIMARY KEY, vendor TEXT NOT NULL, inbound_date TEXT NOT NULL, product_id INTEGER NOT NULL, qty INTEGER NOT NULL, unit_price INTEGER NOT NULL DEFAULT 0, total INTEGER NOT NULL DEFAULT 0, image_url TEXT, created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(product_id) REFERENCES products(id));
 CREATE TABLE IF NOT EXISTS outbounds (id INTEGER PRIMARY KEY, outbound_date TEXT NOT NULL, product_id INTEGER NOT NULL, qty INTEGER NOT NULL, memo TEXT, created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(product_id) REFERENCES products(id));
 `);
 const admin = db.prepare('SELECT id FROM users WHERE username=?').get('admin');
 if(!admin) db.prepare('INSERT INTO users(username,password,name) VALUES(?,?,?)').run('admin',bcrypt.hashSync('1234',10),'관리자');
 const count = db.prepare('SELECT COUNT(*) c FROM products').get().c;
 if(!count){
   const insert=db.prepare('INSERT INTO products(name,spec,vendor,stock,min_stock,last_inbound) VALUES(?,?,?,?,?,?)');
   insert.run('보톡스','50 units','블랑메디컬',5,5,'2026-07-01');
   insert.run('필러','1cc','블랑메디컬',10,6,'2026-07-03');
   insert.run('진정 마스크','10매','뷰티서플라이',3,10,'2026-06-28');
 }
}
init();
function auth(req,res,next){ if(!req.session.user) return res.status(401).json({message:'로그인이 필요합니다.'}); next(); }
function productRow(row){ return {...row, status: row.stock===0?'none':row.stock<row.min_stock?'low':'good'}; }

app.post('/api/login',(req,res)=>{ const {username,password}=req.body; const user=db.prepare('SELECT * FROM users WHERE username=?').get(username); if(!user || !bcrypt.compareSync(password||'',user.password)) return res.status(401).json({message:'아이디 또는 비밀번호가 올바르지 않습니다.'}); req.session.user={id:user.id,name:user.name,username:user.username}; res.json({user:req.session.user}); });
app.post('/api/logout',auth,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/me',(req,res)=>res.json({user:req.session.user||null}));

app.get('/api/dashboard',auth,(req,res)=>{
 const total=db.prepare('SELECT COUNT(*) c FROM products').get().c;
 const low=db.prepare('SELECT COUNT(*) c FROM products WHERE stock<=min_stock').get().c;
 const today=new Date().toISOString().slice(0,10);
 const todayIn=db.prepare('SELECT COALESCE(SUM(qty),0) c FROM purchases WHERE inbound_date=?').get(today).c;
 const recent=db.prepare(`SELECT p.id,p.inbound_date,p.vendor,pr.name,p.qty,p.total FROM purchases p JOIN products pr ON pr.id=p.product_id ORDER BY p.id DESC LIMIT 5`).all();
 const lowRows=db.prepare('SELECT * FROM products WHERE stock<=min_stock ORDER BY stock ASC').all().map(productRow);
 res.json({total,low,todayIn,recent,lowRows});
});
app.get('/api/products',auth,(req,res)=>res.json(db.prepare('SELECT * FROM products ORDER BY name').all().map(productRow)));
app.post('/api/products',auth,(req,res)=>{ const {name,spec='',vendor='',stock=0,minStock=0}=req.body; if(!name?.trim()) return res.status(400).json({message:'제품명을 입력하세요.'}); const r=db.prepare('INSERT INTO products(name,spec,vendor,stock,min_stock) VALUES(?,?,?,?,?)').run(name.trim(),spec.trim(),vendor.trim(),Number(stock)||0,Number(minStock)||0); res.json(db.prepare('SELECT * FROM products WHERE id=?').get(r.lastInsertRowid)); });
app.put('/api/products/:id',auth,(req,res)=>{ const {name,spec='',vendor='',stock=0,minStock=0}=req.body; db.prepare('UPDATE products SET name=?,spec=?,vendor=?,stock=?,min_stock=? WHERE id=?').run(name,spec,vendor,Number(stock)||0,Number(minStock)||0,req.params.id); res.json({ok:true}); });
app.delete('/api/products/:id',auth,(req,res)=>{ const used=db.prepare('SELECT 1 FROM purchases WHERE product_id=? UNION SELECT 1 FROM outbounds WHERE product_id=?').get(req.params.id,req.params.id); if(used) return res.status(400).json({message:'입출고 기록이 있는 제품은 삭제할 수 없습니다.'}); db.prepare('DELETE FROM products WHERE id=?').run(req.params.id); res.json({ok:true}); });

app.post('/api/purchases',auth,upload.single('image'),(req,res)=>{ const {vendor,inboundDate,productId,qty,unitPrice}=req.body; const product=db.prepare('SELECT * FROM products WHERE id=?').get(productId); if(!product) return res.status(400).json({message:'제품을 선택하세요.'}); const q=Number(qty), price=Number(unitPrice)||0; if(!vendor||!inboundDate||q<=0) return res.status(400).json({message:'필수 항목을 확인하세요.'}); const total=q*price; const imageUrl=req.file?`/uploads/${req.file.filename}`:null; const tx=db.transaction(()=>{ db.prepare('INSERT INTO purchases(vendor,inbound_date,product_id,qty,unit_price,total,image_url,created_by) VALUES(?,?,?,?,?,?,?,?)').run(vendor,inboundDate,productId,q,price,total,imageUrl,req.session.user.id); db.prepare('UPDATE products SET stock=stock+?, vendor=?, last_inbound=? WHERE id=?').run(q,vendor,inboundDate,productId); }); tx(); res.json({ok:true}); });
app.post('/api/outbounds',auth,(req,res)=>{ const {outboundDate,productId,qty,memo=''}=req.body; const product=db.prepare('SELECT * FROM products WHERE id=?').get(productId); const q=Number(qty); if(!product||!outboundDate||q<=0) return res.status(400).json({message:'필수 항목을 확인하세요.'}); if(product.stock<q) return res.status(400).json({message:`현재 재고(${product.stock})보다 많이 출고할 수 없습니다.`}); const tx=db.transaction(()=>{ db.prepare('INSERT INTO outbounds(outbound_date,product_id,qty,memo,created_by) VALUES(?,?,?,?,?)').run(outboundDate,productId,q,memo,req.session.user.id); db.prepare('UPDATE products SET stock=stock-? WHERE id=?').run(q,productId); }); tx(); res.json({ok:true}); });
app.get('/api/purchases',auth,(req,res)=>res.json(db.prepare('SELECT p.*,pr.name product_name FROM purchases p JOIN products pr ON pr.id=p.product_id ORDER BY p.inbound_date DESC,p.id DESC').all()));
app.get('/api/outbounds',auth,(req,res)=>res.json(db.prepare('SELECT o.*,pr.name product_name FROM outbounds o JOIN products pr ON pr.id=o.product_id ORDER BY o.outbound_date DESC,o.id DESC').all()));
app.use((err,req,res,next)=>{ if(err instanceof multer.MulterError) return res.status(400).json({message:'사진은 8MB 이하로 업로드하세요.'}); console.error(err); res.status(500).json({message:'처리 중 오류가 발생했습니다.'}); });
app.listen(PORT,()=>console.log(`블랑 재고관리 실행: http://localhost:${PORT}`));
