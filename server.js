const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const UPLOADS = path.join(ROOT, "uploads");
if (!fs.existsSync(UPLOADS)) fs.mkdirSync(UPLOADS, { recursive: true });

const db = new Database(path.join(ROOT, "music.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tracks (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 title TEXT NOT NULL,
 artist TEXT NOT NULL,
 filename TEXT NOT NULL,
 original_name TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS playlists (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 name TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS playlist_tracks (
 playlist_id INTEGER NOT NULL,
 track_id INTEGER NOT NULL,
 UNIQUE(playlist_id, track_id),
 FOREIGN KEY(playlist_id) REFERENCES playlists(id),
 FOREIGN KEY(track_id) REFERENCES tracks(id)
);
`);

app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly:true, sameSite:"lax", maxAge: 1000*60*60*24*7 }
}));
app.use(express.static(path.join(ROOT, "public")));
app.use("/uploads", express.static(UPLOADS));

const storage = multer.diskStorage({
 destination: (_, __, cb) => cb(null, UPLOADS),
 filename: (_, file, cb) => {
   const ext = path.extname(file.originalname).toLowerCase();
   cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
 }
});
const upload = multer({
 storage,
 limits: { fileSize: 50 * 1024 * 1024 },
 fileFilter: (_, file, cb) => {
   const ok = ["audio/mpeg","audio/mp3","audio/wav","audio/ogg","audio/x-wav"].includes(file.mimetype)
     || [".mp3",".wav",".ogg"].includes(path.extname(file.originalname).toLowerCase());
   cb(ok ? null : new Error("Разрешены MP3, WAV и OGG"), ok);
});

function auth(req,res,next){
  if(!req.session.userId) return res.status(401).json({error:"Нужно войти в аккаунт"});
  next();
}

app.get("/api/me", (req,res)=>{
  if(!req.session.userId) return res.json({user:null});
  const user = db.prepare("SELECT id, username, created_at FROM users WHERE id=?").get(req.session.userId);
  res.json({user:user || null});
});

app.post("/api/register", async (req,res)=>{
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  if(!/^[A-Za-zА-Яа-я0-9_]{3,24}$/.test(username))
    return res.status(400).json({error:"Ник: 3–24 символа, буквы, цифры или _"});
  if(password.length < 6) return res.status(400).json({error:"Пароль должен быть минимум 6 символов"});
  try{
    const hash = await bcrypt.hash(password, 10);
    const info = db.prepare("INSERT INTO users(username,password) VALUES(?,?)").run(username,hash);
    req.session.userId = info.lastInsertRowid;
    res.json({ok:true});
  }catch(e){ res.status(400).json({error:"Такой пользователь уже существует"}); }
});

app.post("/api/login", async (req,res)=>{
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE username=?").get(username);
  if(!user || !(await bcrypt.compare(password,user.password)))
    return res.status(401).json({error:"Неверный логин или пароль"});
  req.session.userId = user.id;
  res.json({ok:true});
});

app.post("/api/logout", (req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get("/api/tracks", (req,res)=>{
  const q = String(req.query.q || "").trim();
  let tracks;
  if(q){
    tracks = db.prepare(`
      SELECT t.id,t.title,t.artist,t.filename,t.created_at,u.username AS uploader
      FROM tracks t JOIN users u ON u.id=t.user_id
      WHERE t.title LIKE ? OR t.artist LIKE ? ORDER BY t.id DESC
    `).all(`%${q}%`,`%${q}%`);
  } else {
    tracks = db.prepare(`
      SELECT t.id,t.title,t.artist,t.filename,t.created_at,u.username AS uploader
      FROM tracks t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC
    `).all();
  }
  res.json(tracks.map(t=>({...t,url:`/uploads/${encodeURIComponent(t.filename)}`})));
});

app.post("/api/upload", auth, upload.single("audio"), (req,res)=>{
  if(!req.file) return res.status(400).json({error:"Выберите аудиофайл"});
  const title = String(req.body.title || path.parse(req.file.originalname).name).trim().slice(0,100);
  const artist = String(req.body.artist || req.session.username || "Неизвестный").trim().slice(0,100);
  const info = db.prepare(`
    INSERT INTO tracks(user_id,title,artist,filename,original_name) VALUES(?,?,?,?,?)
  `).run(req.session.userId,title,artist,req.file.filename,req.file.originalname);
  res.json({ok:true,id:info.lastInsertRowid});
});

app.delete("/api/tracks/:id", auth, (req,res)=>{
  const track = db.prepare("SELECT * FROM tracks WHERE id=? AND user_id=?").get(req.params.id,req.session.userId);
  if(!track) return res.status(404).json({error:"Трек не найден"});
  db.prepare("DELETE FROM playlist_tracks WHERE track_id=?").run(track.id);
  db.prepare("DELETE FROM tracks WHERE id=?").run(track.id);
  try{ fs.unlinkSync(path.join(UPLOADS,track.filename)); }catch{}
  res.json({ok:true});
});

app.get("/api/playlists", auth, (req,res)=>{
  const lists = db.prepare("SELECT * FROM playlists WHERE user_id=? ORDER BY id DESC").all(req.session.userId);
  for(const p of lists){
    p.tracks = db.prepare(`
      SELECT t.id,t.title,t.artist,t.filename FROM tracks t
      JOIN playlist_tracks pt ON pt.track_id=t.id
      WHERE pt.playlist_id=? ORDER BY pt.rowid DESC
    `).all(p.id).map(t=>({...t,url:`/uploads/${encodeURIComponent(t.filename)}`}));
  }
  res.json(lists);
});

app.post("/api/playlists", auth, (req,res)=>{
  const name = String(req.body.name || "").trim().slice(0,60);
  if(!name) return res.status(400).json({error:"Введите название"});
  const info = db.prepare("INSERT INTO playlists(user_id,name) VALUES(?,?)").run(req.session.userId,name);
  res.json({ok:true,id:info.lastInsertRowid});
});

app.delete("/api/playlists/:id", auth, (req,res)=>{
  const p = db.prepare("SELECT * FROM playlists WHERE id=? AND user_id=?").get(req.params.id,req.session.userId);
  if(!p) return res.status(404).json({error:"Плейлист не найден"});
  db.prepare("DELETE FROM playlist_tracks WHERE playlist_id=?").run(p.id);
  db.prepare("DELETE FROM playlists WHERE id=?").run(p.id);
  res.json({ok:true});
});

app.post("/api/playlists/:id/tracks", auth, (req,res)=>{
  const playlist = db.prepare("SELECT * FROM playlists WHERE id=? AND user_id=?").get(req.params.id,req.session.userId);
  const track = db.prepare("SELECT * FROM tracks WHERE id=?").get(req.body.trackId);
  if(!playlist || !track) return res.status(404).json({error:"Не найдено"});
  db.prepare("INSERT OR IGNORE INTO playlist_tracks(playlist_id,track_id) VALUES(?,?)").run(playlist.id,track.id);
  res.json({ok:true});
});

app.use((err,req,res,next)=>{
  if(err instanceof multer.MulterError) return res.status(400).json({error:"Файл слишком большой (максимум 50 МБ)"});
  if(err) return res.status(400).json({error:err.message || "Ошибка сервера"});
  next(err);
});

app.listen(PORT,()=>console.log(`Music site: http://localhost:${PORT}`));
