require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const STORAGE_DIR = path.join(ROOT, "storage");
const MAX_UPLOAD_MB = Math.min(50, Math.max(1, Number(process.env.MAX_UPLOAD_MB || 20)));
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(STORAGE_DIR, { recursive: true });

if (process.env.NODE_ENV === "production" && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  throw new Error("Configure SESSION_SECRET com pelo menos 32 caracteres no ambiente de produção.");
}
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-only-change-this-session-secret";
const db = new Database(path.join(DATA_DIR, "botnexus.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS bots (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  zip_path TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'stopped',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));
app.use(express.json({ limit: "50kb" }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA_DIR }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.COOKIE_SECURE === "true",
    maxAge: 1000 * 60 * 60 * 8
  }
}));
app.use(express.static(path.join(ROOT, "public"), { index: false }));

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, STORAGE_DIR),
    filename: (_req, _file, cb) => cb(null, `${crypto.randomUUID()}.zip`)
  }),
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext !== ".zip") return cb(new Error("Envie apenas arquivos .zip."));
    cb(null, true);
  }
});

function esc(value = "") {
  return String(value).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect("/login");
  next();
}
function page(title, content, user) {
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · BotNexus</title><link rel="stylesheet" href="/style.css"></head><body>
  <header class="top"><a class="brand" href="/">BOT<span>NEXUS</span></a><nav>${user ? `<span class="welcome">Olá, ${esc(user.username)}</span><form method="post" action="/logout"><button class="ghost" type="submit">Sair</button></form>` : `<a href="/login">Entrar</a><a class="btn small" href="/register">Criar conta</a>`}</nav></header>
  <main class="wrap">${content}</main><footer>BotNexus · Painel de demonstração · Proteja seus tokens.</footer></body></html>`;
}
function currentUser(req) {
  return req.session.userId ? db.prepare("SELECT id, username FROM users WHERE id = ?").get(req.session.userId) : null;
}
function ownedBot(req, botId) {
  return db.prepare("SELECT * FROM bots WHERE id = ? AND user_id = ?").get(botId, req.session.userId);
}
function log(botId, message) {
  db.prepare("INSERT INTO logs (bot_id, message) VALUES (?, ?)").run(botId, String(message).slice(0, 1000));
  io.to(`bot:${botId}`).emit("log", { message: String(message), time: new Date().toLocaleTimeString("pt-BR") });
}

app.get("/", (req, res) => req.session.userId ? res.redirect("/dashboard") : res.redirect("/login"));
app.get("/register", (req, res) => res.send(page("Criar conta", `
<section class="auth card"><div class="eyebrow">COMECE AGORA</div><h1>Criar sua conta</h1><p class="muted">Seu painel de bots em um só lugar.</p>
<form method="post" action="/register" class="stack"><label>Usuário<input name="username" minlength="3" maxlength="24" pattern="[A-Za-z0-9_-]+" required autocomplete="username" placeholder="seu_usuario"></label><label>Senha<input type="password" name="password" minlength="10" maxlength="128" required autocomplete="new-password" placeholder="Mínimo de 10 caracteres"></label><button class="btn" type="submit">Criar conta</button></form><p class="muted">Já tem conta? <a href="/login">Entrar</a></p></section>`, null)));
app.post("/register", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  if (!/^[A-Za-z0-9_-]{3,24}$/.test(username) || password.length < 10 || password.length > 128) {
    return res.status(400).send(page("Erro", `<section class="card"><h1>Dados inválidos</h1><p>Use usuário de 3 a 24 caracteres (letras, números, _ ou -) e senha de 10 a 128 caracteres.</p><a href="/register">Voltar</a></section>`, null));
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").run(username, hash);
    req.session.userId = Number(result.lastInsertRowid);
    res.redirect("/dashboard");
  } catch {
    res.status(409).send(page("Usuário existente", `<section class="card"><h1>Esse usuário já existe</h1><a href="/register">Tentar outro</a></section>`, null));
  }
});
app.get("/login", (req, res) => res.send(page("Entrar", `
<section class="auth card"><div class="eyebrow">BEM-VINDO DE VOLTA</div><h1>Entrar no painel</h1><p class="muted">Gerencie seus projetos com segurança.</p>
<form method="post" action="/login" class="stack"><label>Usuário<input name="username" required autocomplete="username"></label><label>Senha<input type="password" name="password" required autocomplete="current-password"></label><button class="btn" type="submit">Entrar</button></form><p class="muted">Ainda não tem conta? <a href="/register">Criar conta</a></p></section>`, null)));
app.post("/login", async (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(String(req.body.username || "").trim());
  if (!user || !(await bcrypt.compare(String(req.body.password || ""), user.password_hash))) {
    return res.status(401).send(page("Falha no login", `<section class="card"><h1>Login não reconhecido</h1><p>Confira os dados e tente novamente.</p><a href="/login">Voltar</a></section>`, null));
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).send("Erro ao iniciar sessão.");
    req.session.userId = user.id;
    res.redirect("/dashboard");
  });
});
app.post("/logout", requireAuth, (req, res) => req.session.destroy(() => res.redirect("/login")));

app.get("/dashboard", requireAuth, (req, res) => {
  const user = currentUser(req);
  const bots = db.prepare("SELECT id, name, status, created_at FROM bots WHERE user_id = ? ORDER BY created_at DESC").all(user.id);
  const cards = bots.map(bot => `<article class="bot-card"><div class="bot-title"><div class="bot-icon">⌘</div><div><h3>${esc(bot.name)}</h3><span class="status ${bot.status === "running" ? "on" : ""}">${bot.status === "running" ? "● Online (simulado)" : "● Parado"}</span></div></div><p class="muted tiny">Criado em ${esc(bot.created_at)}</p><div class="actions"><a class="btn small" href="/bots/${encodeURIComponent(bot.id)}">Gerenciar</a><form method="post" action="/bots/${encodeURIComponent(bot.id)}/start"><button class="btn small" ${bot.status === "running" ? "disabled" : ""}>Iniciar</button></form><form method="post" action="/bots/${encodeURIComponent(bot.id)}/stop"><button class="ghost small" ${bot.status !== "running" ? "disabled" : ""}>Parar</button></form></div></article>`).join("");
  res.send(page("Dashboard", `<div class="hero"><div><div class="eyebrow">SEU CENTRO DE CONTROLE</div><h1>Dashboard<span class="blue">.</span></h1><p class="muted">Gerencie seus projetos Discord em um só lugar.</p></div><div class="hero-mark">BN<span>_</span></div></div>
  <section class="stats"><div class="stat"><span>Projetos</span><strong>${bots.length}</strong></div><div class="stat"><span>Em execução</span><strong>${bots.filter(b => b.status === "running").length}</strong></div><div class="stat"><span>Plano</span><strong>Starter</strong></div></section>
  <section class="section-head"><div><h2>Seus bots</h2><p class="muted">Envie um ZIP para cadastrar um projeto.</p></div></section>
  <section class="card upload"><form action="/bots" method="post" enctype="multipart/form-data" class="upload-form"><label>Nome do bot<input name="name" required minlength="2" maxlength="40" placeholder="Ex.: MeuBot"></label><label>Arquivo do projeto (.zip)<input type="file" name="project" accept=".zip,application/zip" required></label><button class="btn" type="submit">＋ Adicionar bot</button></form><p class="muted tiny">Limite atual: ${MAX_UPLOAD_MB} MB por arquivo. Uploads são armazenados, mas não executados automaticamente.</p></section>
  <section class="bot-grid">${cards || `<div class="empty"><div class="empty-icon">⌘</div><h3>Nenhum bot por aqui ainda</h3><p>Envie seu primeiro projeto ZIP acima para começar.</p></div>`}</section>
  <section class="notice"><strong>Importante:</strong> nesta versão, iniciar/parar altera o status de demonstração. A execução real de códigos enviados por usuários exige um worker isolado em containers com limites de CPU/RAM e controles adicionais.</section>`, user));
});

app.post("/bots", requireAuth, (req, res) => {
  upload.single("project")(req, res, err => {
    if (err) return res.status(400).send(page("Upload inválido", `<section class="card"><h1>Não foi possível enviar</h1><p>${esc(err.message)}</p><a href="/dashboard">Voltar ao painel</a></section>`, currentUser(req)));
    if (!req.file) return res.redirect("/dashboard");
    const name = String(req.body.name || "").trim().slice(0, 40);
    if (name.length < 2) {
      fs.unlink(req.file.path, () => {});
      return res.status(400).send("O nome deve ter pelo menos 2 caracteres.");
    }
    const id = crypto.randomUUID();
    db.prepare("INSERT INTO bots (id, user_id, name, zip_path) VALUES (?, ?, ?, ?)").run(id, req.session.userId, name, path.basename(req.file.path));
    log(id, `Projeto "${name}" enviado. Arquivo armazenado; execução real não ativada.`);
    res.redirect(`/bots/${id}`);
  });
});

app.get("/bots/:id", requireAuth, (req, res) => {
  const bot = ownedBot(req, req.params.id);
  if (!bot) return res.status(404).send(page("Não encontrado", `<section class="card"><h1>Bot não encontrado</h1><a href="/dashboard">Voltar</a></section>`, currentUser(req)));
  const logs = db.prepare("SELECT message, created_at FROM logs WHERE bot_id = ? ORDER BY id DESC LIMIT 100").all(bot.id).reverse();
  res.send(page(bot.name, `<a class="back" href="/dashboard">← Voltar ao painel</a><div class="hero"><div><div class="eyebrow">GERENCIAMENTO</div><h1>${esc(bot.name)}<span class="blue">.</span></h1><p class="muted">ID: ${esc(bot.id)}</p></div><div class="status-pill">${bot.status === "running" ? "● Online (simulado)" : "● Parado"}</div></div>
  <section class="stats"><div class="stat"><span>Status</span><strong>${bot.status === "running" ? "Online*" : "Parado"}</strong></div><div class="stat"><span>Runtime</span><strong>Node.js</strong></div><div class="stat"><span>Execução</span><strong>Desativada</strong></div></section>
  <section class="card"><h2>Controles</h2><div class="actions"><form method="post" action="/bots/${encodeURIComponent(bot.id)}/start"><button class="btn" ${bot.status === "running" ? "disabled" : ""}>▶ Iniciar</button></form><form method="post" action="/bots/${encodeURIComponent(bot.id)}/stop"><button class="ghost" ${bot.status !== "running" ? "disabled" : ""}>■ Parar</button></form><form method="post" action="/bots/${encodeURIComponent(bot.id)}/delete" onsubmit="return confirm('Excluir este projeto e seus logs?')"><button class="danger">Excluir</button></form></div><p class="muted tiny">* Status demonstrativo. Nenhum código enviado é executado por este painel.</p></section>
  <section class="card console"><div class="console-head"><h2>Console de logs</h2><span class="live-dot">● HISTÓRICO</span></div><div id="logs" class="logs">${logs.map(l => `<div class="log-line"><span>${esc(l.created_at)}</span> ${esc(l.message)}</div>`).join("") || `<div class="log-line">Nenhum log ainda.</div>`}</div></section>
  <section class="notice">A execução de projetos enviados deve ser adicionada por um serviço worker isolado, sem acesso aos segredos do painel. Não cole tokens no console.</section>
  <script src="/socket.io/socket.io.js"></script><script>const socket=io();socket.emit("join-bot",${JSON.stringify(bot.id)});socket.on("log",x=>{const e=document.createElement("div");e.className="log-line";const s=document.createElement("span");s.textContent=x.time; e.append(s,document.createTextNode(" "+x.message));document.querySelector("#logs").append(e);});</script>`, currentUser(req)));
});

function setBotStatus(req, res, status) {
  const bot = ownedBot(req, req.params.id);
  if (!bot) return res.status(404).send("Bot não encontrado.");
  db.prepare("UPDATE bots SET status = ? WHERE id = ? AND user_id = ?").run(status, bot.id, req.session.userId);
  log(bot.id, status === "running" ? "Solicitação de início recebida (status demonstrativo)." : "Solicitação de parada recebida (status demonstrativo).");
  res.redirect(`/bots/${bot.id}`);
}
app.post("/bots/:id/start", requireAuth, (req, res) => setBotStatus(req, res, "running"));
app.post("/bots/:id/stop", requireAuth, (req, res) => setBotStatus(req, res, "stopped"));
app.post("/bots/:id/delete", requireAuth, (req, res) => {
  const bot = ownedBot(req, req.params.id);
  if (!bot) return res.status(404).send("Bot não encontrado.");
  db.prepare("DELETE FROM bots WHERE id = ? AND user_id = ?").run(bot.id, req.session.userId);
  fs.unlink(path.join(STORAGE_DIR, path.basename(bot.zip_path)), () => {});
  res.redirect("/dashboard");
});

io.on("connection", socket => {
  socket.on("join-bot", botId => {
    if (typeof botId === "string" && /^[0-9a-f-]{36}$/i.test(botId)) socket.join(`bot:${botId}`);
  });
});

app.use((err, _req, res, _next) => {
  console.error("Erro no servidor:", err.message);
  if (res.headersSent) return;
  res.status(500).send(page("Erro", `<section class="card"><h1>Ocorreu um erro</h1><p>Não foi possível concluir a solicitação. Confira o terminal do servidor.</p><a href="/dashboard">Voltar ao painel</a></section>`, null));
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`BotNexus iniciado em http://localhost:${PORT}`);
  console.log(`Limite de upload: ${MAX_UPLOAD_MB} MB`);
});
