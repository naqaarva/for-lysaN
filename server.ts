import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import express, { type NextFunction, type Request, type Response } from 'express';
import { WebSocket, WebSocketServer } from 'ws';
import type {
  CoupleSpace,
  HugEvent,
  LoveNote,
  MemoryItem,
  OpenWhenLetter,
  PartnerLocation,
  SurpriseItem,
} from './src/types.ts';

interface StoredUser {
  id: string;
  email: string;
  name: string;
  passwordHash: string;
  passwordSalt: string;
  coupleId: string | null;
  createdAt: string;
}

interface DatabaseSchema {
  users: Record<string, StoredUser>;
  couples: Record<string, CoupleSpace>;
}

interface AuthenticatedRequest extends Request {
  authUser?: StoredUser;
}

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.resolve(process.cwd(), 'data');
const DB_FILE = path.resolve(DATA_DIR, 'for-lysa-db.json');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

function ensureDb(): DatabaseSchema {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(DB_FILE)) {
    const initial: DatabaseSchema = { users: {}, couples: {} };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2), 'utf-8');
    return initial;
  }
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf-8');
    const parsed = JSON.parse(raw) as DatabaseSchema;
    return {
      users: parsed.users || {},
      couples: parsed.couples || {},
    };
  } catch {
    return { users: {}, couples: {} };
  }
}

const db: DatabaseSchema = ensureDb();

function persistDb(): void {
  const tmpFile = `${DB_FILE}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(db, null, 2), 'utf-8');
  fs.renameSync(tmpFile, DB_FILE);
}

function hashPassword(password: string, salt: string): string {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function verifyPassword(password: string, salt: string, expectedHash: string): boolean {
  const computed = crypto.scryptSync(password, salt, 64);
  const expectedBuf = Buffer.from(expectedHash, 'hex');
  if (computed.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(computed, expectedBuf);
}

function signToken(userId: string): string {
  const payload = Buffer.from(
    JSON.stringify({
      sub: userId,
      iat: Date.now(),
      exp: Date.now() + 1000 * 60 * 60 * 24 * 30,
    }),
  ).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifyToken(token: string): string | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expectedBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return null;
  }
  try {
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8')) as {
      sub?: string;
      exp?: number;
    };
    if (!parsed.sub || !parsed.exp || Date.now() > parsed.exp) return null;
    return parsed.sub;
  } catch {
    return null;
  }
}

function sanitizeText(value: unknown, maxLen: number): string {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLen);
}

function isSafeImageUrl(url: string): boolean {
  if (
    (url.startsWith('/assets/couple/') ||
      url.startsWith('/assets/aistudio/') ||
      url.startsWith('/src/assets/images/')) &&
    !url.includes('..')
  ) {
    return true;
  }
  if (/^data:image\/(png|jpeg|jpg|webp);base64,[A-Za-z0-9+/=]+$/.test(url) && url.length <= 2_500_000) {
    return true;
  }
  return false;
}

function generatePairCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = 'LYSA';
  for (let i = 0; i < 4; i++) {
    code += chars[crypto.randomInt(0, chars.length)];
  }
  return code;
}

function createInitialCoupleSpace(creator: StoredUser): CoupleSpace {
  const coupleId = `cpl_${crypto.randomUUID().slice(0, 12)}`;
  const code = generatePairCode();
  const today = new Date();
  const nextAnniv = new Date(today.getFullYear(), today.getMonth(), today.getDate() + 30);
  const startDate = new Date(today.getFullYear(), today.getMonth(), today.getDate());
  const fmt = (d: Date) => d.toISOString().slice(0, 10);
  const nowIso = new Date().toISOString();

  const userMemories: MemoryItem[] = [
    {
      id: `mem_${crypto.randomUUID().slice(0, 8)}`,
      authorId: creator.id,
      authorName: creator.name,
      title: 'Kita Berdua',
      caption: '',
      date: fmt(today),
      location: 'Bersama',
      imageUrl: '/assets/couple/kenangan-1.jpeg',
      createdAt: nowIso,
    },
    {
      id: `mem_${crypto.randomUUID().slice(0, 8)}`,
      authorId: creator.id,
      authorName: creator.name,
      title: 'Mirror Selfie',
      caption: '',
      date: fmt(today),
      location: 'Bersama',
      imageUrl: '/assets/couple/kenangan-2.jpeg',
      createdAt: nowIso,
    },
    {
      id: `mem_${crypto.randomUUID().slice(0, 8)}`,
      authorId: creator.id,
      authorName: creator.name,
      title: 'Momen Favorit',
      caption: '',
      date: fmt(today),
      location: 'Bersama',
      imageUrl: '/assets/couple/kenangan-3.jpeg',
      createdAt: nowIso,
    },
  ];

  return {
    id: coupleId,
    code,
    title: 'For Lysa',
    anniversaryDate: fmt(nextAnniv),
    relationshipStartDate: fmt(startDate),
    members: [{ id: creator.id, name: creator.name, email: creator.email }],
    locations: {},
    loveNotes: [],
    memories: userMemories,
    letters: [],
    surprises: [],
    hugs: [],
    hugCount: 0,
  };
}

function getCoupleForUser(user: StoredUser): CoupleSpace | null {
  if (!user.coupleId) return null;
  return db.couples[user.coupleId] || null;
}

const app = express();
app.use(express.json({ limit: '4mb' }));

function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
  const userId = token ? verifyToken(token) : null;
  if (!userId || !db.users[userId]) {
    res.status(401).json({ error: 'Sesi tidak valid. Silakan masuk kembali.' });
    return;
  }
  req.authUser = db.users[userId];
  next();
}

const wsClients = new Map<WebSocket, { userId: string; coupleId: string | null }>();

function getOnlineUserIds(coupleId: string | null): string[] {
  if (!coupleId) return [];
  const ids = new Set<string>();
  for (const [client, meta] of wsClients.entries()) {
    if (meta.coupleId === coupleId && meta.userId && client.readyState === WebSocket.OPEN) {
      ids.add(meta.userId);
    }
  }
  return Array.from(ids);
}

function broadcastCoupleUpdate(coupleId: string, eventType: string, payload: unknown): void {
  const couple = db.couples[coupleId];
  if (!couple) return;
  const onlineUserIds = getOnlineUserIds(coupleId);
  const frame = JSON.stringify({ type: eventType, payload, couple, onlineUserIds });
  for (const [client, meta] of wsClients.entries()) {
    if (meta.coupleId === coupleId && client.readyState === WebSocket.OPEN) {
      client.send(frame);
    }
  }
}

function syncWsCoupleId(userId: string, coupleId: string | null): void {
  for (const [, meta] of wsClients.entries()) {
    if (meta.userId === userId) {
      meta.coupleId = coupleId;
    }
  }
}

app.post('/api/auth/register', (req: Request, res: Response) => {
  const email = sanitizeText(req.body?.email, 120).toLowerCase();
  const name = sanitizeText(req.body?.name, 60);
  const password = typeof req.body?.password === 'string' ? req.body.password : '';

  if (!email || !email.includes('@') || !name || password.length < 6) {
    res.status(400).json({ error: 'Isi nama, email valid, dan kata sandi minimal 6 karakter.' });
    return;
  }

  const existing = Object.values(db.users).find((u) => u.email === email);
  if (existing) {
    res.status(409).json({ error: 'Email sudah terdaftar. Silakan masuk.' });
    return;
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const user: StoredUser = {
    id: `usr_${crypto.randomUUID().slice(0, 12)}`,
    email,
    name,
    passwordSalt: salt,
    passwordHash: hashPassword(password, salt),
    coupleId: null,
    createdAt: new Date().toISOString(),
  };

  db.users[user.id] = user;
  persistDb();

  const token = signToken(user.id);
  res.status(201).json({
    token,
    user: { id: user.id, email: user.email, name: user.name, coupleId: user.coupleId, createdAt: user.createdAt },
    couple: null,
    onlineUserIds: [],
  });
});

app.post('/api/auth/login', (req: Request, res: Response) => {
  const email = sanitizeText(req.body?.email, 120).toLowerCase();
  const password = typeof req.body?.password === 'string' ? req.body.password : '';

  const user = Object.values(db.users).find((u) => u.email === email);
  if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
    res.status(401).json({ error: 'Email atau kata sandi salah.' });
    return;
  }

  const token = signToken(user.id);
  const couple = getCoupleForUser(user);
  res.json({
    token,
    user: { id: user.id, email: user.email, name: user.name, coupleId: user.coupleId, createdAt: user.createdAt },
    couple,
    onlineUserIds: getOnlineUserIds(user.coupleId),
  });
});

app.get('/api/me', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const couple = getCoupleForUser(user);
  res.json({
    user: { id: user.id, email: user.email, name: user.name, coupleId: user.coupleId, createdAt: user.createdAt },
    couple,
    onlineUserIds: getOnlineUserIds(user.coupleId),
  });
});

app.get('/api/couple/sync', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const couple = getCoupleForUser(user);
  res.json({
    couple,
    onlineUserIds: getOnlineUserIds(user.coupleId),
  });
});

app.post('/api/couple/create', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  if (user.coupleId && db.couples[user.coupleId]) {
    res.json({
      couple: db.couples[user.coupleId],
      onlineUserIds: getOnlineUserIds(user.coupleId),
    });
    return;
  }

  const couple = createInitialCoupleSpace(user);
  db.couples[couple.id] = couple;
  user.coupleId = couple.id;
  persistDb();
  syncWsCoupleId(user.id, couple.id);

  res.status(201).json({ couple, onlineUserIds: getOnlineUserIds(couple.id) });
});

app.post('/api/couple/join', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const code = sanitizeText(req.body?.code, 20).toUpperCase();
  if (!code) {
    res.status(400).json({ error: 'Masukkan kode pasangan yang valid.' });
    return;
  }

  const targetCouple = Object.values(db.couples).find((c) => c.code === code);
  if (!targetCouple) {
    res.status(404).json({ error: 'Kode pasangan tidak ditemukan. Periksa kembali kode dari pasanganmu.' });
    return;
  }

  if (targetCouple.id === user.coupleId) {
    res.json({ couple: targetCouple, onlineUserIds: getOnlineUserIds(targetCouple.id) });
    return;
  }

  const alreadyMember = targetCouple.members.some((m) => m.id === user.id);
  if (!alreadyMember && targetCouple.members.length >= 2) {
    res.status(409).json({ error: 'Kode pasangan ini sudah terhubung dengan 2 pengguna.' });
    return;
  }

  // If user accidentally created a solo room before joining their partner's code, clean up that solo room
  if (user.coupleId && db.couples[user.coupleId]) {
    const oldCouple = db.couples[user.coupleId];
    if (oldCouple.members.length <= 1) {
      delete db.couples[user.coupleId];
    } else {
      res.status(409).json({ error: 'Akun Anda sudah terhubung dengan pasangan di ruang lain.' });
      return;
    }
  }

  if (!alreadyMember) {
    targetCouple.members.push({ id: user.id, name: user.name, email: user.email });
  }
  user.coupleId = targetCouple.id;
  persistDb();
  syncWsCoupleId(user.id, targetCouple.id);
  broadcastCoupleUpdate(targetCouple.id, 'couple:paired', { memberName: user.name });

  res.json({ couple: targetCouple, onlineUserIds: getOnlineUserIds(targetCouple.id) });
});

app.patch('/api/couple/settings', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const couple = getCoupleForUser(user);
  if (!couple) {
    res.status(400).json({ error: 'Hubungkan kode pasangan terlebih dahulu.' });
    return;
  }

  const title = sanitizeText(req.body?.title, 80);
  const anniversaryDate = sanitizeText(req.body?.anniversaryDate, 20);
  const relationshipStartDate = sanitizeText(req.body?.relationshipStartDate, 20);

  if (title) couple.title = title;
  if (/^\d{4}-\d{2}-\d{2}$/.test(anniversaryDate)) couple.anniversaryDate = anniversaryDate;
  if (/^\d{4}-\d{2}-\d{2}$/.test(relationshipStartDate)) couple.relationshipStartDate = relationshipStartDate;

  persistDb();
  broadcastCoupleUpdate(couple.id, 'couple:updated', {});
  res.json({ couple });
});

app.post('/api/location', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const couple = getCoupleForUser(user);
  if (!couple) {
    res.status(400).json({ error: 'Hubungkan kode pasangan terlebih dahulu.' });
    return;
  }

  const isSharing = Boolean(req.body?.isSharing);
  const lat = Number(req.body?.lat);
  const lng = Number(req.body?.lng);
  const accuracy = typeof req.body?.accuracy === 'number' ? Math.round(req.body.accuracy) : undefined;

  if (isSharing) {
    if (!Number.isFinite(lat) || !Number.isFinite(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180) {
      res.status(400).json({ error: 'Koordinat GPS tidak valid.' });
      return;
    }
    const loc: PartnerLocation = {
      userId: user.id,
      userName: user.name,
      lat,
      lng,
      accuracy,
      isSharing: true,
      updatedAt: new Date().toISOString(),
    };
    couple.locations[user.id] = loc;
  } else {
    const prev = couple.locations[user.id];
    couple.locations[user.id] = {
      userId: user.id,
      userName: user.name,
      lat: prev?.lat ?? 0,
      lng: prev?.lng ?? 0,
      isSharing: false,
      updatedAt: new Date().toISOString(),
    };
  }

  persistDb();
  broadcastCoupleUpdate(couple.id, 'location:updated', { userId: user.id });
  res.json({ couple });
});

app.post('/api/notes', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const couple = getCoupleForUser(user);
  if (!couple) {
    res.status(400).json({ error: 'Hubungkan kode pasangan terlebih dahulu.' });
    return;
  }

  const text = sanitizeText(req.body?.text, 500);
  const mood = sanitizeText(req.body?.mood, 30) || 'Hangat';
  if (!text) {
    res.status(400).json({ error: 'Pesan cinta tidak boleh kosong.' });
    return;
  }

  const note: LoveNote = {
    id: `note_${crypto.randomUUID().slice(0, 8)}`,
    authorId: user.id,
    authorName: user.name,
    text,
    mood,
    isFavorite: false,
    createdAt: new Date().toISOString(),
  };

  couple.loveNotes.unshift(note);
  persistDb();
  broadcastCoupleUpdate(couple.id, 'notes:updated', { note });
  res.status(201).json({ couple, note });
});

app.patch('/api/notes/:id/favorite', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const couple = getCoupleForUser(user);
  if (!couple) {
    res.status(400).json({ error: 'Hubungkan kode pasangan terlebih dahulu.' });
    return;
  }
  const note = couple.loveNotes.find((n) => n.id === req.params.id);
  if (!note) {
    res.status(404).json({ error: 'Pesan tidak ditemukan.' });
    return;
  }
  note.isFavorite = !note.isFavorite;
  persistDb();
  broadcastCoupleUpdate(couple.id, 'notes:updated', { note });
  res.json({ couple });
});

app.delete('/api/notes/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const couple = getCoupleForUser(user);
  if (!couple) {
    res.status(400).json({ error: 'Hubungkan kode pasangan terlebih dahulu.' });
    return;
  }
  const idx = couple.loveNotes.findIndex((n) => n.id === req.params.id);
  if (idx === -1) {
    res.status(404).json({ error: 'Pesan tidak ditemukan.' });
    return;
  }
  couple.loveNotes.splice(idx, 1);
  persistDb();
  broadcastCoupleUpdate(couple.id, 'notes:updated', {});
  res.json({ couple });
});

app.post('/api/memories', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const couple = getCoupleForUser(user);
  if (!couple) {
    res.status(400).json({ error: 'Hubungkan kode pasangan terlebih dahulu.' });
    return;
  }

  const title = sanitizeText(req.body?.title, 100);
  const caption = sanitizeText(req.body?.caption, 400);
  const date = sanitizeText(req.body?.date, 20) || new Date().toISOString().slice(0, 10);
  const location = sanitizeText(req.body?.location, 80) || 'Bersama';
  const imageUrl = typeof req.body?.imageUrl === 'string' ? req.body.imageUrl.trim() : '';

  if (!title || !isSafeImageUrl(imageUrl)) {
    res.status(400).json({ error: 'Judul kenangan dan gambar yang valid wajib diisi.' });
    return;
  }

  const memory: MemoryItem = {
    id: `mem_${crypto.randomUUID().slice(0, 8)}`,
    authorId: user.id,
    authorName: user.name,
    title,
    caption,
    date,
    location,
    imageUrl,
    createdAt: new Date().toISOString(),
  };

  couple.memories.unshift(memory);
  persistDb();
  broadcastCoupleUpdate(couple.id, 'memories:updated', { memory });
  res.status(201).json({ couple, memory });
});

app.delete('/api/memories/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const couple = getCoupleForUser(user);
  if (!couple) {
    res.status(400).json({ error: 'Hubungkan kode pasangan terlebih dahulu.' });
    return;
  }
  const idx = couple.memories.findIndex((m) => m.id === req.params.id);
  if (idx === -1) {
    res.status(404).json({ error: 'Kenangan tidak ditemukan.' });
    return;
  }
  couple.memories.splice(idx, 1);
  persistDb();
  broadcastCoupleUpdate(couple.id, 'memories:updated', {});
  res.json({ couple });
});

app.post('/api/letters', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const couple = getCoupleForUser(user);
  if (!couple) {
    res.status(400).json({ error: 'Hubungkan kode pasangan terlebih dahulu.' });
    return;
  }

  const prompt = sanitizeText(req.body?.prompt, 120);
  const content = sanitizeText(req.body?.content, 2000);
  if (!prompt || !content) {
    res.status(400).json({ error: 'Judul situasi dan isi surat tidak boleh kosong.' });
    return;
  }

  const letter: OpenWhenLetter = {
    id: `let_${crypto.randomUUID().slice(0, 8)}`,
    authorId: user.id,
    authorName: user.name,
    prompt,
    content,
    isOpened: false,
    openedAt: null,
    createdAt: new Date().toISOString(),
  };

  couple.letters.unshift(letter);
  persistDb();
  broadcastCoupleUpdate(couple.id, 'letters:updated', { letter });
  res.status(201).json({ couple, letter });
});

app.patch('/api/letters/:id/open', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const couple = getCoupleForUser(user);
  if (!couple) {
    res.status(400).json({ error: 'Hubungkan kode pasangan terlebih dahulu.' });
    return;
  }
  const letter = couple.letters.find((l) => l.id === req.params.id);
  if (!letter) {
    res.status(404).json({ error: 'Surat tidak ditemukan.' });
    return;
  }
  if (!letter.isOpened) {
    letter.isOpened = true;
    letter.openedAt = new Date().toISOString();
    persistDb();
    broadcastCoupleUpdate(couple.id, 'letters:updated', { letter });
  }
  res.json({ couple, letter });
});

app.delete('/api/letters/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const couple = getCoupleForUser(user);
  if (!couple) {
    res.status(400).json({ error: 'Hubungkan kode pasangan terlebih dahulu.' });
    return;
  }
  const idx = couple.letters.findIndex((l) => l.id === req.params.id);
  if (idx === -1) {
    res.status(404).json({ error: 'Surat tidak ditemukan.' });
    return;
  }
  couple.letters.splice(idx, 1);
  persistDb();
  broadcastCoupleUpdate(couple.id, 'letters:updated', {});
  res.json({ couple });
});

app.post('/api/surprises', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const couple = getCoupleForUser(user);
  if (!couple) {
    res.status(400).json({ error: 'Hubungkan kode pasangan terlebih dahulu.' });
    return;
  }

  const title = sanitizeText(req.body?.title, 100);
  const description = sanitizeText(req.body?.description, 400);
  const rewardType = sanitizeText(req.body?.rewardType, 40) || 'Kejutan Manis';
  if (!title || !description) {
    res.status(400).json({ error: 'Judul dan isi kejutan tidak boleh kosong.' });
    return;
  }

  const item: SurpriseItem = {
    id: `sur_${crypto.randomUUID().slice(0, 8)}`,
    authorId: user.id,
    authorName: user.name,
    title,
    description,
    rewardType,
    isRevealed: false,
    revealedAt: null,
    createdAt: new Date().toISOString(),
  };

  couple.surprises.unshift(item);
  persistDb();
  broadcastCoupleUpdate(couple.id, 'surprises:updated', { item });
  res.status(201).json({ couple, item });
});

app.patch('/api/surprises/:id/reveal', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const couple = getCoupleForUser(user);
  if (!couple) {
    res.status(400).json({ error: 'Hubungkan kode pasangan terlebih dahulu.' });
    return;
  }
  const item = couple.surprises.find((s) => s.id === req.params.id);
  if (!item) {
    res.status(404).json({ error: 'Kotak kejutan tidak ditemukan.' });
    return;
  }
  item.isRevealed = true;
  item.revealedAt = new Date().toISOString();
  persistDb();
  broadcastCoupleUpdate(couple.id, 'surprises:updated', { item });
  res.json({ couple, item });
});

app.delete('/api/surprises/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const couple = getCoupleForUser(user);
  if (!couple) {
    res.status(400).json({ error: 'Hubungkan kode pasangan terlebih dahulu.' });
    return;
  }
  const idx = couple.surprises.findIndex((s) => s.id === req.params.id);
  if (idx === -1) {
    res.status(404).json({ error: 'Kotak kejutan tidak ditemukan.' });
    return;
  }
  couple.surprises.splice(idx, 1);
  persistDb();
  broadcastCoupleUpdate(couple.id, 'surprises:updated', {});
  res.json({ couple });
});

app.post('/api/hugs', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.authUser!;
  const couple = getCoupleForUser(user);
  if (!couple) {
    res.status(400).json({ error: 'Hubungkan kode pasangan terlebih dahulu.' });
    return;
  }

  const message = sanitizeText(req.body?.message, 160) || 'Pelukan hangat penuh rindu untukmu!';
  const hug: HugEvent = {
    id: `hug_${crypto.randomUUID().slice(0, 8)}`,
    fromUserId: user.id,
    fromUserName: user.name,
    message,
    createdAt: new Date().toISOString(),
  };

  couple.hugCount += 1;
  couple.hugs = [hug, ...couple.hugs].slice(0, 20);
  persistDb();
  broadcastCoupleUpdate(couple.id, 'hug:received', { hug });
  res.status(201).json({ couple, hug });
});

async function startServer(): Promise<void> {
  const server = http.createServer(app);
  const wss = new WebSocketServer({ server, path: '/ws' });

  wss.on('connection', (ws: WebSocket) => {
    wsClients.set(ws, { userId: '', coupleId: null });

    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString()) as { type?: string; token?: string };
        if (msg.type === 'auth' && typeof msg.token === 'string') {
          const userId = verifyToken(msg.token);
          if (userId && db.users[userId]) {
            const user = db.users[userId];
            wsClients.set(ws, { userId: user.id, coupleId: user.coupleId });
            ws.send(
              JSON.stringify({
                type: 'auth:ok',
                couple: getCoupleForUser(user),
                onlineUserIds: getOnlineUserIds(user.coupleId),
              }),
            );
            if (user.coupleId) {
              broadcastCoupleUpdate(user.coupleId, 'presence:updated', { userId: user.id });
            }
          } else {
            ws.send(JSON.stringify({ type: 'auth:error' }));
          }
        }
      } catch {
        // Ignore malformed frames
      }
    });

    ws.on('close', () => {
      const meta = wsClients.get(ws);
      wsClients.delete(ws);
      if (meta?.coupleId) {
        broadcastCoupleUpdate(meta.coupleId, 'presence:updated', { userId: meta.userId });
      }
    });
  });

  const distDir = path.resolve(process.cwd(), 'dist');
  const isProduction =
    process.env.NODE_ENV === 'production' ||
    (process.env.npm_lifecycle_event === 'start' && fs.existsSync(distDir));

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: false },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(distDir, 'index.html'));
    });
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`For Lysa server running on http://localhost:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start For Lysa server:', err);
  process.exit(1);
});
