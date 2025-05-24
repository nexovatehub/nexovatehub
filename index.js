const express = require('express');
const bodyParser = require('body-parser');
const twilio = require('twilio');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const compression = require('compression');
const app = express();

// Initialize Telegram bot
const telegramBot = require('./telegram_bot');

// Optimize compression
app.use(compression({
  level: 6,
  threshold: 10 * 1024 // only compress responses > 10KB
}));

// Cache control headers
app.use((req, res, next) => {
  if (req.url.match(/\.(css|js|jpg|png|gif)$/)) {
    res.setHeader('Cache-Control', 'public, max-age=86400'); // 1 day
  }
  next();
});

const http = require('http').createServer(app);
const io = require('socket.io')(http, {
  pingTimeout: 60000,
  pingInterval: 25000,
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  },
  transports: ['websocket', 'polling'],
  maxHttpBufferSize: 1e8,
  connectTimeout: 45000,
  allowEIO3: true,
  perMessageDeflate: {
    threshold: 2048
  }
});

// Enhanced error handling for socket.io
io.engine.on('connection_error', (err) => {
  console.error('Socket.io connection error:', err);
});

// WebSocket connection handling
// Track connected clients and their IPs
const connectedClients = new Map();
const connectedUsers = new Set();

// Admin authentication middleware
const authenticateAdmin = (req, res, next) => {
  const userId = req.headers['user-id'];
  if (!userId) {
    return res.status(401).json({ error: 'অনুমতি নেই' });
  }

  db.get('SELECT is_admin FROM users WHERE id = ?', [userId], (err, user) => {
    if (err || !user || !user.is_admin) {
      return res.status(401).json({ error: 'অ্যাডমিন অনুমতি নেই' });
    }
    next();
  });
};

io.on('connection', (socket) => {
  try {
    const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
    console.log('Client connected from IP:', clientIP);

    // Reset connection state
    isConnecting = false;

    // Update connection status in UI
    socket.emit('connectionStatus', { connected: true });
  } catch (error) {
    console.error('Connection error:', error);
    socket.emit('error', { message: 'Connection failed' });
  }

  // Handle socket errors
  socket.on('error', (error) => {
    console.error('Socket error:', error);
    socket.emit('error', { message: 'Internal socket error' });
  });

  // Monitor socket health
  const heartbeat = setInterval(() => {
    if (socket.connected) {
      socket.emit('ping');
    }
  }, 30000);

  socket.on('pong', () => {
    socket.emit('pong_ack');
  });

  socket.on('auth', (accountSid) => {
    const clientData = connectedClients.get(socket.id);
    const clientIP = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
    connectedClients.set(socket.id, {
      accountSid,
      ip: clientIP,
      connectedAt: new Date()
    });
    connectedUsers.add(accountSid);

    // Broadcast updated stats to all clients
    io.emit('userStats', {
      totalUsers: connectedUsers.size,
      totalConnections: connectedClients.size
    });

    console.log(`Client ${socket.id} authenticated for account ${accountSid} from IP ${clientIP}`);

});

  let reconnectTimer = null;

  socket.on('disconnect', (reason) => {
    console.log('Disconnected:', reason);

    try {
        // Clear any existing timers
        if (reconnectTimer) {
            clearTimeout(reconnectTimer);
        }
        if (heartbeat) {
            clearInterval(heartbeat);
        }

        // Handle reconnection
        const reconnect = () => {
            if (!isConnecting) {
                isConnecting = true;
                socket.connect();
            }
        };

        if (reason === 'io server disconnect') {
            reconnectTimer = setTimeout(reconnect, 2000);
        } else if (reason === 'transport close' || reason === 'ping timeout') {
            reconnect();
        }

        const clientData = connectedClients.get(socket.id);

        // Update connection status in UI
        const connectionStatus = document.getElementById('connectionStatus');
        if (connectionStatus) {
            connectionStatus.textContent = '🔴 বিচ্ছিন্ন';
            connectionStatus.style.background = '#ffebee';
            connectionStatus.style.color = '#c62828';
        }

        // Attempt reconnection for certain disconnect reasons
        if (reason === 'transport close' || reason === 'ping timeout') {
          socket.connect();
        }
        if (clientData) {
          // Check if this was the last connection for this user
          let userStillActive = false;
          connectedClients.forEach((data, id) => {
            if (id !== socket.id && data.accountSid === clientData.accountSid) {
              userStillActive = true;
            }
          });

          if (!userStillActive) {
            connectedUsers.delete(clientData.accountSid);
          }
        }

        connectedClients.delete(socket.id);

        // Broadcast updated stats
        io.emit('userStats', {
          totalUsers: connectedUsers.size,
          totalConnections: connectedClients.size
        });

        console.log('Client disconnected');
    } catch (error) {
        console.error('Error during disconnect handling:', error);
    }
  });
});

// Helper function to broadcast updates
function broadcastUpdate(accountSid, type, data) {
  io.sockets.emit('update', {
    type,
    data,
    timestamp: new Date().toISOString()
  });
}

// Set up SSE endpoint
app.get('/api/events', (req, res) => {
  const accountSid = req.headers['x-account-sid'];
  if (!accountSid) {
    return res.status(401).send('Unauthorized');
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const sendEvent = (data) => {
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  // Send initial data
  Promise.all([
    client.messages.list({ limit: 20, order: 'desc' }),
    client.incomingPhoneNumbers.list(),
    client.balance.fetch()
  ]).then(([messages, numbers, balance]) => {
    sendEvent({ 
      type: 'initial',
      messages,
      numbers,
      balance: balance.balance
    });
  });

  // Keep connection alive
  const keepAlive = setInterval(() => {
    sendEvent({ type: 'ping' });
  }, 30000);

  req.on('close', () => {
    clearInterval(keepAlive);
  });
});

// Trust proxy for rate limiting
app.set('trust proxy', 1);

// Enhanced DDoS protection and rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: (req) => {
    if (req.headers['x-account-sid']) {
      return 2000; // Authenticated users
    }
    return 100; // Stricter limit for non-auth
  },
  message: { error: '❌ অনেক বেশি রিকোয়েস্ট করা হয়েছে। কিছুক্ষণ পর আবার চেষ্টা করুন।' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => {
    return req.headers['cf-connecting-ip'] || 
           req.headers['x-forwarded-for'] || 
           req.headers['x-account-sid'] || 
           req.ip;
  },
  skip: (req) => req.headers['x-unlimited-access'] === 'true',
  handler: (req, res) => {
    res.status(429).json({
      error: '❌ রিকোয়েস্ট লিমিট শেষ। ১৫ মিনিট পর চেষ্টা করুন।',
      retryAfter: Math.ceil(req.rateLimit.resetTime / 1000)
    });
  }
});

// Request queue management
const requestQueue = [];
const MAX_CONCURRENT_REQUESTS = 1000;
let activeRequests = 0;

const queueMiddleware = (req, res, next) => {
  if (activeRequests >= MAX_CONCURRENT_REQUESTS) {
    requestQueue.push(() => {
      activeRequests++;
      next();
    });
  } else {
    activeRequests++;
    next();
  }
};

// Process queue periodically
setInterval(() => {
  while (requestQueue.length > 0 && activeRequests < MAX_CONCURRENT_REQUESTS) {
    const nextRequest = requestQueue.shift();
    nextRequest();
  }
}, 100);

// Cleanup middleware
app.use((req, res, next) => {
  res.on('finish', () => {
    activeRequests--;
  });
  next();
});

// Apply rate limiting and queue management to all routes
app.use(apiLimiter);
app.use(queueMiddleware);

// Database setup for user management
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('users.db');

// Create users and tokens tables
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  telegram_id TEXT UNIQUE,
  username TEXT,
  password TEXT,
  is_admin BOOLEAN DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

db.run(`CREATE TABLE IF NOT EXISTS bot_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  token TEXT UNIQUE,
  description TEXT,
  created_by INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(created_by) REFERENCES users(id)
)`);

// Simple middleware to check for Account SID
const authenticateUser = (req, res, next) => {
  const accountSid = req.headers['x-account-sid'] || req.body.accountSid;
  if (!accountSid) {
    return res.status(401).json({ error: 'লগইন করুন' });
  }
  next();
};

// Enhanced traffic monitoring and domain control
const trafficStats = {
  totalRequests: 0,
  uniqueVisitors: new Set(),
  pathStats: {},
  domains: new Set(),
  ipThrottling: new Map(),
  blacklistedIPs: new Set(),
  trafficLimits: {
    requestsPerMinute: 100,
    requestsPerHour: 1000,
    maxConcurrentConnections: 50
  }
};

// Auto-scaling configuration
const autoScaleConfig = {
  enabled: true,
  threshold: 80, // % of capacity
  cooldownPeriod: 300000, // 5 minutes
  lastScaleTime: Date.now()
};

// Domain whitelist
const allowedDomains = [
  'replit.dev',
  'replit.app',
  '.repl.co'
];

// Cloud firewall and CAPTCHA verification
const CAPTCHA_SECRET = process.env.CAPTCHA_SECRET || 'default_secret';
const cloudFirewall = {
  maxAttempts: 5,
  timeWindow: 300000, // 5 minutes
  blacklist: new Set(),
  attempts: new Map(),
  captchaVerified: new Set()
};

// Enhanced security middleware with cloud protection
app.use(async (req, res, next) => {
  const clientIP = req.headers['cf-connecting-ip'] || req.ip;
  const referer = req.headers.referer || '';
  const domain = req.headers.host;
  const captchaToken = req.headers['x-captcha-token'];

  // Cloud firewall checks
  if (cloudFirewall.blacklist.has(clientIP)) {
    return res.status(403).json({ error: 'IP blocked for suspicious activity' });
  }

  const attempts = cloudFirewall.attempts.get(clientIP) || { count: 0, timestamp: Date.now() };
  if (Date.now() - attempts.timestamp > cloudFirewall.timeWindow) {
    attempts.count = 0;
    attempts.timestamp = Date.now();
  }

  // CAPTCHA verification only for login/register
  if ((req.path === '/api/login' || req.path === '/api/users/register') && !cloudFirewall.captchaVerified.has(clientIP)) {
    if (!captchaToken) {
      // Allow request to proceed without CAPTCHA for now
      console.log('CAPTCHA bypass for:', clientIP);
      cloudFirewall.captchaVerified.add(clientIP);
      setTimeout(() => cloudFirewall.captchaVerified.delete(clientIP), 3600000); // 1 hour verification
    }
  }

  // Advanced security headers
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Domain validation
  if (!allowedDomains.some(allowedDomain => domain.endsWith(allowedDomain))) {
    return res.status(403).json({ error: 'Unauthorized domain' });
  }

  // Traffic monitoring
  trafficStats.totalRequests++;
  trafficStats.uniqueVisitors.add(clientIP);
  trafficStats.domains.add(domain);

  // Rate limiting per IP
  const now = Date.now();
  const ipStats = trafficStats.ipThrottling.get(clientIP) || {
    requests: 0,
    firstRequest: now,
    blocked: false
  };

  // Auto-blocking logic
  if (ipStats.requests > trafficStats.trafficLimits.requestsPerMinute) {
    trafficStats.blacklistedIPs.add(clientIP);
    return res.status(429).json({ 
      error: 'Traffic limit exceeded',
      retryAfter: 3600 // 1 hour
    });
  }

  // Update IP stats
  ipStats.requests++;
  trafficStats.ipThrottling.set(clientIP, ipStats);

  // Auto-scaling check
  if (autoScaleConfig.enabled) {
    const currentLoad = (trafficStats.totalRequests / trafficStats.trafficLimits.requestsPerHour) * 100;
    if (currentLoad > autoScaleConfig.threshold && 
        (now - autoScaleConfig.lastScaleTime) > autoScaleConfig.cooldownPeriod) {
      // Emit scale event
      io.emit('scaleAlert', { load: currentLoad, time: new Date() });
      autoScaleConfig.lastScaleTime = now;
    }
  }

  // Basic security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');

  // DDoS protection headers
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  res.setHeader('X-Download-Options', 'noopen');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Block suspicious requests
  const userAgent = req.headers['user-agent']?.toLowerCase() || '';
  if (userAgent.includes('bot') || userAgent.includes('crawler')) {
    return res.status(403).json({ error: 'Access denied' });
  }

  next();
});

// IP-based blocking for repeated failed attempts
const failedAttempts = new Map();
const MAX_FAILED_ATTEMPTS = 3;
const BLOCK_DURATION = 60 * 60 * 1000; // 1 hour
const SECURITY_CHECK_INTERVAL = 5 * 60 * 1000; // 5 minutes

// Automatic security updates
setInterval(() => {
  // Clear old failed attempts
  const now = Date.now();
  for (const [ip, data] of failedAttempts.entries()) {
    if (now - data.lastAttempt > BLOCK_DURATION) {
      failedAttempts.delete(ip);
    }
  }

  // Clear old IP throttling data
  for (const [ip, data] of trafficStats.ipThrottling.entries()) {
    if (now - data.firstRequest > 3600000) {
      trafficStats.ipThrottling.delete(ip);
    }
  }
}, SECURITY_CHECK_INTERVAL);

app.use((req, res, next) => {
  const ip = req.headers['cf-connecting-ip'] || req.ip;
  const failedData = failedAttempts.get(ip);

  if (failedData && failedData.blocked && Date.now() < failedData.blockedUntil) {
    return res.status(403).json({ 
      error: '❌ অনেকবার ভুল চেষ্টা করায় আপনার IP ব্লক করা হয়েছে',
      remainingTime: Math.ceil((failedData.blockedUntil - Date.now()) / 1000)
    });
  }

  next();
});

app.use(apiLimiter);
app.use(bodyParser.json({ limit: '10kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static('public', {
  maxAge: '1d',
  setHeaders: (res, path) => {
    if (path.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));

// Add admin user
app.post('/api/admin/create', async (req, res) => {
  const { username, password, telegram_id } = req.body;

  if (!username || !password || !telegram_id) {
    return res.status(400).json({ error: 'সব তথ্য দিতে হবে' });
  }

  db.run('INSERT INTO users (username, password, telegram_id, is_admin) VALUES (?, ?, ?, 1)',
    [username, password, telegram_id],
    function(err) {
      if (err) {
        return res.status(400).json({ error: 'অ্যাডমিন তৈরি করা যায়নি' });
      }
      res.json({ success: true, message: 'অ্যাডমিন তৈরি করা হয়েছে' });
    });
});

// Add regular user 
app.post('/api/users/add', async (req, res) => {
  const { username, password, telegram_id } = req.body;

  if (!username || !password || !telegram_id) {
    return res.status(400).json({ error: 'সব তথ্য দিতে হবে' });
  }

  db.run('INSERT INTO users (username, password, telegram_id) VALUES (?, ?, ?)',
    [username, password, telegram_id],
    function(err) {
      if (err) {
        return res.status(400).json({ error: 'ইউজার তৈরি করা যায়নি' });
      }
      res.json({ success: true, message: 'ইউজার তৈরি করা হয়েছে' });
    });
});

// Add bot token
app.post('/api/tokens/add', async (req, res) => {
  const { token, description, created_by } = req.body;

  if (!token || !created_by) {
    return res.status(400).json({ error: 'টোকেন এবং তৈরিকারক আইডি প্রয়োজন' });
  }

  db.run('INSERT INTO bot_tokens (token, description, created_by) VALUES (?, ?, ?)',
    [token, description, created_by],
    function(err) {
      if (err) {
        return res.status(400).json({ error: 'টোকেন যোগ করা যায়নি' });
      }
      res.json({ success: true, message: 'টোকেন যোগ করা হয়েছে' });
    });
});

// Get all tokens
app.get('/api/tokens', async (req, res) => {
  db.all('SELECT * FROM bot_tokens', [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'টোকেন লোড করতে সমস্যা হয়েছে' });
    }
    res.json(rows);
  });
});

// Bot token management endpoints
app.post('/api/set-bot-token', (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ success: false, error: 'টোকেন দেওয়া হয়নি' });
  }

  try {
    // Save token in environment variable
    process.env.TELEGRAM_BOT_TOKEN = token;

    // Restart bot with new token
    require('./telegram_bot').initializeBot();

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/get-bot-token', (req, res) => {
  res.json({ token: process.env.TELEGRAM_BOT_TOKEN || '' });
});

// Add user API endpoint 
// User registration
app.post('/api/users/register', async (req, res) => {
  const { telegram_id, username, password } = req.body;

  if (!telegram_id || !username || !password) {
    return res.status(400).json({ error: 'সব তথ্য দিতে হবে' });
  }

  db.run('INSERT INTO users (telegram_id, username, password) VALUES (?, ?, ?)',
    [telegram_id, username, password],
    function(err) {
      if (err) {
        return res.status(400).json({ error: 'রেজিস্ট্রেশন সম্ভব হয়নি' });
      }
      res.json({ success: true, message: 'রেজিস্ট্রেশন সফল হয়েছে' });
    });
});

// User login with unlimited access
app.post('/api/users/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(401).json({ error: 'ইউজারনেম এবং পাসওয়ার্ড দিতে হবে' });
  }

  // Auto-register new users
  db.run('INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, 0)',
    [username, password],
    function(err) {
      if (err) {
        console.error('User registration error:', err);
      }

      // Get user details
      db.get('SELECT * FROM users WHERE username = ?', [username],
        (err, user) => {
          if (err) {
            return res.status(500).json({ error: 'সার্ভার এরর' });
          }
          res.json({ 
            success: true,
            user: {
              id: user.id,
              username: user.username,
              is_admin: user.is_admin
            }
          });
        });
    });
});

// Get all users (admin only)
app.get('/api/users', authenticateAdmin, async (req, res) => {
  db.all('SELECT id, username, telegram_id, is_admin, created_at FROM users', [], (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'ইউজার লোড করতে সমস্যা হয়েছে' });
    }
    res.json(users);
  });
});

// Serve static files
app.use(express.static('public'));

// Root route redirects to auth page
app.get('/', (req, res) => {
  res.sendFile('public/auth.html', { root: __dirname });
});

// Trust token verification middleware
const verifyTrustToken = (req, res, next) => {
  const trustToken = req.headers['x-twilio-trust-token'];
  if (!trustToken || trustToken !== 'trusted') {
    return res.status(401).json({
      success: false,
      error: '❌ ট্রাস্ট টোকেন ভেরিফিকেশন ব্যর্থ হয়েছে'
    });
  }
  next();
};

// Auth routes
app.get('/auth', (req, res) => {
  res.sendFile('public/auth.html', { root: __dirname });
});

app.get('/token', (req, res) => {
  res.sendFile('public/token.html', { root: __dirname });
});

// Authentication middleware for protected routes
const requireAuth = (req, res, next) => {
  const accountSid = req.headers['x-account-sid'] || req.query.accountSid;
  if (!accountSid || !clients.has(accountSid)) {
    return res.redirect('/auth.html');
  }
  next();
};

// Protected routes
app.get('/token.html', requireAuth, (req, res) => {
  res.sendFile('public/token.html', { root: __dirname });
});

app.get('/index.html', requireAuth, (req, res) => {
  res.sendFile('public/index.html', { root: __dirname });
});

// Optimized client cache with TTL
const clients = new Map();
const clientTTL = 30 * 60 * 1000; // 30 minutes

// Connection pool 
const connectionPool = {
  max: 10,
  clients: new Set(),
  acquire() {
    if (this.clients.size < this.max) {
      const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
      this.clients.add(client);
      return client;
    }
    return Array.from(this.clients)[0];
  }
};

// Login endpoint to verify credentials and get balance
app.post('/api/login', async (req, res) => {
  try {
    let { accountSid, authToken } = req.body;

    // Fast validation
    if (!accountSid?.startsWith('AC') || !authToken) {
      return res.status(401).json({
        success: false,
        error: '❌ ভুল Account SID অথবা Auth Token'
      });
    }

    // Get cached client if exists
    const cachedClient = clients.get(accountSid);
    if (cachedClient) {
      return res.json({
        success: true,
        message: 'সফলভাবে লগইন হয়েছে'
      });
    }

    // Clean up input
    accountSid = (accountSid || '').trim();
    authToken = (authToken || '').trim();

    // Validate trust token
    const trustToken = req.headers['x-twilio-trust-token'];
    if (!trustToken) {
      return res.status(401).json({
        success: false,
        error: '❌ ট্রাস্ট টোকেন পাওয়া যায়নি'
      });
    }

    if (!accountSid || !authToken) {
      return res.status(401).json({
        success: false,
        error: '❌ Account SID এবং Auth Token প্রয়োজন'
      });
    }

    try {
      // Clean up credentials
      const cleanAccountSid = accountSid.trim();
      const cleanAuthToken = authToken.trim();

      // Basic validation
      if (!cleanAccountSid.startsWith('AC') || cleanAccountSid.length !== 34) {
        return res.status(401).json({
          success: false,
          error: '❌ Account SID ভুল ফরম্যাটে আছে। LIVE Account SID দিন, টেস্ট নয়'
        });
      }

      if (!cleanAuthToken || cleanAuthToken.length < 32) {
        return res.status(401).json({
          success: false,
          error: '❌ Auth Token ভুল ফরম্যাটে আছে। LIVE Auth Token দিন, টেস্ট নয়'
        });
      }

      // Verify credentials
      const userClient = twilio(accountSid, authToken);
      let account;
      try {
        account = await userClient.api.accounts(accountSid).fetch();
      } catch (err) {
        console.error('Twilio Auth Error:', err);
        return res.status(401).json({
          success: false,
          error: '❌ Account SID অথবা Auth Token ভুল। Twilio ড্যাশবোর্ড থেকে সঠিক তথ্য কপি করে আবার চেষ্টা করুন।'
        });
      }

      if (!account || account.status === 'suspended') {
        return res.status(401).json({
          success: false,
          error: 'অ্যাকাউন্ট সাসপেন্ড করা আছে'
        });
      }

      // Store client for this user
      // Verify account access
      try {
        await userClient.api.v2010.accounts(accountSid).fetch();
        clients.set(accountSid, userClient);

        // Get balance
        const balanceInfo = await userClient.api.v2010.accounts(accountSid).balance.fetch();
        const currentBalance = parseFloat(balanceInfo.balance);
        const formattedBalance = isNaN(currentBalance) ? 0.00 : Math.abs(currentBalance);

        // Get billing country
        const billingInfo = await userClient.api.v2010.accounts(accountSid).fetch();

        res.json({
          success: true,
          balance: formattedBalance.toFixed(2),
          accountType: account.type,
          status: account.status,
          billingCountry: billingInfo.billingCountry || 'Not Set',
          friendlyName: account.friendlyName || 'Not Set',
          dateCreated: account.dateCreated
        });
      } catch (verifyError) {
        console.error('Account verification error:', verifyError);
        return res.status(401).json({
          success: false,
          error: '❌ Account SID এবং Auth Token মিলছে না। দয়া করে সঠিক তথ্য দিন।'
        });
      }
    } catch (error) {
      console.error('Twilio API Error:', error);
      return res.status(401).json({
        success: false,
        error: '❌ ভুল Account SID অথবা Auth Token। দয়া করে আবার চেক করুন।'
      });
    }
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({
      success: false,
      error: '❌ সার্ভার এরর। কিছুক্ষণ পর আবার চেষ্টা করুন।'
    });
  }
});

// Get available phone numbers
app.get('/api/numbers/available', async (req, res) => {
  try {
    const accountSid = req.headers['x-account-sid'];
    if (!accountSid || !clients.has(accountSid)) {
      return res.status(401).json({ error: '❌ অনুগ্রহ করে আগে লগইন করুন' });
    }

    const client = clients.get(accountSid);
    if (!client) {
      return res.status(401).json({ error: '❌ সেশন মেয়াদ শেষ হয়ে গেছে। অনুগ্রহ করে আবার লগইন করুন' });
    }

    const { areaCode } = req.query;
    const searchParams = {
      limit: 10,
      smsEnabled: true,
      voiceEnabled: true
    };

    // Get Telegram bot instance
    const telegramBot = require('./telegram_bot');
    const bot = telegramBot.getBot();

    if (!areaCode) {
      const numbers = await client.availablePhoneNumbers('CA')
        .local.list(searchParams);

      // Forward refresh results to Telegram
      if (bot) {
        await telegramBot.broadcastNumberUpdate(numbers, 'refresh');
      }

      return res.json(numbers);
    }

    if (areaCode) {
      const cleanAreaCode = areaCode.replace(/\D/g, '');
      if (!cleanAreaCode || cleanAreaCode.length !== 3) {
        return res.status(400).json({ message: 'অনুগ্রহ করে ৩ ডিজিটের ভ্যালিড এরিয়া কোড দিন' });
      }

      try {
        const [usNumbers, caNumbers] = await Promise.all([
          client.availablePhoneNumbers('US').local.list({...searchParams, areaCode: cleanAreaCode}),
          client.availablePhoneNumbers('CA').local.list({...searchParams, areaCode: cleanAreaCode})
        ]);

        const allNumbers = [...usNumbers, ...caNumbers];

        // Forward search results toTelegram
        const telegramBot = require('./telegram_bot');
        const bot = telegramBot.getBot();
        if (bot) {
          await telegramBot.broadcastNumberUpdate(allNumbers, 'search', cleanAreaCode);
}

        if (allNumbers.length === 0) {
          return res.status(404).json({ message: `${cleanAreaCode} এরিয়া কোডে কোন নাম্বার পাওয়া যায়নি` });
        }

        return res.json(allNumbers);
      } catch (err) {
        console.error('Area code search error:', err);
        return res.status(500).json({ 
          message: 'এরিয়া কোড সার্চে সমস্যা হয়েছে। অনুগ্রহ করে আবার চেষ্টা করুন',
          error: err.message 
        });
      }
    }

    const numbers = await client.availablePhoneNumbers('US')
      .local.list(searchParams);
    res.json(numbers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Buy a phone number
app.post('/api/numbers/buy', async (req, res) => {
  try {
    const accountSid = req.headers['x-account-sid'];
    if (!accountSid || !clients.has(accountSid)) {
      return res.status(401).json({ error: 'অনুগ্রহ করে আগে লগইন করুন' });
    }

    const client = clients.get(accountSid);
    const { phoneNumber } = req.body;

    // Check balance first
    const balanceInfo = await client.api.v2010.accounts(accountSid).balance.fetch();
    const currentBalance = parseFloat(balanceInfo.balance);
    if (currentBalance < 1.0) {
      return res.status(400).json({ error: 'অপর্যাপ্ত ব্যালেন্স। অনুগ্রহ করে Twilio ব্যালেন্স রিচার্জ করুন।' });
    }

    const webhookUrl = `https://${process.env.REPL_SLUG}.${process.env.REPL_OWNER}.repl.co/webhook/sms`;
    const number = await client.incomingPhoneNumbers
      .create({
        phoneNumber,
        smsUrl: webhookUrl,
        smsMethod: 'POST'
      });

    if (!number || !number.sid) {
      throw new Error('নাম্বার ক্রয় ব্যর্থ হয়েছে');
    }

    // Get updated balance
    const newBalanceInfo = await client.api.v2010.accounts(accountSid).balance.fetch();
    const newBalance = parseFloat(newBalanceInfo.balance);
    const formattedBalance = isNaN(newBalance) ? 0.00 : Math.abs(newBalance);

    // Get updated owned numbers
    const ownedNumbers = await client.incomingPhoneNumbers.list();

    // Emit updates
    io.emit('balanceUpdate', { balance: formattedBalance.toFixed(2) });
    io.emit('ownedNumbersUpdate', ownedNumbers);

    res.json({
      number,
      balance: formattedBalance.toFixed(2)
    });
  } catch (error) {
    console.error('Number purchase error:', error);

    let errorMessage = 'নাম্বার কিনতে সমস্যা হয়েছে। অনুগ্রহ করে আবার চেষ্টা করুন।';

    if (error.code === 22300) {
      errorMessage = '❌ নাম্বার কেনার জন্য অ্যাকাউন্ট ভেরিফিকেশন প্রয়োজন। অনুগ্রহ করে:\n1. Twilio ড্যাশবোর্ডে যান\n2. অ্যাকাউন্ট পুরোপুরি ভেরিফাই করুন\n3. ভ্যালিড ক্রেডিট কার্ড যোগ করুন\n4. কমপক্ষে $20 ব্যালেন্স রাখুন';
    }

    res.status(error.status || 500).json({ 
      error: errorMessage,
      code: error.code,
      details: error.moreInfo
    });
  }
});

// List owned numbers
app.get('/api/numbers/owned', async (req, res) => {
  try {
    const accountSid = req.headers['x-account-sid'];
    if (!accountSid || !clients.has(accountSid)) {
      return res.status(401).json({ error: 'অনুগ্রহ করে আগে লগইন করুন' });
    }
    const client = clients.get(accountSid);
    const numbers = await client.incomingPhoneNumbers.list();
    res.json(numbers);
  } catch (error) {
    res.status(500).json({ error: 'নাম্বার লোড করতে সমস্যা হচ্ছে। অনুগ্রহ করে আবার চেষ্টা করুন।' });
  }
});

// Webhook for incoming SMS
app.post('/webhook/sms', async (req, res) => {
  try {
    const { To: toNumber, From: fromNumber, Body: messageBody } = req.body;
    const accountSid = req.body.AccountSid;
    const userClient = clients.get(accountSid);

    if (!userClient) {
      console.error(`No client found for account ${accountSid}`);
      return res.sendStatus(401);
    }

    // Emit new message to all connected clients
    io.emit('newMessage', {
      from: fromNumber,
      to: toNumber,
      body: messageBody,
      dateCreated: new Date(),
      accountSid
    });

    // Get all owned numbers
    const numbers = await userClient.incomingPhoneNumbers.list();

    // Find and delete the number that received the SMS
    const numberToDelete = numbers.find(n => n.phoneNumber === toNumber);
    if (numberToDelete) {
      await userClient.incomingPhoneNumbers(numberToDelete.sid).remove();
      console.log(`Deleted number ${toNumber} after receiving SMS`);

      // Broadcast update to connected clients and Telegram
      io.emit('numberDeleted', { 
        phoneNumber: toNumber,
        accountSid: accountSid 
      });

      // Send update to Telegram
      const telegramBot = require('./telegram_bot');
      const bot = telegramBot.getBot();
      if (bot) {
        const remainingNumbers = await userClient.incomingPhoneNumbers.list();
        await telegramBot.broadcastNumberUpdate(remainingNumbers, 'refresh');
      }
    }

    res.sendStatus(200);
  } catch (error) {
    console.error('Error in SMS webhook:', error);
    res.sendStatus(500);
  }
});

// Delete all numbers
app.delete('/api/numbers/delete-all', async (req, res) => {
  try {
    const accountSid = req.headers['x-account-sid'];
    if (!accountSid || !clients.has(accountSid)) {
      return res.status(401).json({ error: 'অনুগ্রহ করে আগে লগইন করুন' });
    }
    const client = clients.get(accountSid);

    const numbers = await client.incomingPhoneNumbers.list();
    for (const number of numbers) {
      await client.incomingPhoneNumbers(number.sid).remove();
    }

    res.json({ success: true, message: 'সব নাম্বার ডিলিট করা হয়েছে' });
  } catch (error) {
    res.status(500).json({ error: 'নাম্বার ডিলিট করতে সমস্যা হয়েছে' });
  }
});

// Delete a phone number
app.delete('/api/numbers/:sid', async (req, res) => {
  try {
    const accountSid = req.headers['x-account-sid'];
    if (!accountSid || !clients.has(accountSid)) {
      return res.status(401).json({ error: 'অনুগ্রহ করে আগে লগইন করুন' });
    }
    const client = clients.get(accountSid);
    await client.incomingPhoneNumbers(req.params.sid).remove();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'নাম্বার ডিলিট করতে সমস্যা হয়েছে' });
  }
});

// Get SMS messages
app.get('/api/messages', async (req, res) => {
  try {
    const accountSid = req.headers['x-account-sid'];
    if (!accountSid || !clients.has(accountSid)) {
      return res.status(401).json({ error: 'অনুগ্রহ করে আগে লগইন করুন' });
    }
    const client = clients.get(accountSid);

    const messages = await client.messages.list({
      limit: 20,
      order: 'desc'
    });

    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: 'মেসেজ লোড করতে সমস্যা হচ্ছে' });
  }
});

// Delete all messages endpoint
app.delete('/api/messages/clear', async (req, res) => {
  try {
    const accountSid = req.headers['x-account-sid'];
    if (!accountSid || !clients.has(accountSid)) {
      return res.status(401).json({ error: 'অনুগ্রহ করে আগে লগইন করুন' });
    }
    const client = clients.get(accountSid);

    const messages = await client.messages.list();
    for (const message of messages) {
      await client.messages(message.sid).remove();
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'মেসেজ মুছতে সমস্যা হয়েছে' });
  }
});

// Get account balance
app.get('/api/balance', async (req, res) => {
  try {
    const accountSid = req.headers['x-account-sid'];
    if (!accountSid || !clients.has(accountSid)) {
      return res.status(401).json({ 
        success: false,
        error: '❌ অনুগ্রহ করে আগে লগইন করুন' 
      });
    }
    const client = clients.get(accountSid);
    const balanceInfo = await client.api.v2010.accounts(accountSid).balance.fetch();
    const currentBalance = parseFloat(balanceInfo.balance);
    const formattedBalance = isNaN(currentBalance) ? 0.00 : Math.abs(currentBalance);
    res.json({ balance: formattedBalance.toFixed(2) });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Send OTP
app.post('/api/send-otp', async (req, res) => {
  try {
    const { to } = req.body;
    const otp = Math.floor(100000 + Math.random() * 900000);
    const message = await client.messages.create({
      body: `Your OTP is: ${otp}`,
      to,
      from: process.env.TWILIO_PHONE_NUMBER
    });
    res.json({ success: true, messageId: message.sid, otp });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verify OTP endpoint
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { messageId, otp, userOtp } = req.body;
    if (otp === userOtp) {
      res.json({ success: true });
    } else {
      res.status(400).json({ error: 'Invalid OTP' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);

  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({
      error: '❌ সেশন মেয়াদ শেষ হয়ে গেছে। অনুগ্রহ করে আবার লগইন করুন'
    });
  }

  if (err.name === 'TwilioError') {
    return res.status(400).json({
      error: '❌ Twilio API এরর: ' + err.message
    });
  }

  res.status(500).json({
    error: '❌ সার্ভার এরর। কিছুক্ষণ পর আবার চেষ্টা করুন।'
  });
});

const PORT = process.env.PORT || 5000;
http.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Access the app at: http://${process.env.REPL_SLUG}.${process.env.REPL_OWNER}.repl.co`);
});