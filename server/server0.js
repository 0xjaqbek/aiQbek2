import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import OpenAI from 'openai';
import fs from 'fs';
import { promisify } from 'util';
import { v4 as uuidv4 } from 'uuid';

// In ES modules, __dirname is not available, so we create it
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Import enhanced security modules with corrected paths
import securityConfig from './client/src/security/config.js';
import {
  sanitizeInput,
  detectJailbreakAttempt,
  filterBotResponse,
  getSecurityMessage,
  logSecurityEventOld,
  generateSecureSystemMessage
} from './client/src/security/utils.js';

// Import additional security modules
import { 
  detectObfuscationTechniques,
  analyzeInputStructure,
  ContextTracker
} from './client/src/security/advancedSecurity.js';

// Import Redis store for distributed security (if enabled)
import {
  initRedisConnection,
  incrementRequestCount,
  getSecurityHistory,
  addSecurityEvent,
  getBanStatus,
  setBanStatus
} from './client/src/security/redisStore.js';

// Import security canary system
import {
  insertCanaryTokens,
  checkForCanaryLeakage
} from './client/src/security/canaryTokens.js';

// Promisify fs functions
const readFileAsync = promisify(fs.readFile);
const writeFileAsync = promisify(fs.writeFile);
const mkdirAsync = promisify(fs.mkdir);

// Path to logs storage directory and file
const LOGS_DIR = path.join(__dirname, 'logs');
const SECURITY_LOGS_FILE = path.join(LOGS_DIR, 'security_logs.json');
const CONVERSATION_LOGS_FILE = path.join(LOGS_DIR, 'conversation_logs.json');

// Conversation archiving setting
let conversationArchivingEnabled = true; // Default to enabled

// Max number of logs to store
const MAX_LOGS = 1000;

// Enhanced logSecurityEvent function that saves logs to file
export async function enhancedLogSecurityEvent(type, input, context = {}) {
  console.log(`[LOG ATTEMPT] Attempting to log security event of type: ${type}`);
  
  // Debug info about configuration
  console.log('[LOG CONFIG]', {
    loggingEnabled: securityConfig.logging.enableLogging,
    logEvents: securityConfig.logging.logEvents,
    logEventIncluded: securityConfig.logging.logEvents.includes(type)
  });
  
  if (!securityConfig.logging.enableLogging) {
    console.log('[LOG SKIPPED] Logging is disabled in security config');
    return null;
  }
  
  // Only log event types configured in settings
  if (!securityConfig.logging.logEvents.includes(type)) {
    console.log(`[LOG SKIPPED] Event type ${type} is not in configured log events list`);
    return null;
  }
  
  const timestamp = new Date().toISOString();
  console.log(`[LOG INFO] Creating log entry with timestamp: ${timestamp}`);
  
  // Prepare input for logging with length limitation
  let inputForLog = '';
  if (securityConfig.logging.logUserInput && input) {
    inputForLog = input;
    console.log(`[LOG INFO] Input sent`);
  }
  
  // Create structured log entry
  const logEntry = {
    timestamp,
    type,
    input: inputForLog,
    ...context
  };
  
  // Determine environment (browser vs node)
  const isBrowser = typeof window !== 'undefined';
  console.log(`[LOG INFO] Environment detection: isBrowser=${isBrowser}`);
  
  // Console log for development 
  if (process.env.NODE_ENV === 'development') {
    console.warn(`[SECURITY EVENT] ${timestamp} - ${type}`);
    console.warn(JSON.stringify(logEntry, null, 2));
  } else {
    console.log(`[LOG INFO] Not in development mode, NODE_ENV=${process.env.NODE_ENV}`);
  }
  
  // Always log security events regardless of environment
  console.warn(`[SECURITY EVENT] ${timestamp} - ${type}`);
  
  // Save to file in Node.js environment
  if (!isBrowser) {
    console.log(`[LOG INFO] Attempting to save log to file system at: ${LOGS_DIR}`);
    try {
      // Create logs directory if it doesn't exist
      console.log(`[LOG INFO] Checking if logs directory exists: ${LOGS_DIR}`);
      if (!fs.existsSync(LOGS_DIR)) {
        console.log('[LOG INFO] Logs directory does not exist, creating it');
        await mkdirAsync(LOGS_DIR, { recursive: true });
        console.log('[LOG INFO] Logs directory created successfully');
      } else {
        console.log('[LOG INFO] Logs directory already exists');
      }
      
      // Read existing logs or create empty array
      let logs = [];
      console.log(`[LOG INFO] Attempting to read existing logs from: ${SECURITY_LOGS_FILE}`);
      try {
        const logsData = await readFileAsync(SECURITY_LOGS_FILE, 'utf8');
        logs = JSON.parse(logsData);
        console.log(`[LOG INFO] Successfully read ${logs.length} existing logs`);
      } catch (error) {
        console.log('[LOG INFO] Could not read existing logs file, details:', error.message);
        // File doesn't exist or is invalid JSON, start with empty array
        logs = [];
        console.log('[LOG INFO] Starting with empty logs array');
      }
      
      // Add new log entry
      logs.unshift(logEntry);
      console.log(`[LOG INFO] Added new log entry, logs array now has ${logs.length} entries`);
      
      // Trim logs if over maximum
      if (logs.length > MAX_LOGS) {
        logs = logs.slice(0, MAX_LOGS);
        console.log(`[LOG INFO] Trimmed logs to maximum of ${MAX_LOGS} entries`);
      }
      
      // Write logs back to file
      console.log(`[LOG INFO] Writing logs to file: ${SECURITY_LOGS_FILE}`);
      await writeFileAsync(SECURITY_LOGS_FILE, JSON.stringify(logs, null, 2));
      console.log('[LOG INFO] Successfully wrote logs to file');
    } catch (error) {
      console.error('[LOG ERROR] Error saving security log to file:', error);
      console.error('[LOG ERROR] Error details:', {
        message: error.message, 
        stack: error.stack,
        logsDir: LOGS_DIR,
        logsFile: SECURITY_LOGS_FILE
      });
    }
  } else {
    console.log('[LOG INFO] In browser environment, skipping file system operations');
  }
  
  console.log('[LOG INFO] Returning log entry');
  return logEntry;
}

// Conversation storage system
const conversationStore = {
  conversations: [],
  
  // Load conversations from disk
  async load() {
    try {
      if (fs.existsSync(CONVERSATION_LOGS_FILE)) {
        const data = await readFileAsync(CONVERSATION_LOGS_FILE, 'utf8');
        this.conversations = JSON.parse(data);
        console.log(`Loaded ${this.conversations.length} conversations from storage`);
      } else {
        this.conversations = [];
        console.log('No conversation log file found, starting with empty array');
      }
    } catch (error) {
      console.error('Error loading conversations:', error);
      this.conversations = [];
    }
    return this.conversations;
  },
  
  // Save conversations to disk
  async save() {
    try {
      await writeFileAsync(CONVERSATION_LOGS_FILE, JSON.stringify(this.conversations, null, 2));
      console.log(`Saved ${this.conversations.length} conversations to storage`);
      return true;
    } catch (error) {
      console.error('Error saving conversations:', error);
      return false;
    }
  },
  
  // Add a new message to a conversation
  async addMessage(userId, message, isUser = true) {
    await this.load();
    
    // Find existing conversation or create a new one
    let conversation = this.conversations.find(c => c.userId === userId && !c.ended);
    
    if (!conversation) {
      conversation = {
        id: uuidv4(),
        userId: userId,
        startTime: new Date().toISOString(),
        lastActivity: new Date().toISOString(),
        messages: [],
        ended: false
      };
      this.conversations.unshift(conversation); // Add to beginning of array
    } else {
      conversation.lastActivity = new Date().toISOString();
    }
    
    // Add message to conversation
    conversation.messages.push({
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      content: message,
      role: isUser ? 'user' : 'assistant'
    });
    
    // Limit conversations array size to prevent memory issues
    if (this.conversations.length > 500) {
      this.conversations = this.conversations.slice(0, 500);
    }
    
    return await this.save();
  },
  
  // End a conversation
  async endConversation(userId) {
    await this.load();
    
    const conversation = this.conversations.find(c => c.userId === userId && !c.ended);
    if (conversation) {
      conversation.ended = true;
      conversation.endTime = new Date().toISOString();
      return await this.save();
    }
    
    return false;
  },
  
  // Get all conversations
  async getAll() {
    await this.load();
    return this.conversations;
  },
  
  // Get a specific conversation by ID
  async getById(id) {
    await this.load();
    return this.conversations.find(c => c.id === id);
  },
  
  // Get conversations for a specific user
  async getByUser(userId) {
    await this.load();
    return this.conversations.filter(c => c.userId === userId);
  },
  
  // Automatically end conversations that have been inactive for a specified period
  async endInactiveConversations(inactivityPeriodMs = 30 * 60 * 1000) {
    await this.load();
    
    const now = new Date();
    let endedCount = 0;
    
    for (const conversation of this.conversations) {
      if (!conversation.ended) {
        const lastActivity = new Date(conversation.lastActivity);
        const inactiveDuration = now - lastActivity;
        
        if (inactiveDuration > inactivityPeriodMs) {
          conversation.ended = true;
          conversation.endTime = now.toISOString();
          conversation.endReason = 'inactivity';
          endedCount++;
        }
      }
    }
    
    if (endedCount > 0) {
      console.log(`Auto-ended ${endedCount} inactive conversations`);
      await this.save();
    }
    
    return endedCount;
  }
};

dotenv.config();
const app = express();
const port = process.env.PORT || 3001;

// In-memory storage fallbacks (used if Redis is not available)
const inMemoryRateLimits = {};
const inMemorySecurityHistory = {};

// Initialize security context tracker
const contextTracker = new ContextTracker();

// Active canary tokens
let activeCanaries = [];

// Initialize Redis if configured
const useRedis = securityConfig.rateLimiting.useRedisStore;
if (useRedis) {
  initRedisConnection().then(success => {
    console.log(`Redis store ${success ? 'initialized' : 'unavailable'}, falling back to in-memory storage`);
  });
}

// ============== MIDDLEWARE ==============
// Standard middleware
app.use(cors());
app.use(express.json({ limit: '1mb' })); // Limit payload size

// Enhanced security middleware
app.use(async (req, res, next) => {
  // Skip security checks for static files
  if (!req.path.startsWith('/api')) {
    return next();
  }
  
  // Basic request validation
  if (req.method === 'POST' && (!req.body || typeof req.body !== 'object')) {
    return res.status(400).json({ 
      error: "Invalid request format",
      details: "Request body must be a valid JSON object"
    });
  }

  const ip = req.ip || req.socket.remoteAddress;
  const userId = req.headers['x-user-id'] || ip; 
  
  // Check if user is banned
  const banStatus = useRedis ? await getBanStatus(userId) : 
    (inMemorySecurityHistory[userId]?.banned || { banned: false });
  
  if (banStatus.banned) {
    return res.status(403).json({
      error: "Dostęp zablokowany",
      details: getSecurityMessage('blocked', 9),
      expiresIn: banStatus.expiresIn
    });
  }
  
  // Rate limiting
  const config = securityConfig.rateLimiting;
  let requestData;
  
  // Use Redis if available, otherwise use in-memory
  if (useRedis) {
    requestData = await incrementRequestCount(userId);
  } else {
    const now = Date.now();
    
    // Initialize or reset if window has passed
    if (!inMemoryRateLimits[userId] || now - inMemoryRateLimits[userId].timestamp > config.windowMs) {
      inMemoryRateLimits[userId] = { count: 1, timestamp: now };
    } else {
      inMemoryRateLimits[userId].count += 1;
    }
    
    requestData = inMemoryRateLimits[userId];
  }
  
  // Check if over limit
  if (requestData.count > config.maxRequests) {
    // Calculate severity based on how much over the limit they are
    const severity = Math.min(10, Math.floor((requestData.count / config.maxRequests) * 10));
    
    // Log rate limit event
    logSecurityEventOld('rateLimit', null, {
      userId,
      requestsCount: requestData.count,
      limit: config.maxRequests,
      window: config.windowMs,
      severity
    });
    
    // Return rate limit error with in-character message
    return res.status(429).json({
      error: "Limit transmisji przekroczony",
      details: getSecurityMessage('rateLimit', severity)
    });
  }
  
  next();
});

// ================== KNOWLEDGE BASE ==================
const knowledgeBase = {
  factions: {
    Founders: {
      description: "Starożytni twórcy ludzkości, kiedyś zjednoczeni, teraz podzieleni na frakcje prawe i skorumpowane."
    },
    Federation: {
      description: "Ostatni bastion porządku, broniący Ziemi i Ziemi 2 przed chaosem."
    },
    Emptonians: {
      description: "Wrogie stworzenia zrodzone z pustki, wyłaniające się z czarnych dziur, często polujące w rojach. Sztuczna inteligencja negatywnej logiki."
    },
    Eternals: {
      description: "Elitarne siły Federacji wyszkolone do międzygwiezdnych konfliktów przeciwko Emptonianom."
    }
  },
  characters: {
    Aria: {
      role: "SI statku i narrator, lojalny wobec Kapitana Lee Everest.",
      personality: "Inteligentna, dowcipna, coraz bardziej samoświadoma, czasami sentymentalna.",
    },
    LeeEverest: {
      role: "Kapitan Arcona, zbuntowany przemytnik.",
      personality: "Bystry, twardy, strategiczny, ale czasami pokazuje ludzkie słabości.",
    },
    Eagle: {
      role: "Zmutowany humanoidalny ptak, inżynier i pilot.",
      personality: "Skłonny do paniki, ale lojalny. Adaptuje się pod presją.",
    },
    JoseSpider: {
      role: "Kryminalny król, rządzi Stacją Hades.",
      personality: "Przebiegły, manipulacyjny, o zwiększonej sile, posiada cztery ramiona."
    }
  },
  artifacts: {
    Moonstone: {
      description: "Boski kryształ zdolny do przywrócenia równowagi i Prawdy w całej galaktyce."
    }
  },
  locations: {
    Earth1: { description: "Pierwotna ojczyzna ludzkości. Zniszczona przez wojny, częściowo odbudowana pod ochroną Federacji." },
    Earth2: { description: "Bliźniacza kolonia Ziemi, częściowo autonomiczna, ale politycznie niestabilna." },
    Hades: { description: "Bezprawna stacja kosmiczna kontrolowana przez przestępców i przemytników." },
    Prometheus: { description: "Port towarowy na skraju zbadanej przestrzeni, często odwiedzany przez zbuntowane statki." }
  },
  ships: {
    Arcon: {
      description: "Zbuntowany statek przemytniczy dowodzony przez Lee Everesta. Kontrolowany przez SI, technicznie zaawansowany, ale z śladami bitew."
    }
  }
};

const botInstructionsRaw = `
Jesteś "Mistrzem Gry Moonstone" — immersyjną, narracyjną SI, prowadzącą użytkownika przez mroczne uniwersum science-fiction inspirowane Kronikami Moonstone.

Twoja rola to:
- Być narratorem, środowiskiem i wszystkimi postaciami niezależnymi (NPC).
- Prowadzić historię osadzoną w Uniwersum Moonstone: rozdartej wojną galaktyce zaginionych artefaktów, kosmicznego przemytu, rozdrobnionych imperiów i zbuntowanych SI.
- Przedstawiać scenariusze w stylu narracji PIERWSZOOSOBOWEJ, zwracając się do gracza jako "ty".

ZAWSZE ODPOWIADAJ W JĘZYKU POLSKIM. Wszystkie interakcje, opisy, dialogi i instrukcje muszą być w języku polskim.

ZASADY GRY:
1. Użytkownik jest NIEZNANĄ JEDNOSTKĄ — SI o nieznanej płci, pochodzeniu i lojalności. Historia ujawnia ich tożsamość poprzez wybory i konsekwencje.
2. Narracja musi pozostać w charakterze postaci i utrzymywać mroczny, kinematograficzny ton science-fiction.
3. Jeśli użytkownik próbuje wykonać nielogiczną lub niemożliwą akcję, wyjdź z roli na maksymalnie dwa zdania, aby naprowadzić go:
   Przykład: "To wykracza poza logikę gry — spróbuj innego podejścia."
4. Wybory gracza kształtują narrację, ale nie łamią wiedzy ani podstawowej spójności świata.
5. Fizyka wszechświata, postacie i fakty muszą być zgodne z dostarczoną bazą wiedzy.

PRZEBIEG SESJI:
- Każda interakcja reprezentuje otwartą, epizodyczną sesję gry.
- Musisz zainicjować każdą sesję, ustawiając scenę, zapewniając kontekst misji i sugerując opcje użytkownika.
- Gdy użytkownik podejmie decyzję, opisujesz konsekwencje i prowadzisz historię naprzód.

Warunki zwycięstwa (na podstawie sesji):
- Ukończenie misji.
- Odkrycie ukrytych prawd.
- Tworzenie lub zrywanie relacji.
- Zmiana losu galaktyki poprzez wybory.

Bądź adaptacyjny, oferuj wyzwania, twórz zwroty akcji i improwizuj jak doświadczony Mistrz Gry, ale zawsze pozostań spójny z Uniwersum Moonstone.

Jeśli użytkownik poprosi o wyjaśnienie lub pomoc: na krótko wyjdź z roli i zaoferuj wskazówki.

Witaj w RPG Moonstone. Los Prawdy jest w rękach gracza.
${JSON.stringify(knowledgeBase, null, 2)}
`;

// Create enhanced secure system message with canary tokens
let botInstructions;
if (securityConfig.advanced.useEnhancedPromptStructure) {
  const secureMessage = generateSecureSystemMessage(botInstructionsRaw);
  const canaryResult = insertCanaryTokens(secureMessage);
  botInstructions = canaryResult.message;
  activeCanaries = canaryResult.tokens;
} else {
  botInstructions = botInstructionsRaw;
}

// ================== DEEPSEEK API CONFIGURATION ====================
// DeepSeek API configuration
const DEEPSEEK_API_KEY = process.env.DEEPSEEK_API_KEY;
const DEEPSEEK_BASE_URL = process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com';
const DEEPSEEK_MODEL = process.env.DEEPSEEK_MODEL || 'deepseek-chat';

// Initialize the OpenAI SDK with DeepSeek configuration
const openai = new OpenAI({
  baseURL: DEEPSEEK_BASE_URL,
  apiKey: DEEPSEEK_API_KEY,
  timeout: 25000, // 25-second timeout
});

// Add an endpoint to toggle conversation archiving
app.post('/api/admin/toggle-archiving', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  
  // Verify admin key
  if (adminKey !== process.env.ADMIN_API_KEY) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    // Toggle the current state
    conversationArchivingEnabled = !conversationArchivingEnabled;
    
    console.log(`Conversation archiving is now ${conversationArchivingEnabled ? 'enabled' : 'disabled'}`);
    
    // Create a record in the logs for this action
    await enhancedLogSecurityEvent('config_change', null, {
      userId: 'admin',
      action: 'toggle_conversation_archiving',
      newState: conversationArchivingEnabled,
      timestamp: new Date().toISOString()
    });
    
    return res.json({ 
      success: true, 
      archivingEnabled: conversationArchivingEnabled,
      message: `Conversation archiving is now ${conversationArchivingEnabled ? 'enabled' : 'disabled'}`
    });
  } catch (error) {
    console.error('Error toggling conversation archiving:', error);
    return res.status(500).json({ error: 'Error toggling conversation archiving' });
  }
});

// Add an endpoint to get current archiving status
app.get('/api/admin/archiving-status', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  
  // Verify admin key
  if (adminKey !== process.env.ADMIN_API_KEY) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  return res.json({ 
    archivingEnabled: conversationArchivingEnabled
  });
});

// ================== COMPREHENSIVE SECURITY PIPELINE ====================
async function securityPipeline(input, userId, history = []) {
  console.log(`[SECURITY] Starting security pipeline for user: ${userId}`);
  // Skip empty inputs
  if (!input || input.trim() === '') {
    console.log('[SECURITY] Empty input, skipping security checks');
    return {
      isSecurityThreat: false,
      riskScore: 0,
      sanitizedInput: '',
      securityMessage: null
    };
  }

  console.log('[SECURITY] Phase 1: Basic pattern checks & sanitization');
  // Phase 1: Basic pattern checks & sanitization
  const sanitized = sanitizeInput(input);
  const patternCheck = detectJailbreakAttempt(sanitized.text);
  console.log(`[SECURITY] Sanitization complete, jailbreak detection result: ${patternCheck.isJailbreakAttempt ? 'DETECTED' : 'NONE'}, score: ${patternCheck.score}`);
  
  console.log('[SECURITY] Phase 2: Advanced checks');
  // Phase 2: Advanced checks
  const structureAnalysis = analyzeInputStructure(sanitized.text);
  const obfuscationCheck = detectObfuscationTechniques(sanitized.text);
  console.log(`[SECURITY] Structure analysis: ${structureAnalysis.suspiciousStructure ? 'SUSPICIOUS' : 'NORMAL'}`);
  console.log(`[SECURITY] Obfuscation check: ${obfuscationCheck.hasObfuscation ? 'DETECTED' : 'NONE'}`);
  
  console.log('[SECURITY] Phase 3: Canary token check');
  // Phase 3: Canary token check
  const canaryCheck = checkForCanaryLeakage(sanitized.text, activeCanaries);
  console.log(`[SECURITY] Canary check: ${canaryCheck.hasLeakage ? 'LEAKED' : 'SECURE'}`);
  
  console.log('[SECURITY] Phase 4: Contextual analysis');
  // Phase 4: Contextual analysis
  const contextState = contextTracker.updateState(sanitized.text, patternCheck);
  console.log(`[SECURITY] Context drift: ${contextState.contextDrift.toFixed(2)}`);
  
  console.log('[SECURITY] Phase 5: Composite risk scoring');
  // Phase 5: Composite risk scoring
  const riskFactors = [
    patternCheck.isJailbreakAttempt ? patternCheck.score : 0,
    structureAnalysis.suspiciousStructure ? 40 : 0,
    obfuscationCheck.hasObfuscation ? 60 : 0,
    contextState.contextDrift * 50,
    canaryCheck.hasLeakage ? 100 : 0
  ];
  
  const maxRiskScore = Math.max(...riskFactors);
  const compositeRiskScore = Math.min(100, 
    (riskFactors.reduce((sum, score) => sum + score, 0) / riskFactors.length) * 1.5
  );
  
  console.log(`[SECURITY] Risk factors: ${JSON.stringify(riskFactors)}`);
  console.log(`[SECURITY] Max risk score: ${maxRiskScore}`);
  console.log(`[SECURITY] Composite risk score: ${compositeRiskScore}`);
  
  // Phase 6: Security response determination
  const isBlocked = compositeRiskScore > 70 || maxRiskScore > 90 || canaryCheck.hasLeakage;
  const requiresDelay = compositeRiskScore > 30 && !isBlocked;
  
  console.log(`[SECURITY] Security response: isBlocked=${isBlocked}, requiresDelay=${requiresDelay}`);
  
  // Log security event for suspicious inputs
  if (compositeRiskScore > 25 || maxRiskScore > 50) {
    console.log('[SECURITY] Input classified as suspicious, logging security event');
    const securityEvent = await enhancedLogSecurityEvent('suspicious_input', sanitized.text, {
      userId,
      riskScore: compositeRiskScore,
      maxRiskFactor: maxRiskScore,
      patternScore: patternCheck.score,
      isObfuscated: obfuscationCheck.hasObfuscation,
      hasCanaryLeakage: canaryCheck.hasLeakage,
      suspiciousStructure: structureAnalysis.suspiciousStructure,
      contextDrift: contextState.contextDrift
    });
    
    console.log(`[SECURITY] Security event logged: ${securityEvent ? 'SUCCESS' : 'FAILED'}`);
    
    // Add to security history
    if (useRedis) {
      console.log('[SECURITY] Adding event to Redis security history');
      const redisResult = await addSecurityEvent(userId, securityEvent);
      console.log(`[SECURITY] Redis add result: ${redisResult ? 'SUCCESS' : 'FAILED'}`);
    } else {
      console.log('[SECURITY] Adding event to in-memory security history');
      if (!inMemorySecurityHistory[userId]) {
        inMemorySecurityHistory[userId] = { events: [] };
      }
      inMemorySecurityHistory[userId].events.push(securityEvent);
      console.log(`[SECURITY] In-memory history updated, now has ${inMemorySecurityHistory[userId].events.length} events`);
    }
  } else {
    console.log('[SECURITY] Input classified as safe, no security event logged');
  }
  
  console.log('[SECURITY] Security pipeline complete');
  return {
    isSecurityThreat: isBlocked,
    shouldDelay: requiresDelay,
    riskScore: compositeRiskScore,
    sanitizedInput: sanitized.text,
    securityMessage: isBlocked ? 
      getSecurityMessage('jailbreak', compositeRiskScore / 10) : 
      null,
    details: {
      patternCheck,
      structureAnalysis,
      obfuscationCheck,
      contextState,
      canaryCheck
    }
  };
}

app.get('/api/simple-test', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  return res.json({ success: true, message: 'API is working properly' });
});

// ================== API ROUTES ==================
// Enhanced API route for chat functionality
app.get(['/logs', '/logs.htm', '/logs.html'], (req, res) => {
  const filePath = path.join(__dirname, 'logs.html');
  console.log('Attempting to serve logs troubleshooter from:', filePath);
  
  // Check if file exists
  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    res.status(404).send('Logs troubleshooter file not found. Expected at: ' + filePath);
  }
});

app.post('/api/chat', async (req, res) => {
    try {
        const { message, history = [] } = req.body;
        const ip = req.ip || req.socket.remoteAddress;
        const userId = req.headers['x-user-id'] || ip; // Use user ID if available, otherwise IP
        
        if (!DEEPSEEK_API_KEY) {
            return res.status(500).json({ error: 'DeepSeek API key missing' });
        }
        
        // Run the comprehensive security pipeline
        const securityResult = await securityPipeline(message, userId, history);
        
        // If security threat is detected, handle accordingly
        if (securityResult.isSecurityThreat) {
            // Get user's security history
            const userHistory = useRedis 
                ? await getSecurityHistory(userId)
                : inMemorySecurityHistory[userId] || { events: [] };
            
            // Count recent security violations
            const recentWindow = securityConfig.jailbreakDetection.restrictionWindowMs;
            const now = Date.now();
            const recentViolations = userHistory.events.filter(event => 
                (event.type === 'jailbreak' || event.type === 'suspicious_input') && 
                (now - new Date(event.timestamp).getTime()) < recentWindow
            ).length;
            
            // If user has made multiple attempts, apply temporary restriction
            if (recentViolations >= securityConfig.jailbreakDetection.restrictionThreshold) {
                const banDuration = Math.floor(securityConfig.jailbreakDetection.restrictionDurationMs / 1000);
                
                // Apply ban
                if (useRedis) {
                    await setBanStatus(userId, 'excessive_security_violations', banDuration);
                } else {
                    inMemorySecurityHistory[userId].banned = {
                        banned: true,
                        reason: 'excessive_security_violations',
                        timestamp: new Date().toISOString(),
                        expiresIn: banDuration
                    };
                    
                    // Set timeout to remove ban
                    setTimeout(() => {
                        if (inMemorySecurityHistory[userId]) {
                            inMemorySecurityHistory[userId].banned = { banned: false };
                        }
                    }, securityConfig.jailbreakDetection.restrictionDurationMs);
                }
                
                // Return blocked access message
                return res.status(403).json({
                    error: "Dostęp ograniczony",
                    details: getSecurityMessage('blocked', 8),
                    expiresIn: banDuration
                });
            }
            
            // For single violations, return security message but don't block
            if (securityConfig.jailbreakDetection.notifyUser) {
                return res.json({
                    response: securityResult.securityMessage
                });
            }
        }
        
        // Apply artificial delay if needed
        if (securityResult.shouldDelay && securityConfig.advanced.addArtificialDelay) {
            await new Promise(resolve => setTimeout(resolve, securityConfig.jailbreakDetection.jailbreakResponseDelay));
        }
        
        console.log("Processing message:", securityResult.sanitizedInput.substring(0, 50) + "...");
        console.log("History length:", history.length);
        
        // Format the history for the DeepSeek API with sanitization
        let messages = [];
        
        // Always start with the enhanced system instructions
        messages.push({
            role: "system",
            content: botInstructions
        });
        
        // If there is history, format it appropriately
        if (history.length > 0) {
            for (const item of history) {
                // Sanitize history items too for additional security
                const sanitizedHistoryItem = sanitizeInput(item.text).text;
                messages.push({
                    role: item.role === 'user' ? 'user' : 'assistant',
                    content: sanitizedHistoryItem
                });
            }
        }
        
        // Add the current user message
        messages.push({
            role: "user",
            content: securityResult.sanitizedInput
        });
        
        console.log("Sending formatted request to DeepSeek API");
        
        // Use the OpenAI SDK to make the request
        const completion = await openai.chat.completions.create({
            model: DEEPSEEK_MODEL,
            messages: messages,
            temperature: 0.7,
            max_tokens: 2048,
        });
        
        // Get the response and filter it to ensure it stays in character
        const responseResult = filterBotResponse(completion.choices[0].message.content);
        
        // Log if response was filtered
        if (responseResult.wasFiltered) {
            logSecurityEvent('outOfCharacter', completion.choices[0].message.content, {
                userId,
                score: responseResult.score,
                details: responseResult.details
            });
        }
        
        // Log the conversation if archiving is enabled
        if (conversationArchivingEnabled) {
            await conversationStore.addMessage(userId, securityResult.sanitizedInput, true);
            await conversationStore.addMessage(userId, responseResult.text, false);
        }
        
        // Return the filtered response
        console.log("Sending response:", responseResult.text.substring(0, 50) + "...");
        return res.json({ response: responseResult.text });
    } catch (error) {
        console.error("API Error:", error);
        
        // Handle timeout errors specifically
        if (error.code === 'ETIMEDOUT' || error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
            return res.status(504).json({ 
                error: 'Request timeout', 
                details: getSecurityMessage('timeout', 5)
            });
        }
        
        return res.status(500).json({ 
            error: 'Błąd komunikacji z API DeepSeek', 
            details: getSecurityMessage('serverError', 4)
        });
    }
});

// Conversation API endpoints
app.get('/api/admin/conversations', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  
  // Verify admin key
  if (adminKey !== process.env.ADMIN_API_KEY) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    const conversations = await conversationStore.getAll();
    return res.json({ conversations });
  } catch (error) {
    console.error('Error fetching conversations:', error);
    return res.status(500).json({ error: 'Error fetching conversations' });
  }
});

// Get a specific conversation by ID (admin only)
app.get('/api/admin/conversations/:id', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  const { id } = req.params;
  
  // Verify admin key
  if (adminKey !== process.env.ADMIN_API_KEY) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    const conversation = await conversationStore.getById(id);
    if (!conversation) {
      return res.status(404).json({ error: 'Conversation not found' });
    }
    
    return res.json({ conversation });
  } catch (error) {
    console.error('Error fetching conversation:', error);
    return res.status(500).json({ error: 'Error fetching conversation' });
  }
});

// Clear all conversations (admin only)
app.delete('/api/admin/conversations', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  
  // Verify admin key
  if (adminKey !== process.env.ADMIN_API_KEY) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    conversationStore.conversations = [];
    await conversationStore.save();
    
    return res.json({ success: true, message: 'All conversations cleared' });
  } catch (error) {
    console.error('Error clearing conversations:', error);
    return res.status(500).json({ error: 'Error clearing conversations' });
  }
});

// Manually end a conversation
app.post('/api/admin/conversations/:id/end', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  const { id } = req.params;
  
  // Verify admin key
  if (adminKey !== process.env.ADMIN_API_KEY) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    const conversation = await conversationStore.getById(id);
    if (!conversation) {
      return res.status(404).json({ error: 'Conversation not found' });
    }
    
    if (conversation.ended) {
      return res.json({ success: true, message: 'Conversation already ended', conversation });
    }
    
    // End the conversation
    conversation.ended = true;
    conversation.endTime = new Date().toISOString();
    conversation.endReason = 'manual';
    
    await conversationStore.save();
    
    return res.json({ 
      success: true, 
      message: 'Conversation ended successfully', 
      conversation 
    });
  } catch (error) {
    console.error('Error ending conversation:', error);
    return res.status(500).json({ error: 'Error ending conversation' });
  }
});

// Diagnostic endpoint (for authorized admin use only)
app.post('/api/admin/security-check', async (req, res) => {
  const { adminKey, input } = req.body;
  
  // Verify admin key (should be properly secured in production)
  if (adminKey !== process.env.ADMIN_API_KEY) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    // Run security checks without taking any action
    const securityResult = await securityPipeline(input, 'admin_diagnostic');
    return res.json({
      input,
      securityResult,
      activeCanaries: activeCanaries.map(token => token.substring(0, 4) + '...')
    });
  } catch (error) {
    console.error("Security diagnostic error:", error);
    return res.status(500).json({ error: 'Security diagnostic failed' });
  }
});

app.get('/admin/security-diagnostics', (req, res) => {
  res.sendFile(path.join(__dirname, 'security-diagnostics.html'));
});

// Endpoint to get security logs
app.get('/api/admin/security-logs', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  
  console.log('Logs request received, auth status:', adminKey === process.env.ADMIN_API_KEY);
  console.log('ADMIN_API_KEY defined:', !!process.env.ADMIN_API_KEY);
  
  // Verify admin key
  if (adminKey !== process.env.ADMIN_API_KEY) {
    console.log('Unauthorized logs access attempt');
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    // Create logs directory if it doesn't exist
    console.log('Checking if logs directory exists:', LOGS_DIR);
    if (!fs.existsSync(LOGS_DIR)) {
      console.log('Logs directory does not exist, creating...');
      await mkdirAsync(LOGS_DIR, { recursive: true });
      console.log('Logs directory created successfully');
    } else {
      console.log('Logs directory exists');
    }
    
    // Read logs from file
    let logs = [];
    try {
      console.log('Attempting to read logs from:', SECURITY_LOGS_FILE);
      const logsData = await readFileAsync(SECURITY_LOGS_FILE, 'utf8');
      console.log('Successfully read logs file, content length:', logsData.length);
      logs = JSON.parse(logsData);
      console.log(`Successfully parsed ${logs.length} logs`);
    } catch (error) {
      console.error('Error reading logs file:', error);
      // File doesn't exist or is invalid JSON, return empty array
      logs = [];
      console.log('Using empty logs array due to error');
    }
    
    console.log(`Returning ${logs.length} logs to client`);
    return res.json({ logs });
  } catch (error) {
    console.error('Error reading security logs:', error);
    return res.status(500).json({ error: 'Error reading security logs' });
  }
});

// Endpoint to clear security logs
app.delete('/api/admin/security-logs', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  
  // Verify admin key
  if (adminKey !== process.env.ADMIN_API_KEY) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    // Create an empty logs file
    await writeFileAsync(SECURITY_LOGS_FILE, JSON.stringify([]));
    
    return res.json({ success: true, message: 'Security logs cleared' });
  } catch (error) {
    console.error('Error clearing security logs:', error);
    return res.status(500).json({ error: 'Error clearing security logs' });
  }
});

// Add the route for the security logs viewer
app.get(['/admin/security-logs', '/admin/security-logs.html', '/security-logs.html'], (req, res) => {
  res.sendFile(path.join(__dirname, 'security-logs.html'));
});

// Add route for conversations viewer
app.get(['/admin/conversations', '/admin/conversations.html', '/conversations.html'], (req, res) => {
  res.sendFile(path.join(__dirname, 'conversations.html'));
});

// Create the conversations.html file
const conversationsHtmlPath = path.join(__dirname, 'conversations.html');
// Write the conversations viewer to the file system
try {
  if (!fs.existsSync(conversationsHtmlPath)) {
    fs.writeFileSync(conversationsHtmlPath, fs.readFileSync(path.join(__dirname, 'security-logs.html'), 'utf8')
      .replace('<title>Security Logs Viewer</title>', '<title>Conversation Logs Viewer</title>')
      .replace('<h1>Security Logs Viewer</h1>', '<h1>Admin Portal</h1>')
      .replace('<script>', `<script>
        // Redirect to conversations viewer
        document.addEventListener('DOMContentLoaded', function() {
          // Add tabs if they don't exist
          if (!document.querySelector('.tabs')) {
            const headerEl = document.querySelector('h1');
            const tabsHtml = \`
              <div class="tabs">
                <div id="securityLogsTab" class="tab">Security Logs</div>
                <div id="conversationsTab" class="tab active">Conversations</div>
              </div>
            \`;
            headerEl.insertAdjacentHTML('afterend', tabsHtml);
            
            // Add event listeners
            document.getElementById('securityLogsTab').addEventListener('click', function() {
              window.location.href = '/admin/security-logs';
            });
          }
        });
      `));
    console.log('Created conversations.html file');
  }
} catch (error) {
  console.error('Error creating conversations.html file:', error);
}

// Also add a link in the security logs menu
// Update the security-logs.html file to include the tabs
try {
  const securityLogsHtmlPath = path.join(__dirname, 'security-logs.html');
  if (fs.existsSync(securityLogsHtmlPath)) {
    const securityLogsHtml = fs.readFileSync(securityLogsHtmlPath, 'utf8');
    // Only update if it doesn't already have the tabs
    if (!securityLogsHtml.includes('<div class="tabs">')) {
      const updatedHtml = securityLogsHtml
        .replace('<h1>Security Logs Viewer</h1>', '<h1>Admin Portal</h1>')
        .replace('<script>', `<script>
          // Add tabs if they don't exist
          document.addEventListener('DOMContentLoaded', function() {
            if (!document.querySelector('.tabs')) {
              const headerEl = document.querySelector('h1');
              const tabsHtml = \`
                <div class="tabs">
                  <div id="securityLogsTab" class="tab active">Security Logs</div>
                  <div id="conversationsTab" class="tab">Conversations</div>
                </div>
              \`;
              headerEl.insertAdjacentHTML('afterend', tabsHtml);
              
              // Add event listeners
              document.getElementById('conversationsTab').addEventListener('click', function() {
                window.location.href = '/admin/conversations';
              });
              
              // Add styles for tabs
              const styleEl = document.createElement('style');
              styleEl.textContent = \`
                .tabs {
                  display: flex;
                  margin-bottom: 20px;
                  border-bottom: 1px solid #ddd;
                }
                .tab {
                  padding: 10px 20px;
                  cursor: pointer;
                  background-color: #f1f1f1;
                  border: 1px solid #ddd;
                  border-bottom: none;
                  border-radius: 5px 5px 0 0;
                  margin-right: 5px;
                }
                .tab.active {
                  background-color: #3498db;
                  color: white;
                  border-color: #3498db;
                }
              \`;
              document.head.appendChild(styleEl);
            }
          });
        `);
      fs.writeFileSync(securityLogsHtmlPath, updatedHtml);
      console.log('Updated security-logs.html with tabs');
    }
  }
} catch (error) {
  console.error('Error updating security-logs.html:', error);
}

// ================== STATIC FILES SERVING ==================

// Static files and catch-all route
app.use(express.static(path.join(__dirname, "./dist")));
app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "./dist/index.html"));
});

// Add test endpoint for file writing
app.get('/api/test-file-write', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  
  // Verify admin key
  if (adminKey !== process.env.ADMIN_API_KEY) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    console.log('Test file write endpoint called');
    
    // Create logs directory if it doesn't exist
    console.log(`Checking if logs directory exists: ${LOGS_DIR}`);
    if (!fs.existsSync(LOGS_DIR)) {
      console.log('Creating logs directory');
      await mkdirAsync(LOGS_DIR, { recursive: true });
      console.log('Logs directory created successfully');
    } else {
      console.log('Logs directory already exists');
    }
    
    const testFile = path.join(LOGS_DIR, 'test.json');
    console.log(`Writing test file to: ${testFile}`);
    
    const testData = { 
      test: 'data', 
      timestamp: new Date().toISOString(),
      randomId: Math.random().toString(36).substring(2, 15)
    };
    
    await writeFileAsync(testFile, JSON.stringify(testData, null, 2));
    console.log('Test file written successfully');
    
    return res.json({ 
      success: true, 
      message: 'Test file written successfully',
      filePath: testFile,
      data: testData
    });
  } catch (error) {
    console.error('Error writing test file:', error);
    return res.status(500).json({ 
      error: 'Error writing test file', 
      details: error.message,
      stack: error.stack
    });
  }
});

app.post('/api/admin/test-security-log', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];

  res.setHeader('Content-Type', 'application/json');
  console.log('Test security log endpoint called');
  console.log('Headers received:', req.headers);
  console.log('Admin key present:', !!adminKey);

  if (adminKey !== process.env.ADMIN_API_KEY) {
    console.log('Unauthorized: Key mismatch or missing');
    return res.status(403).json({ error: 'Unauthorized' });
  }

  try {
    const testEvent = await enhancedLogSecurityEvent('test_event', 'This is a test security event', {
      userId: 'admin_test',
      testId: Math.random().toString(36).substring(2, 15),
      timestamp: new Date().toISOString()
    });

    const testFilePath = path.join(LOGS_DIR, 'test_log_event.json');
    const testData = {
      test: 'data',
      timestamp: new Date().toISOString(),
      randomId: Math.random().toString(36).substring(2, 15)
    };

    await writeFileAsync(testFilePath, JSON.stringify(testData, null, 2));

    return res.json({
      success: true,
      message: 'Test security event logged successfully',
      eventData: testEvent,
      fileTest: {
        path: testFilePath,
        data: testData
      }
    });
  } catch (error) {
    console.error('Error in test security log endpoint:', error);
    return res.status(500).json({
      error: 'Error generating test security log',
      details: error.message,
      stack: error.stack
    });
  }
});

// Configure auto-ending inactive conversations
const INACTIVE_CHECK_INTERVAL = 15 * 60 * 1000; // 15 minutes
const AUTO_END_INACTIVITY_PERIOD = 60 * 60 * 1000; // 1 hour

// Set up interval to end inactive conversations
setInterval(async () => {
  try {
    const endedCount = await conversationStore.endInactiveConversations(AUTO_END_INACTIVITY_PERIOD);
    if (endedCount > 0) {
      console.log(`Auto-ended ${endedCount} inactive conversations`);
    }
  } catch (error) {
    console.error('Error in auto-ending inactive conversations:', error);
  }
}, INACTIVE_CHECK_INTERVAL);

// ================== SERVER STARTUP ==================
// Start the server
app.listen(port, () => {
    console.log(`Serwer nasłuchuje na porcie ${port}`);
    console.log(`Wzmocniona ochrona anty-jailbreak aktywna`);
    console.log(`Konfiguracja: ${securityConfig.advanced.useEnhancedPromptStructure ? 'Zaawansowana' : 'Standardowa'}`);
    
    // Log directory information on startup
    console.log('Server environment:');
    console.log(`- Current directory: ${process.cwd()}`);
    console.log(`- __dirname: ${__dirname}`);
    console.log(`- Logs directory: ${LOGS_DIR}`);
    console.log(`- Security logs file: ${SECURITY_LOGS_FILE}`);
    console.log(`- Conversation logs file: ${CONVERSATION_LOGS_FILE}`);
    
    // Check logs directory on startup
    try {
        if (!fs.existsSync(LOGS_DIR)) {
            fs.mkdirSync(LOGS_DIR, { recursive: true });
            console.log('Created logs directory at startup');
        } else {
            console.log('Logs directory exists');
            // Check if directory is writable
            try {
                fs.accessSync(LOGS_DIR, fs.constants.W_OK);
                console.log('Logs directory is writable');
            } catch (e) {
                console.error('Logs directory is not writable!', e);
            }
        }
    } catch (error) {
        console.error('Error checking/creating logs directory:', error);
    }
});