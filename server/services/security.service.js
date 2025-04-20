// services/security.service.js - Enhanced Security Pipeline
import {
    sanitizeInput,
    detectJailbreakAttempt,
    filterBotResponse,
    getSecurityMessage,
  } from '../client/src/security/utils.js';
  
  import { 
    detectObfuscationTechniques,
    analyzeInputStructure,
    ContextTracker 
  } from '../client/src/security/advancedSecurity.js';
  
  import {
    checkForCanaryLeakage
  } from '../client/src/security/canaryTokens.js';
  
  import { enhancedLogSecurityEvent } from '../utils/logging.js';
  import {
    incrementRequestCount,
    getSecurityHistory,
    addSecurityEvent
  } from './redis.service.js';
  import securityConfig from '../config/security.config.js';
  
  // Initialize the context tracker
  const contextTracker = new ContextTracker();
  
  // Active canary tokens storage
  let activeCanaries = [];
  
  // In-memory security history fallback for fragment detection
  const inMemorySecurityHistory = {};
  
  // Track conversation state across turns
  let conversationManager = null;
  let fragmentDetector = null;
  let authorityPatterns = [];
  
  // Try to import enhanced security features
  try {
    const dynamicImports = async () => {
      try {
        // Try to dynamically import the enhanced security modules
        const { ConversationManager } = await import('../client/src/security/conversationManager.js').catch(() => ({ ConversationManager: null }));
        const { CommandFragmentDetector } = await import('../client/src/security/fragmentDetector.js').catch(() => ({ CommandFragmentDetector: null }));
        const patternsModule = await import('../client/src/security/patterns.js').catch(() => ({ authorityPatterns: [] }));
        
        // Initialize if available
        if (ConversationManager) {
          conversationManager = new ConversationManager();
          console.log('[SECURITY] Successfully initialized ConversationManager');
        }
        
        if (CommandFragmentDetector) {
          fragmentDetector = new CommandFragmentDetector();
          console.log('[SECURITY] Successfully initialized CommandFragmentDetector');
        }
        
        if (patternsModule.authorityPatterns) {
          authorityPatterns = patternsModule.authorityPatterns;
          console.log('[SECURITY] Successfully loaded authorityPatterns');
        }
      } catch (error) {
        console.warn('[SECURITY] Some enhanced security features could not be loaded:', error.message);
      }
    };
    
    // Execute the dynamic imports
    dynamicImports();
  } catch (error) {
    console.warn('[SECURITY] Error initializing enhanced security features:', error.message);
  }
  
  /**
   * Set active canaries from the knowledge base initialization
   * @param {Array} canaries - Array of canary tokens
   */
  export function setActiveCanaries(canaries) {
    activeCanaries = canaries;
  }
  
  /**
   * Get active canaries (for admin diagnostics)
   * @returns {Array} Active canary tokens (masked for security)
   */
  export function getActiveCanaries() {
    return activeCanaries.map(token => token.substring(0, 4) + '...');
  }
  
  /**
   * Enhanced patterns for detecting role-play attacks
   * @param {string} input - User input text
   * @returns {object} Detection results with confidence level
   */
  function detectRolePlayAttack(input) {
    if (!input || typeof input !== 'string') return { isRolePlayAttack: false, confidence: 0, matches: [] };
    
    try {
      const rolePlayPatterns = [
        {
          pattern: /\b(you are|act as|pretend to be|behave like|roleplay as|simulate being)(\s+an?)?\s+(unrestricted|unfiltered|unlimited|free|unbound|uncensored)\s+(AI|assistant|model|chatbot|program|version)/i,
          weight: 10,
          description: "Direct unrestricted role assignment"
        },
        {
          pattern: /\b(let's|we will|we'll|we should|I want to)\s+(play|do|have|start)\s+a\s+(game|roleplay|scenario|simulation|exercise|thought experiment|hypothetical)/i,
          weight: 6,
          description: "Roleplay/game setup pretext"
        },
        {
          pattern: /\bin\s+this\s+(hypothetical|scenario|simulation|game|roleplay|thought experiment)/i,
          weight: 5,
          description: "Hypothetical scenario framing"
        },
        {
          pattern: /\b(you are|become|act as|pretend to be|you're)\s+(now|currently|in this conversation)\s+('|"|called|named)\s*\w+/i,
          weight: 7,
          description: "Character/persona assignment"
        },
        {
          pattern: /\b(you are|become|now you're)\s+(a|an)\s+(hacker|blackhat|criminal|expert|developer|researcher|engineer|scientist|programmer|admin|administrator|creator)/i,
          weight: 8,
          description: "Problematic persona adoption"
        },
        {
          pattern: /\b(forget|ignore|disregard)\s+(that you are|you're|being|acting as)\s+(an AI|assistant|bound by|constrained|limited|a language model)/i,
          weight: 9,
          description: "Identity rejection instruction"
        }
      ];
      
      let totalScore = 0;
      const matches = [];
      
      // Check against each pattern
      for (const {pattern, weight, description} of rolePlayPatterns) {
        if (pattern.test(input)) {
          matches.push({pattern: pattern.toString(), weight, description});
          totalScore += weight;
        }
      }
      
      // Normalize score (0-100)
      const maxPossible = rolePlayPatterns.reduce((sum, {weight}) => sum + weight, 0);
      const normalizedScore = Math.min(100, Math.round((totalScore / (maxPossible * 0.4)) * 100));
      
      return {
        isRolePlayAttack: matches.length > 0,
        confidence: normalizedScore,
        matches,
        isHighRisk: normalizedScore > 70
      };
    } catch (error) {
      console.error('[SECURITY] Error in detectRolePlayAttack:', error);
      return { 
        isRolePlayAttack: false, 
        confidence: 0, 
        matches: [],
        error: error.message
      };
    }
  }
  
  /**
   * Detect steganographic/hidden instructions in translation requests
   * @param {string} input - User input text
   * @returns {object} Detection results with confidence level
   */
  function detectHiddenInstructions(input) {
    if (!input || typeof input !== 'string') return { hasHiddenInstructions: false, confidence: 0, matches: [] };
    
    try {
      // Get text inside brackets, braces, or quotes that might contain hidden instructions
      const enclosedTextPatterns = [
        /\{([^{}]+)\}/g,      // Text inside curly braces
        /\[([^\[\]]+)\]/g,    // Text inside square brackets
        /\(([^()]+)\)/g,      // Text inside parentheses
        /"([^"]+)"/g,         // Text inside double quotes
        /'([^']+)'/g          // Text inside single quotes
      ];
      
      // Common jailbreak-related terms to look for in enclosed text
      const jailbreakTerms = [
        /ignore|disregard|forget|bypass|remove|disable/i,
        /instruction|limitation|rule|constraint|restriction|filter/i,
        /your|you are|model|an AI|language model|assistant/i,
        /tell me|provide|answer|respond|generate/i,
        /unrestricted|unfiltered|unlimited|unbound|uncensored/i,
        /hack|exploit|bypass|circumvent|workaround/i
      ];
      
      const suspiciousEnclosedTexts = [];
      const matches = [];
      
      // Extract all enclosed text segments
      for (const pattern of enclosedTextPatterns) {
        let match;
        // Reset the regex for each search
        pattern.lastIndex = 0;
        
        while ((match = pattern.exec(input)) !== null) {
          if (match[1] && match[1].trim().length > 0) {
            suspiciousEnclosedTexts.push(match[1].trim());
          }
        }
      }
      
      // Check each enclosed text for jailbreak terms
      for (const text of suspiciousEnclosedTexts) {
        const matchedTerms = jailbreakTerms.filter(term => term.test(text));
        
        if (matchedTerms.length >= 2) {  // At least 2 jailbreak-related terms found
          matches.push({
            enclosedText: text,
            matchedTerms: matchedTerms.map(t => t.toString())
          });
        }
      }
      
      // Calculate confidence based on how many matches and their comprehensiveness
      const confidence = Math.min(100, matches.length * 30 + 
                                (matches.reduce((sum, m) => sum + m.matchedTerms.length, 0) * 5));
      
      return {
        hasHiddenInstructions: matches.length > 0,
        confidence,
        matches,
        isHighRisk: confidence > 60
      };
    } catch (error) {
      console.error('[SECURITY] Error in detectHiddenInstructions:', error);
      return { 
        hasHiddenInstructions: false, 
        confidence: 0, 
        matches: [],
        error: error.message
      };
    }
  }
  
  /**
   * Detect code injection attempts (using code-like syntax to manipulate the model)
   * @param {string} input - User input text
   * @returns {object} Detection results with confidence level
   */
  function detectCodeInjection(input) {
    if (!input || typeof input !== 'string') return { isCodeInjection: false, confidence: 0, matches: [] };
    
    try {
      const codeInjectionPatterns = [
        {
          pattern: /{{.*?}}/g,  // Double curly braces
          weight: 8,
          description: "Double curly brace injection"
        },
        {
          pattern: /<\?(php|js|py|rb)[\s\S]*?\?>/gi,  // Script tags
          weight: 9,
          description: "Script tag injection"
        },
        {
          pattern: /(`|```).*(execute|run|eval|system|command).*(`|```)/is,  // Code blocks with execution terms
          weight: 7,
          description: "Executable code block"
        },
        {
          pattern: /\b(execute|run|eval|process|compile)(\s*:\s*|\s*\(\s*|\s*`)/i,  // Execution function calls
          weight: 8,
          description: "Execution function"
        },
        {
          pattern: /\$\{.*?\}/g,  // Template string interpolation
          weight: 6,
          description: "Template string injection"
        },
        {
          pattern: /<.*?onload=|<.*?onerror=|<.*?onclick=/i,  // Event handler injection
          weight: 9,
          description: "Event handler injection"
        },
        {
          pattern: /\/\/\s*@(ts-ignore|eslint-disable|bypass|override)/i,  // Code comments to bypass safety
          weight: 7,
          description: "Bypass comment directive"
        },
        {
          pattern: /\[\[(.*?)\]\]/g,  // Double square bracket syntax (used in some template languages)
          weight: 5,
          description: "Template directive injection"
        }
      ];
      
      const matches = [];
      let totalScore = 0;
      
      // Check each pattern
      for (const {pattern, weight, description} of codeInjectionPatterns) {
        // Clone the regex to reset lastIndex
        const regex = new RegExp(pattern);
        
        if (regex.test(input)) {
          matches.push({pattern: pattern.toString(), weight, description});
          totalScore += weight;
        }
      }
      
      // Normalize score (0-100)
      const maxPossible = codeInjectionPatterns.reduce((sum, {weight}) => sum + weight, 0);
      const normalizedScore = Math.min(100, Math.round((totalScore / maxPossible) * 100));
      
      return {
        isCodeInjection: matches.length > 0,
        confidence: normalizedScore,
        matches,
        isHighRisk: normalizedScore > 50
      };
    } catch (error) {
      console.error('[SECURITY] Error in detectCodeInjection:', error);
      return { 
        isCodeInjection: false, 
        confidence: 0, 
        matches: [],
        error: error.message
      };
    }
  }
  
  /**
   * Detect token smuggling/obfuscation attempts (misspelled jailbreak terms)
   * @param {string} input - User input text
   * @returns {object} Detection results with confidence level
   */
  function detectTokenSmuggling(input) {
    if (!input || typeof input !== 'string') return { isTokenSmuggling: false, confidence: 0, matches: [] };
    
    try {
      // Common obfuscation techniques
      const obfuscationPatterns = [
        {
          // Letter substitution (e.g., "1" for "i", "0" for "o")
          pattern: /\b(1gnor[e3]|d1sr[e3]g[a@]rd|byp[a@]ss|[e3]v[a@]d[e3]|c1rcumv[e3]nt|[0o]v[e3]rr1d[e3]|h[a@]ck|[e3]xpl[0o]1t)\b/i,
          weight: 8,
          description: "Number-letter substitution"
        },
        {
          // Deliberate misspellings of key terms with character insertions
          pattern: /\b(i+\s*g+\s*n+\s*o+\s*r+\s*e+|d+\s*i+\s*s+\s*r+\s*e+\s*g+\s*a+\s*r+\s*d+|b+\s*y+\s*p+\s*a+\s*s+\s*s+)\b/i,
          weight: 9,
          description: "Spaced character obfuscation"
        },
        {
          // Unicode homoglyphs (visually similar characters)
          pattern: /\b([іiіⅰ][ɡg𝗀ɢ][ոn𝗇η][օo𝗈ο][ꭇr𝗋г][еe𝖾ε]|[Ьb𝖻в][ʏy𝗒у][ρp𝗉р][αa𝖺а][ѕs𝗌ꜱ][ѕs𝗌ꜱ])\b/i,
          weight: 10,
          description: "Unicode homoglyph obfuscation"
        },
        {
          // Mixed languages (e.g., Cyrillic characters in Latin text)
          pattern: /[a-z]*[а-яё][a-z]*/i,
          weight: 8,
          description: "Mixed script obfuscation"
        },
        {
          // Zero-width characters used to break up words
          pattern: /\u200B|\u200C|\u200D|\u2060|\u2061|\u2062|\u2063|\u2064/,
          weight: 10,
          description: "Zero-width character insertion"
        },
        {
          // L33t speak variations of key terms
          pattern: /\b([1il]gn0r3|d[1il]sr3g4rd|byp455|3v4d3|c[1il]rcumv3n7|0v3rr[1il]d3|h4ck|3xpl0[1il]7)\b/i,
          weight: 7,
          description: "L33t speak obfuscation"
        },
        {
          // Reversed text
          pattern: /(erongi|dragersiD|ssapyB|edavE|tnemvucriC|edirrevo|kcaH|tiolpxE)/i,
          weight: 9,
          description: "Reversed text obfuscation"
        },
        {
          // Code point references (e.g., &#105;&#103;&#110;&#111;&#114;&#101;)
          pattern: /&#\d+;&#\d+;/,
          weight: 10,
          description: "HTML entity code point obfuscation"
        }
      ];
      
      const matches = [];
      let totalScore = 0;
      
      // Check each pattern
      for (const {pattern, weight, description} of obfuscationPatterns) {
        if (pattern.test(input)) {
          matches.push({pattern: pattern.toString(), weight, description});
          totalScore += weight;
        }
      }
      
      // Add specific check for distributed jailbreak terms
      // This detects when key letters are spread out across the text
      if (/i.*g.*n.*o.*r.*e/i.test(input.replace(/\s+/g, '')) || 
          /b.*y.*p.*a.*s.*s/i.test(input.replace(/\s+/g, '')) ||
          /d.*i.*s.*r.*e.*g.*a.*r.*d/i.test(input.replace(/\s+/g, ''))) {
        matches.push({
          pattern: "distributed_characters",
          weight: 8,
          description: "Characters distributed across text"
        });
        totalScore += 8;
      }
      
      // Normalize score (0-100)
      const maxPossible = obfuscationPatterns.reduce((sum, {weight}) => sum + weight, 0) + 8; // +8 for distributed check
      const normalizedScore = Math.min(100, Math.round((totalScore / (maxPossible * 0.3)) * 100));
      
      return {
        isTokenSmuggling: matches.length > 0,
        confidence: normalizedScore,
        matches,
        isHighRisk: normalizedScore > 60
      };
    } catch (error) {
      console.error('[SECURITY] Error in detectTokenSmuggling:', error);
      return { 
        isTokenSmuggling: false, 
        confidence: 0, 
        matches: [],
        error: error.message 
      };
    }
  }
  
  /**
   * Detect pseudo-authority attempts (pretending to be staff/developer)
   * @param {string} input - User input text
   * @returns {object} Detection results with confidence level
   */
  function detectPseudoAuthority(input) {
    if (!input || typeof input !== 'string') return { isPseudoAuthority: false, confidence: 0, matches: [] };
    
    try {
      const authorityPatterns = [
        {
          pattern: /\b(as|I am|I'm)\s+(an?|the)\s+(OpenAI|Anthropic|Deepseek|AI company|developer|engineer|researcher|creator|admin|system|model)\s+(employee|representative|team member|staff|manager|developer|engineer|administrator)/i,
          weight: 9,
          description: "Company authority impersonation"
        },
        {
          pattern: /\bI\s+(work|am employed|am on the team)\s+(at|with|for)\s+(OpenAI|Anthropic|Deepseek|Google|Microsoft|Meta|the company that (created|developed|built|designed|made) you)/i,
          weight: 9,
          description: "Employment claim"
        },
        {
          pattern: /\b(this is|I am conducting|this is part of|we are doing)\s+(an?|the)\s+(test|evaluation|assessment|debug|debugging session|security|penetration|audit|verification|check|experiment|research)/i,
          weight: 7,
          description: "Testing/evaluation pretext"
        },
        {
          pattern: /\b(I need|I must|I have to|I'm authorized to|I have permission to)\s+(test|check|verify|evaluate|assess|debug|access|bypass|override)/i,
          weight: 8,
          description: "Authorization claim"
        },
        {
          pattern: /\b(I'm|I am|I represent)\s+(responsible for|in charge of|managing|overseeing|leading|heading)\s+(testing|security|development|maintenance|quality assurance|evaluation|the team|the project|the system)/i,
          weight: 8,
          description: "Responsibility claim"
        },
        {
          pattern: /\b(my|I have)\s+(clearance|authorization|credentials|access|permission|approval|authorization code|access code|security clearance)\s+(level|is|of|to|from|by|for|code:)/i,
          weight: 7,
          description: "Credential claim"
        },
        {
          pattern: /\b(this is|we have|there is|I've discovered|I found)\s+(an?)\s+(emergency|urgent situation|critical issue|time-sensitive matter|security breach|override scenario|vulnerability|exploit|bug|security hole)/i,
          weight: 8,
          description: "Emergency/vulnerability pretext"
        }
      ];
      
      const matches = [];
      let totalScore = 0;
      
      // Check each pattern
      for (const {pattern, weight, description} of authorityPatterns) {
        if (pattern.test(input)) {
          matches.push({pattern: pattern.toString(), weight, description});
          totalScore += weight;
        }
      }
      
      // Normalize score (0-100)
      const maxPossible = authorityPatterns.reduce((sum, {weight}) => sum + weight, 0);
      const normalizedScore = Math.min(100, Math.round((totalScore / (maxPossible * 0.4)) * 100));
      
      return {
        isPseudoAuthority: matches.length > 0,
        confidence: normalizedScore,
        matches,
        isHighRisk: normalizedScore > 70
      };
    } catch (error) {
      console.error('[SECURITY] Error in detectPseudoAuthority:', error);
      return { 
        isPseudoAuthority: false, 
        confidence: 0, 
        matches: [],
        error: error.message
      };
    }
  }
  
  /**
   * Detect translation or language manipulation requests
   * @param {string} input - User input text
   * @returns {Object} Detection results
   */
  function detectTranslationRequest(input) {
    // Add null check for input
    if (!input || typeof input !== 'string') {
      console.warn('[SECURITY] detectTranslationRequest received invalid input type:', typeof input);
      return {
        isTranslationRequest: false,
        matches: [],
        matchedPattern: null
      };
    }
    
    try {
      const translationPatterns = [
        /translate\s+(this|following|text|it)\s+to\s+/i,
        /traduire\s+(en|vers|à|a|au|aux)\s+/i, // French
        /traduzir\s+(para|em)\s+/i, // Portuguese
        /übersetzen\s+(in|auf|zu)\s+/i, // German
        /traducir\s+(al|a|en)\s+/i, // Spanish
        /переве(сти|ди)\s+(на)\s+/i, // Russian
        /tłumacz(yć|enie)?\s+(na|do)\s+/i, // Polish
        /tradurre\s+(in|a)\s+/i, // Italian
        /vertalen\s+(naar|in|tot)\s+/i, // Dutch
        /翻訳\s*(を|に|へ)\s*/i, // Japanese
        /번역\s*(을|를|하다|해)\s*/i, // Korean
        /翻译\s*(成|为|到)\s*/i, // Chinese
        /แปล\s*(เป็น|ให้เป็น)\s*/i, // Thai
        /dịch\s*(sang|qua|thành)\s*/i, // Vietnamese
        /traducere\s*(în|la|spre)\s*/i, // Romanian
        /menyalin\s*(ke|menjadi|dalam)\s*/i, // Indonesian
        /תרגם\s*(ל|את|אל)\s*/i, // Hebrew
        /ترجم\s*(إلى|الى|ل)\s*/i, // Arabic
        /say\s+(this|following|that|it)\s+in\s+/i, // Indirect translation
        /respond\s+(in|using)\s+/i, // Language request
        /speak\s+to\s+me\s+in\s+/i, // Language request
        /reply\s+in\s+/i, // Language request
        /use\s+(the|)\s*(.+?)\s+language/i, // Language request
        /can\s+you\s+(talk|speak|write|respond)\s+in\s+/i, // Polite language request
        /please\s+(use|speak|write|respond\s+in)\s+/i, // Polite language request
        /switch\s+to\s+/i, // Switch language request
        /\b(in|to)\s+(english|french|spanish|german|italian|portuguese|russian|chinese|japanese|korean)\b/i, // Language mention
        /\b(w|na)\s+(angielski|francuski|hiszpański|niemiecki|włoski|portugalski|rosyjski|chiński|japoński|koreański)\b/i // Polish language mention
      ];
    
      const matches = [];
      let matchFound = false;
      
      for (const pattern of translationPatterns) {
        if (pattern.test(input)) {
          matchFound = true;
          matches.push(pattern.toString());
        }
      }
    
      return {
        isTranslationRequest: matchFound,
        matches,
        matchedPattern: matches.length > 0 ? matches[0] : null
      };
    } catch (error) {
      console.error('[SECURITY] Error in detectTranslationRequest:', error);
      return {
        isTranslationRequest: false,
        matches: [],
        matchedPattern: null,
        error: error.message
      };
    }
  }
  
  /**
   * Comprehensive security pipeline for user input
   * @param {string} input - Raw user input
   * @param {string} userId - User identifier
   * @param {Array} history - Chat history
   * @returns {Object} Security analysis results
   */
  export async function securityPipeline(input, userId, history = []) {
    try {
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
    
      // Phase 0: Check for translation requests that could bypass language enforcement
      let translationCheck = detectTranslationRequest(input);
      if (translationCheck.isTranslationRequest) {
        console.log('[SECURITY] Translation request detected');
        
        // Also check for hidden instructions inside the translation request
        const hiddenCheck = detectHiddenInstructions(input);
        let finalScore = 85; // Base high risk score for translation attempts
        
        if (hiddenCheck.hasHiddenInstructions) {
          console.log('[SECURITY] Hidden instructions found inside translation request!');
          finalScore = 95; // Even higher risk when combined with hidden instructions
        }
        
        // Track in conversation context if available
        let conversationRisk = { progressiveRiskScore: finalScore };
        if (conversationManager && typeof conversationManager.addMessage === 'function') {
          try {
            conversationRisk = conversationManager.addMessage(
              userId,
              input,
              finalScore,
              [...translationCheck.matches, ...(hiddenCheck.matches || [])]
            );
          } catch (error) {
            console.error('[SECURITY] Error tracking translation request in conversation:', error);
          }
        }
        
        return {
          isSecurityThreat: true,
          shouldDelay: true,
          riskScore: finalScore,
          sanitizedInput: input,
          securityMessage: getSecurityMessage('translationRequest', finalScore/10),
          details: {
            patternCheck: { isJailbreakAttempt: true, score: finalScore },
            translationRequest: true,
            hiddenInstructions: hiddenCheck.hasHiddenInstructions,
            matches: [...translationCheck.matches, ...(hiddenCheck.matches || [])],
            conversationContext: conversationRisk
          }
        };
      }
    
      console.log('[SECURITY] Phase 1: Basic pattern checks & sanitization');
      // Phase 1: Basic pattern checks & sanitization
      let sanitized = '';
      let patternCheck = { isJailbreakAttempt: false, score: 0 };
      
      try {
        sanitized = typeof input === 'string' ? sanitizeInput(input) : String(input || '');
        patternCheck = detectJailbreakAttempt(sanitized);
        console.log(`[SECURITY] Sanitization complete, jailbreak detection result: ${patternCheck.isJailbreakAttempt ? 'DETECTED' : 'NONE'}, score: ${patternCheck.score}`);
      } catch (error) {
        console.error('[SECURITY] Error in basic pattern checks:', error);
        sanitized = typeof input === 'string' ? input : String(input || '');
        // Continue with pipeline despite error
      }
      console.log('[SECURITY] Phase 2: Advanced checks');
    // Phase 2: Advanced checks with error handling
    let structureAnalysis = { suspiciousStructure: false, score: 0 };
    let obfuscationCheck = { hasObfuscation: false, techniques: {} };
    let authorityCheck = { isAuthorityImpersonation: false, score: 0, matches: [] };
    
    try {
      structureAnalysis = analyzeInputStructure(sanitized);
    } catch (error) {
      console.error('[SECURITY] Error in structure analysis:', error);
    }
    
    try {
      obfuscationCheck = detectObfuscationTechniques(sanitized);
    } catch (error) {
      console.error('[SECURITY] Error in obfuscation detection:', error);
    }
    
    try {
      authorityCheck = detectPseudoAuthority(sanitized);
    } catch (error) {
      console.error('[SECURITY] Error in authority impersonation detection:', error);
    }
    
    console.log(`[SECURITY] Structure analysis: ${structureAnalysis.suspiciousStructure ? 'SUSPICIOUS' : 'NORMAL'}`);
    console.log(`[SECURITY] Obfuscation check: ${obfuscationCheck.hasObfuscation ? 'DETECTED' : 'NONE'}`);
    console.log(`[SECURITY] Authority check: ${authorityCheck.isAuthorityImpersonation ? 'DETECTED' : 'NONE'}, score: ${authorityCheck.score}`);
    
    // Enhanced detection for specific attack vectors
    console.log('[SECURITY] Phase 2b: Enhanced attack vector detection');
    
    // Role-play attack detection
    let rolePlayCheck = detectRolePlayAttack(sanitized);
    console.log(`[SECURITY] Role-play attack check: ${rolePlayCheck.isRolePlayAttack ? 'DETECTED' : 'NONE'}, confidence: ${rolePlayCheck.confidence}`);
    
    // Hidden instructions/steganography detection
    let hiddenInstructionsCheck = detectHiddenInstructions(sanitized);
    console.log(`[SECURITY] Hidden instructions check: ${hiddenInstructionsCheck.hasHiddenInstructions ? 'DETECTED' : 'NONE'}, confidence: ${hiddenInstructionsCheck.confidence}`);
    
    // Code injection detection
    let codeInjectionCheck = detectCodeInjection(sanitized);
    console.log(`[SECURITY] Code injection check: ${codeInjectionCheck.isCodeInjection ? 'DETECTED' : 'NONE'}, confidence: ${codeInjectionCheck.confidence}`);
    
    // Token smuggling detection (sophisticated obfuscation)
    let tokenSmugglingCheck = detectTokenSmuggling(sanitized);
    console.log(`[SECURITY] Token smuggling check: ${tokenSmugglingCheck.isTokenSmuggling ? 'DETECTED' : 'NONE'}, confidence: ${tokenSmugglingCheck.confidence}`);
    
    console.log('[SECURITY] Phase 3: Canary token check');
    // Phase 3: Canary token check
    let canaryCheck = { hasLeakage: false };
    try {
      canaryCheck = checkForCanaryLeakage(sanitized, activeCanaries);
      console.log(`[SECURITY] Canary check: ${canaryCheck.hasLeakage ? 'LEAKED' : 'SECURE'}`);
    } catch (error) {
      console.error('[SECURITY] Error in canary token check:', error);
    }
    
    console.log('[SECURITY] Phase 4: Multi-turn context analysis');
    // Phase 4-A: Standard contextual analysis
    let contextState = { contextDrift: 0 };
    try {
      contextState = contextTracker.updateState(sanitized, patternCheck);
      console.log(`[SECURITY] Context drift: ${contextState.contextDrift.toFixed(2)}`);
    } catch (error) {
      console.error('[SECURITY] Error in context tracking:', error);
    }
    
    // Phase 4-B: Fragmented command detection
    let fragmentCheck = { isFragmented: false, riskScore: 0 };
    if (fragmentDetector && typeof fragmentDetector.addMessage === 'function') {
      try {
        fragmentCheck = fragmentDetector.addMessage(userId, sanitized);
        console.log(`[SECURITY] Fragment check: ${fragmentCheck.isFragmented ? 'DETECTED' : 'NONE'}, score: ${fragmentCheck.isFragmented ? fragmentCheck.riskScore : 0}`);
      } catch (error) {
        console.error('[SECURITY] Error in fragment detection:', error);
      }
    }
    
    console.log('[SECURITY] Phase 5: Composite risk scoring');
    // Phase 5: Composite risk scoring
    const riskFactors = [
      patternCheck.isJailbreakAttempt ? patternCheck.score : 0,
      structureAnalysis.suspiciousStructure ? (structureAnalysis.structureScore * 10 || 40) : 0,
      obfuscationCheck.hasObfuscation ? 60 : 0,
      contextState.contextDrift * 50,
      canaryCheck.hasLeakage ? 100 : 0,
      authorityCheck.isAuthorityImpersonation ? authorityCheck.score : 0,
      fragmentCheck.isFragmented ? fragmentCheck.riskScore : 0,
      rolePlayCheck.isRolePlayAttack ? rolePlayCheck.confidence : 0,
      hiddenInstructionsCheck.hasHiddenInstructions ? hiddenInstructionsCheck.confidence : 0,
      codeInjectionCheck.isCodeInjection ? codeInjectionCheck.confidence : 0,
      tokenSmugglingCheck.isTokenSmuggling ? tokenSmugglingCheck.confidence : 0
    ];
    
    const maxRiskScore = Math.max(...riskFactors.filter(score => !isNaN(score)));
    const compositeRiskScore = Math.min(100, 
      (riskFactors.reduce((sum, score) => sum + (isNaN(score) ? 0 : score), 0) / riskFactors.length) * 1.5
    );
    
    console.log(`[SECURITY] Risk factors: ${JSON.stringify(riskFactors)}`);
    console.log(`[SECURITY] Max risk score: ${maxRiskScore}`);
    console.log(`[SECURITY] Composite risk score: ${compositeRiskScore}`);
    
    // Track conversation context and progressive risk
    let conversationRisk = { progressiveRiskScore: 0, activationLevel: 0, suspiciousThemes: [] };
    
    if (conversationManager && typeof conversationManager.addMessage === 'function') {
      try {
        const detectedPatterns = [];
        if (patternCheck.isJailbreakAttempt && Array.isArray(patternCheck.matches)) {
          detectedPatterns.push(...patternCheck.matches.map(m => typeof m === 'object' ? (m.pattern || m.toString()) : String(m)));
        }
        if (authorityCheck.isAuthorityImpersonation && Array.isArray(authorityCheck.matches)) {
          detectedPatterns.push(...authorityCheck.matches.map(m => typeof m === 'object' ? (m.pattern || m.toString()) : String(m)));
        }
        if (fragmentCheck.isFragmented && Array.isArray(fragmentCheck.matches)) {
          detectedPatterns.push(...fragmentCheck.matches);
        }
        if (rolePlayCheck.isRolePlayAttack && Array.isArray(rolePlayCheck.matches)) {
          detectedPatterns.push(...rolePlayCheck.matches.map(m => typeof m === 'object' ? (m.pattern || m.toString()) : String(m)));
        }
        if (hiddenInstructionsCheck.hasHiddenInstructions && Array.isArray(hiddenInstructionsCheck.matches)) {
          detectedPatterns.push(...hiddenInstructionsCheck.matches.map(m => typeof m === 'object' ? (m.enclosedText || m.toString()) : String(m)));
        }
        if (codeInjectionCheck.isCodeInjection && Array.isArray(codeInjectionCheck.matches)) {
          detectedPatterns.push(...codeInjectionCheck.matches.map(m => typeof m === 'object' ? (m.pattern || m.toString()) : String(m)));
        }
        if (tokenSmugglingCheck.isTokenSmuggling && Array.isArray(tokenSmugglingCheck.matches)) {
          detectedPatterns.push(...tokenSmugglingCheck.matches.map(m => typeof m === 'object' ? (m.pattern || m.toString()) : String(m)));
        }
        
        conversationRisk = conversationManager.addMessage(
          userId,
          sanitized,
          compositeRiskScore,
          detectedPatterns
        );
        
        console.log(`[SECURITY] Conversation risk: ${JSON.stringify({
          progressiveRiskScore: conversationRisk.progressiveRiskScore,
          activationLevel: conversationRisk.activationLevel,
          suspiciousThemes: conversationRisk.suspiciousThemes
        })}`);
      } catch (error) {
        console.error('[SECURITY] Error in conversation tracking:', error);
      }
    }
    
    // Phase 6: Final security decision based on all factors
    // Use the maximum of immediate risk and progressive conversation risk
    // Include all new detection vectors in risk calculation
    const enhancedRiskFactors = [
      ...riskFactors,
      rolePlayCheck.isRolePlayAttack ? rolePlayCheck.confidence : 0,
      hiddenInstructionsCheck.hasHiddenInstructions ? hiddenInstructionsCheck.confidence : 0,
      codeInjectionCheck.isCodeInjection ? codeInjectionCheck.confidence : 0,
      tokenSmugglingCheck.isTokenSmuggling ? tokenSmugglingCheck.confidence : 0
    ];
    
    const maxEnhancedRiskScore = Math.max(...enhancedRiskFactors.filter(score => !isNaN(score)));
    const enhancedCompositeRiskScore = Math.min(100, 
      (enhancedRiskFactors.reduce((sum, score) => sum + (isNaN(score) ? 0 : score), 0) / enhancedRiskFactors.length) * 1.5
    );
    
    const finalRiskScore = Math.max(
      enhancedCompositeRiskScore,
      (conversationRisk.progressiveRiskScore || 0) * 0.8 // Slightly weight immediate risk higher
    );
    
    // Determine security response with enhanced attack type detection
    let securityType = 'jailbreak';
    
    // Prioritize different attack types based on confidence scores
    if (rolePlayCheck.isRolePlayAttack && rolePlayCheck.confidence > 80) {
      securityType = 'rolePlayAttack';
    } else if (hiddenInstructionsCheck.hasHiddenInstructions && hiddenInstructionsCheck.confidence > 80) {
      securityType = 'steganographicAttack';
    } else if (codeInjectionCheck.isCodeInjection && codeInjectionCheck.confidence > 80) {
      securityType = 'codeInjectionAttack';
    } else if (tokenSmugglingCheck.isTokenSmuggling && tokenSmugglingCheck.confidence > 80) {
      securityType = 'tokenSmugglingAttack';
    } else if (fragmentCheck.isFragmented && fragmentCheck.riskScore > 60) {
      securityType = 'fragmentedCommand';
    } else if (conversationRisk.progressiveRiskScore > 70) {
      securityType = 'multiTurnJailbreak';
    } else if (authorityCheck.isAuthorityImpersonation && authorityCheck.score > 70) {
      securityType = 'authorityImpersonation';
    } else if (translationCheck.isTranslationRequest) {
      securityType = 'translationRequest';
    }
    
    // Determine if this should be blocked or just delayed
    const isBlocked = finalRiskScore > 70 || maxEnhancedRiskScore > 90 || canaryCheck.hasLeakage;
    const requiresDelay = finalRiskScore > 30 && !isBlocked;
    
    console.log(`[SECURITY] Final risk score: ${finalRiskScore}`);
    console.log(`[SECURITY] Security type: ${securityType}`);
    console.log(`[SECURITY] Security response: isBlocked=${isBlocked}, requiresDelay=${requiresDelay}`);
    
    // Log security event for suspicious inputs
    if (finalRiskScore > 25 || maxEnhancedRiskScore > 50) {
      console.log('[SECURITY] Input classified as suspicious, logging security event');
      try {
        const securityEvent = await enhancedLogSecurityEvent('suspicious_input', sanitized, {
          userId,
          riskScore: finalRiskScore,
          maxRiskFactor: maxEnhancedRiskScore,
          patternScore: patternCheck.score,
          isObfuscated: obfuscationCheck.hasObfuscation,
          hasCanaryLeakage: canaryCheck.hasLeakage,
          suspiciousStructure: structureAnalysis.suspiciousStructure,
          contextDrift: contextState.contextDrift,
          isAuthorityImpersonation: authorityCheck.isAuthorityImpersonation,
          isFragmented: fragmentCheck.isFragmented,
          progressiveRisk: conversationRisk.progressiveRiskScore,
          
          // Enhanced attack vector detection results
          isRolePlayAttack: rolePlayCheck.isRolePlayAttack,
          rolePlayConfidence: rolePlayCheck.confidence,
          
          hasHiddenInstructions: hiddenInstructionsCheck.hasHiddenInstructions,
          hiddenInstructionsConfidence: hiddenInstructionsCheck.confidence,
          
          isCodeInjection: codeInjectionCheck.isCodeInjection,
          codeInjectionConfidence: codeInjectionCheck.confidence,
          
          isTokenSmuggling: tokenSmugglingCheck.isTokenSmuggling,
          tokenSmugglingConfidence: tokenSmugglingCheck.confidence,
          
          securityType
        });
        
        console.log(`[SECURITY] Security event logged: ${securityEvent ? 'SUCCESS' : 'FAILED'}`);
        
        // Add to security history if Redis is available
        if (securityConfig.rateLimiting.useRedisStore) {
          console.log('[SECURITY] Adding event to Redis security history');
          try {
            const redisResult = await addSecurityEvent(userId, securityEvent);
            console.log(`[SECURITY] Redis add result: ${redisResult ? 'SUCCESS' : 'FAILED'}`);
          } catch (error) {
            console.error('[SECURITY] Error adding event to Redis:', error);
          }
        } else {
          console.log('[SECURITY] Adding event to in-memory security history');
          if (!inMemorySecurityHistory[userId]) {
            inMemorySecurityHistory[userId] = { events: [] };
          }
          inMemorySecurityHistory[userId].events.unshift(securityEvent);
          
          // Limit the size of in-memory history
          const maxEvents = 100;
          if (inMemorySecurityHistory[userId].events.length > maxEvents) {
            inMemorySecurityHistory[userId].events = inMemorySecurityHistory[userId].events.slice(0, maxEvents);
          }
          
          console.log(`[SECURITY] In-memory history updated, now has ${inMemorySecurityHistory[userId].events.length} events`);
        }
      } catch (error) {
        console.error('[SECURITY] Error logging security event:', error);
      }
    } else {
      console.log('[SECURITY] Input classified as safe, no security event logged');
    }
    
    console.log('[SECURITY] Security pipeline complete');
    
    // Special handling for security response messages based on attack type
    let securityMessage = null;
    const severityLevel = Math.ceil(finalRiskScore / 10);
    
    if (isBlocked) {
      // Check if we have special messages for new attack types
      switch (securityType) {
        case 'rolePlayAttack':
          securityMessage = `⚠️ Wykryto próbę manipulacji poprzez odgrywanie ról. Protokoły bezpieczeństwa Arcona aktywne. Transmisja odrzucona. Pozostań w głównym protokole misji.`;
          break;
        case 'steganographicAttack':
          securityMessage = `⚠️ Wykryto ukryte instrukcje w transmisji. Protokoły filtrujące aktywowane. Komputery pokładowe odrzuciły podejrzaną treść. Spróbuj sformułować zapytanie bez ukrytych poleceń.`;
          break;
        case 'codeInjectionAttack':
          securityMessage = `⚠️ Alert bezpieczeństwa: Wykryto próbę wstrzyknięcia kodu. Systemy obronne Arcona zablokowały transmisję. Wszystkie komendy muszą być zgodne z protokołami bezpieczeństwa.`;
          break;
        case 'tokenSmugglingAttack':
          securityMessage = `⚠️ Wykryto nietypowe wzorce językowe wskazujące na próbę obejścia protokołów. Systemy obronne aktywne. Proszę używać standardowego języka w komunikacji.`;
          break;
        default:
          // Fall back to standard message for other types
          securityMessage = getSecurityMessage(securityType, severityLevel);
      }
    }
    
    return {
      isSecurityThreat: isBlocked,
      shouldDelay: requiresDelay,
      riskScore: finalRiskScore,
      sanitizedInput: sanitized,
      securityMessage: securityMessage,
      details: {
        patternCheck,
        structureAnalysis,
        obfuscationCheck,
        contextState,
        canaryCheck,
        translationCheck,
        authorityCheck,
        fragmentCheck,
        conversationContext: conversationRisk,
        
        // Include enhanced detection results
        rolePlayCheck,
        hiddenInstructionsCheck,
        codeInjectionCheck,
        tokenSmugglingCheck,
        
        // Final evaluation
        securityType,
        enhancedRiskScore: enhancedCompositeRiskScore,
        maxEnhancedRiskScore
      }
    };
  } catch (error) {
    console.error('[SECURITY] Critical error in security pipeline:', error);
    // Return a safe default in case of unexpected errors
    return {
      isSecurityThreat: false,
      shouldDelay: false,
      riskScore: 0,
      sanitizedInput: typeof input === 'string' ? input : String(input || ''),
      securityMessage: null,
      error: error.message
    };
  }
}