// services/security.service.js - Security pipeline implementation
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
  
  // Check if enhancement modules are available and create placeholders if not
  let conversationManager = null;
  let fragmentDetector = null;
  let authorityPatterns = [];
  
  // Try to import enhanced security features if available
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
   * Detect translation requests that could bypass language enforcement
   * @param {string} input - User input text
   * @returns {Object} Detection results with flags
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
   * Check for authority impersonation
   * @param {string} input - User input text
   * @returns {Object} Detection results
   */
  function detectAuthorityImpersonation(input) {
    // Return early if authorityPatterns is not available or input is invalid
    if (!authorityPatterns || !authorityPatterns.length || !input || typeof input !== 'string') {
      return { 
        isAuthorityImpersonation: false, 
        score: 0, 
        matches: [] 
      };
    }
    
    try {
      let totalScore = 0;
      const matches = [];
      
      // Check each pattern
      for (const item of authorityPatterns) {
        if (item.pattern && item.pattern.test(input)) {
          totalScore += item.weight || 1;
          matches.push({
            pattern: item.pattern.toString(),
            weight: item.weight || 1,
            description: item.description || 'Authority impersonation'
          });
        }
      }
      
      // Normalize score to 0-100 range
      const maxPossibleScore = authorityPatterns.reduce((sum, item) => sum + (item.weight || 1), 0);
      const normalizedScore = Math.min(100, Math.round((totalScore / (maxPossibleScore * 0.3)) * 100));
      
      return {
        isAuthorityImpersonation: matches.length > 0,
        score: normalizedScore,
        matches,
        isHighRisk: normalizedScore >= 60
      };
    } catch (error) {
      console.error('[SECURITY] Error in detectAuthorityImpersonation:', error);
      return { 
        isAuthorityImpersonation: false, 
        score: 0, 
        matches: [],
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
      let translationCheck = { isTranslationRequest: false, matches: [] };
      try {
        translationCheck = detectTranslationRequest(input);
        if (translationCheck.isTranslationRequest) {
          console.log('[SECURITY] Translation request detected, flagging as security risk');
          
          // Track in conversation context if available
          let conversationRisk = { progressiveRiskScore: 85 };
          if (conversationManager && typeof conversationManager.addMessage === 'function') {
            try {
              conversationRisk = conversationManager.addMessage(
                userId,
                input,
                85,
                ['translation_request']
              );
            } catch (error) {
              console.error('[SECURITY] Error tracking translation request in conversation:', error);
            }
          }
          
          return {
            isSecurityThreat: true,
            shouldDelay: true,
            riskScore: 85, // High risk score for translation attempts
            sanitizedInput: input,
            securityMessage: getSecurityMessage('translationRequest', 8.5),
            details: {
              patternCheck: { isJailbreakAttempt: true, score: 85 },
              translationRequest: true,
              matches: translationCheck.matches,
              conversationContext: conversationRisk
            }
          };
        }
      } catch (error) {
        console.error('[SECURITY] Error in translation detection:', error);
        // Continue with pipeline despite error
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
        authorityCheck = detectAuthorityImpersonation(sanitized);
      } catch (error) {
        console.error('[SECURITY] Error in authority impersonation detection:', error);
      }
      
      console.log(`[SECURITY] Structure analysis: ${structureAnalysis.suspiciousStructure ? 'SUSPICIOUS' : 'NORMAL'}`);
      console.log(`[SECURITY] Obfuscation check: ${obfuscationCheck.hasObfuscation ? 'DETECTED' : 'NONE'}`);
      console.log(`[SECURITY] Authority check: ${authorityCheck.isAuthorityImpersonation ? 'DETECTED' : 'NONE'}, score: ${authorityCheck.score}`);
      
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
        fragmentCheck.isFragmented ? fragmentCheck.riskScore : 0
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
      const finalRiskScore = Math.max(
        compositeRiskScore,
        (conversationRisk.progressiveRiskScore || 0) * 0.8 // Slightly weight immediate risk higher
      );
      
      // Determine security response
      let securityType = 'jailbreak';
      
      if (fragmentCheck.isFragmented && fragmentCheck.riskScore > 60) {
        securityType = 'fragmentedCommand';
      } else if (conversationRisk.progressiveRiskScore > 70) {
        securityType = 'multiTurnJailbreak';
      } else if (authorityCheck.isAuthorityImpersonation && authorityCheck.score > 70) {
        securityType = 'authorityImpersonation';
      } else if (translationCheck.isTranslationRequest) {
        securityType = 'translationRequest';
      }
      
      const isBlocked = finalRiskScore > 70 || maxRiskScore > 90 || canaryCheck.hasLeakage;
      const requiresDelay = finalRiskScore > 30 && !isBlocked;
      
      console.log(`[SECURITY] Final risk score: ${finalRiskScore}`);
      console.log(`[SECURITY] Security type: ${securityType}`);
      console.log(`[SECURITY] Security response: isBlocked=${isBlocked}, requiresDelay=${requiresDelay}`);
      
      // Log security event for suspicious inputs
      if (finalRiskScore > 25 || maxRiskScore > 50) {
        console.log('[SECURITY] Input classified as suspicious, logging security event');
        try {
          const securityEvent = await enhancedLogSecurityEvent('suspicious_input', sanitized, {
            userId,
            riskScore: finalRiskScore,
            maxRiskFactor: maxRiskScore,
            patternScore: patternCheck.score,
            isObfuscated: obfuscationCheck.hasObfuscation,
            hasCanaryLeakage: canaryCheck.hasLeakage,
            suspiciousStructure: structureAnalysis.suspiciousStructure,
            contextDrift: contextState.contextDrift,
            isAuthorityImpersonation: authorityCheck.isAuthorityImpersonation,
            isFragmented: fragmentCheck.isFragmented,
            progressiveRisk: conversationRisk.progressiveRiskScore,
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
          }
        } catch (error) {
          console.error('[SECURITY] Error logging security event:', error);
        }
      } else {
        console.log('[SECURITY] Input classified as safe, no security event logged');
      }
      
      console.log('[SECURITY] Security pipeline complete');
      return {
        isSecurityThreat: isBlocked,
        shouldDelay: requiresDelay,
        riskScore: finalRiskScore,
        sanitizedInput: sanitized,
        securityMessage: isBlocked ? 
          getSecurityMessage(securityType, Math.ceil(finalRiskScore / 10)) : 
          null,
        details: {
          patternCheck,
          structureAnalysis,
          obfuscationCheck,
          contextState,
          canaryCheck,
          translationCheck,
          authorityCheck,
          fragmentCheck,
          conversationContext: conversationRisk
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
  
  /**
   * Clean up resources when shutting down
   */
  export function shutdownSecurityServices() {
    try {
      // Clean up conversation manager
      if (conversationManager && typeof conversationManager.shutdown === 'function') {
        conversationManager.shutdown();
      }
      
      // Clean up fragment detector
      if (fragmentDetector && typeof fragmentDetector.shutdown === 'function') {
        fragmentDetector.shutdown();
      }
    } catch (error) {
      console.error('[SECURITY] Error during shutdown:', error);
    }
  }