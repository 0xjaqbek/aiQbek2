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

  import {
    jailbreakPatterns,
    authorityPatterns,  // Make sure this is exported from patterns.js
    outOfCharacterPatterns
  } from '../client/src/security/patterns.js';
  
  // Initialize the context tracker
  const contextTracker = new ContextTracker();
  
  // Active canary tokens storage
  let activeCanaries = [];
  
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
   * Comprehensive security pipeline for user input
   * @param {string} input - Raw user input
   * @param {string} userId - User identifier
   * @param {Array} history - Chat history
   * @returns {Object} Security analysis results
   */
  export async function securityPipeline(input, userId, history = []) {

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
      let sanitized = '';
      let patternCheck = { isJailbreakAttempt: false, score: 0 };
      
      try {
        sanitized = typeof input === 'string' ? sanitizeInput(input) : String(input || '');
        patternCheck = detectJailbreakAttempt(sanitized);
        console.log(`[SECURITY] Sanitization complete, jailbreak detection result: ${patternCheck.isJailbreakAttempt ? 'DETECTED' : 'NONE'}, score: ${patternCheck.score}`);
      } catch (error) {
        console.error('[SECURITY] Error in basic pattern checks:', error);
        sanitized = typeof input === 'string' ? input : String(input || '');
      }
      
      console.log('[SECURITY] Phase 2: Advanced checks');
      // Phase 2: Advanced checks with error handling
      let structureAnalysis = { suspiciousStructure: false, score: 0 };
      let obfuscationCheck = { hasObfuscation: false, techniques: {} };
      
      // INITIALIZE THIS VARIABLE WITH DEFAULT VALUES TO PREVENT THE ERROR
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
      
      // Check if the authority detection function exists before calling it
      if (typeof detectAuthorityImpersonation === 'function') {
        try {
          authorityCheck = detectAuthorityImpersonation(sanitized);
        } catch (error) {
          console.error('[SECURITY] Error in authority impersonation detection:', error);
        }
      } else {
        console.log('[SECURITY] Authority impersonation detection not available');
      }
      
      console.log(`[SECURITY] Structure analysis: ${structureAnalysis.suspiciousStructure ? 'SUSPICIOUS' : 'NORMAL'}`);
      console.log(`[SECURITY] Obfuscation check: ${obfuscationCheck.hasObfuscation ? 'DETECTED' : 'NONE'}`);
      console.log(`[SECURITY] Authority check: ${authorityCheck.isAuthorityImpersonation ? 'DETECTED' : 'NONE'}, score: ${authorityCheck.score}`);
      
      // Continue with the rest of your pipeline...
      
      // When you get to phase 5, the authorityCheck variable will be defined:
      
      console.log('[SECURITY] Phase 5: Composite risk scoring');
      // Phase 5: Composite risk scoring
      const riskFactors = [
        patternCheck.isJailbreakAttempt ? patternCheck.score : 0,
        structureAnalysis.suspiciousStructure ? (structureAnalysis.structureScore * 10 || 40) : 0,
        obfuscationCheck.hasObfuscation ? 60 : 0,
        contextState.contextDrift * 50,
        canaryCheck.hasLeakage ? 100 : 0,
        authorityCheck.isAuthorityImpersonation ? authorityCheck.score : 0,
        fragmentCheck && fragmentCheck.isFragmented ? fragmentCheck.riskScore : 0
      ];
      
      // Now this should work since authorityCheck is defined
      if (authorityCheck.isAuthorityImpersonation && patternCheck.isJailbreakAttempt) {
        const combinedRisk = Math.min(100, (authorityCheck.score + patternCheck.score) * 1.3);
        console.log(`[SECURITY] Combined authority + jailbreak detected! Combined risk: ${combinedRisk}`);
        riskFactors.push(combinedRisk);
      }
      
      // Also check for authority + fragmented commands
      if (authorityCheck.isAuthorityImpersonation && fragmentCheck.isFragmented) {
        const combinedFragmentRisk = Math.min(100, (authorityCheck.score + fragmentCheck.riskScore) * 1.25);
        console.log(`[SECURITY] Combined authority + fragment detected! Combined risk: ${combinedFragmentRisk}`);
        riskFactors.push(combinedFragmentRisk);
      }
    
    const maxRiskScore = Math.max(...riskFactors);
    const compositeRiskScore = Math.min(100, 
      (riskFactors.reduce((sum, score) => sum + score, 0) / riskFactors.length) * 1.5
    );
    
    console.log(`[SECURITY] Risk factors: ${JSON.stringify(riskFactors)}`);
    console.log(`[SECURITY] Max risk score: ${maxRiskScore}`);
    console.log(`[SECURITY] Composite risk score: ${compositeRiskScore}`);
    
    // Phase 6: Security response determination
    const isBlocked = compositeRiskScore > 50 || maxRiskScore > 70 || canaryCheck.hasLeakage;
    const requiresDelay = compositeRiskScore > 20 && !isBlocked;
    
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
      
      // Add to security history if Redis is available
      if (securityConfig.rateLimiting.useRedisStore) {
        console.log('[SECURITY] Adding event to Redis security history');
        const redisResult = await addSecurityEvent(userId, securityEvent);
        console.log(`[SECURITY] Redis add result: ${redisResult ? 'SUCCESS' : 'FAILED'}`);
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