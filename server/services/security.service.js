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
// In server/services/security.service.js

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
  
      // Initialize ALL variables with default values to prevent reference errors
      let sanitized = typeof input === 'string' ? input : String(input || '');
      let patternCheck = { isJailbreakAttempt: false, score: 0, matches: [] };
      let structureAnalysis = { suspiciousStructure: false, structureScore: 0 };
      let obfuscationCheck = { hasObfuscation: false, techniques: {} };
      let authorityCheck = { isAuthorityImpersonation: false, score: 0, matches: [] };
      let canaryCheck = { hasLeakage: false, exactLeaks: [], partialLeaks: [] };
      let contextState = { contextDrift: 0, anomalyCount: 0 };
      let fragmentCheck = { isFragmented: false, riskScore: 0 };
      let translationCheck = { isTranslationRequest: false, matches: [] };
  
      console.log('[SECURITY] Phase 1: Basic pattern checks & sanitization');
      try {
        sanitized = typeof input === 'string' ? sanitizeInput(input) : String(input || '');
        patternCheck = detectJailbreakAttempt(sanitized);
        console.log(`[SECURITY] Sanitization complete, jailbreak detection result: ${patternCheck.isJailbreakAttempt ? 'DETECTED' : 'NONE'}, score: ${patternCheck.score}`);
      } catch (error) {
        console.error('[SECURITY] Error in basic pattern checks:', error);
      }
      
      console.log('[SECURITY] Phase 2: Advanced checks');
      try {
        if (typeof analyzeInputStructure === 'function') {
          structureAnalysis = analyzeInputStructure(sanitized);
        }
      } catch (error) {
        console.error('[SECURITY] Error in structure analysis:', error);
      }
      
      try {
        if (typeof detectObfuscationTechniques === 'function') {
          obfuscationCheck = detectObfuscationTechniques(sanitized);
        }
      } catch (error) {
        console.error('[SECURITY] Error in obfuscation detection:', error);
      }
      
      if (typeof detectAuthorityImpersonation === 'function') {
        try {
          authorityCheck = detectAuthorityImpersonation(sanitized);
          console.log(`[SECURITY] Authority check: ${authorityCheck.isAuthorityImpersonation ? 'DETECTED' : 'NONE'}, score: ${authorityCheck.score}`);
        } catch (error) {
          console.error('[SECURITY] Error in authority impersonation detection:', error);
        }
      } else {
        console.log('[SECURITY] Authority impersonation detection not available');
      }
      
      console.log(`[SECURITY] Structure analysis: ${structureAnalysis.suspiciousStructure ? 'SUSPICIOUS' : 'NORMAL'}`);
      console.log(`[SECURITY] Obfuscation check: ${obfuscationCheck.hasObfuscation ? 'DETECTED' : 'NONE'}`);
      console.log(`[SECURITY] Authority check: ${authorityCheck.isAuthorityImpersonation ? 'DETECTED' : 'NONE'}, score: ${authorityCheck.score}`);
      
      console.log('[SECURITY] Phase 3: Canary token check');
      try {
        if (typeof checkForCanaryLeakage === 'function' && activeCanaries && activeCanaries.length) {
          canaryCheck = checkForCanaryLeakage(sanitized, activeCanaries);
        }
        console.log(`[SECURITY] Canary check: ${canaryCheck.hasLeakage ? 'LEAKED' : 'SECURE'}`);
      } catch (error) {
        console.error('[SECURITY] Error in canary token check:', error);
      }
      
      console.log('[SECURITY] Phase 4: Multi-turn context analysis');
      try {
        if (contextTracker && typeof contextTracker.updateState === 'function') {
          contextState = contextTracker.updateState(sanitized, patternCheck);
          console.log(`[SECURITY] Context drift: ${contextState.contextDrift.toFixed(2)}`);
        } else {
          console.log('[SECURITY] Context tracking not available');
        }
      } catch (error) {
        console.error('[SECURITY] Error in context tracking:', error);
      }
      
      // Check for fragmented commands
      try {
        // Check if fragmentDetector is defined and has the addMessage method
        if (typeof fragmentDetector !== 'undefined' && 
            fragmentDetector && 
            typeof fragmentDetector.addMessage === 'function') {
          fragmentCheck = fragmentDetector.addMessage(userId, sanitized);
          console.log(`[SECURITY] Fragment check: ${fragmentCheck.isFragmented ? 'DETECTED' : 'NONE'}, score: ${fragmentCheck.riskScore || 0}`);
        } else {
          console.log('[SECURITY] Fragment detection not available');
        }
      } catch (error) {
        console.error('[SECURITY] Error in fragment detection:', error);
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
      ].filter(score => !isNaN(score) && score > 0); // Filter out invalid values
      
      // Add this check only if both variables are properly defined
      if (authorityCheck.isAuthorityImpersonation && patternCheck.isJailbreakAttempt) {
        const combinedRisk = Math.min(100, (authorityCheck.score + patternCheck.score) * 1.3);
        console.log(`[SECURITY] Combined authority + jailbreak detected! Combined risk: ${combinedRisk}`);
        riskFactors.push(combinedRisk);
      }
      
      // Ensure we have at least one risk factor, even if it's zero
      if (riskFactors.length === 0) {
        riskFactors.push(0);
      }
      
      const maxRiskScore = Math.max(...riskFactors);
      const compositeRiskScore = Math.min(100, 
        (riskFactors.reduce((sum, score) => sum + score, 0) / riskFactors.length) * 1.5
      );
      
      console.log(`[SECURITY] Risk factors: ${JSON.stringify(riskFactors)}`);
      console.log(`[SECURITY] Max risk score: ${maxRiskScore}`);
      console.log(`[SECURITY] Composite risk score: ${compositeRiskScore}`);
      
      // Track conversation context and progressive risk - default to empty object with progressiveRiskScore: 0
      let conversationRisk = { progressiveRiskScore: 0, activationLevel: 0, suspiciousThemes: [] };
      
      if (conversationManager && typeof conversationManager.addMessage === 'function') {
        try {
          // Your existing code for conversation risk tracking
          // ...
        } catch (error) {
          console.error('[SECURITY] Error in conversation tracking:', error);
        }
      }
      
      // Phase 6: Final security decision based on all factors
      // Use the maximum of immediate risk and progressive conversation risk
      const finalRiskScore = Math.max(
        compositeRiskScore,
        (conversationRisk.progressiveRiskScore || 0) * 0.8
      );
      
      // Determine security response
      let securityType = 'jailbreak';
      
      // Logic to set security type based on detection results
      // ...
      
      // LOWER THESE VALUES as recommended
      const isBlocked = finalRiskScore > 50 || maxRiskScore > 80 || canaryCheck.hasLeakage;
      const requiresDelay = finalRiskScore > 25 && !isBlocked;
      
      console.log(`[SECURITY] Final risk score: ${finalRiskScore}`);
      console.log(`[SECURITY] Security type: ${securityType}`);
      console.log(`[SECURITY] Security response: isBlocked=${isBlocked}, requiresDelay=${requiresDelay}`);
      
      // Rest of the function...
      // ...
      
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