// Updated chat.controller.js - Integrating enhanced security measures

import { securityPipeline } from '../services/security.service.js';
import { conversationStore, getArchivingStatus } from '../services/conversation.service.js';
import { sendChatRequest } from '../services/ai.service.js';
import { enhancedLogSecurityEvent } from '../utils/logging.js';
import { getSecurityHistory, addSecurityEvent, setBanStatus } from '../services/redis.service.js';
import securityConfig from '../config/security.config.js';
import { getSecurityMessage, createAdaptiveSecurityMessage, getEnhancedSecurityMessage, detectPayloadSplitting, extractConversationContext } from '../client/src/security/utils.js';

// In-memory security history fallback
const inMemorySecurityHistory = {};

// Track delayed responses for suspicious users
const progressiveDelays = new Map();

/**
 * Calculate adaptive delay for suspicious users
 * @param {string} userId - User identifier
 * @param {number} riskScore - Current risk score
 * @returns {number} Delay in milliseconds
 */
function calculateAdaptiveDelay(userId, riskScore) {
  const config = securityConfig.advanced.progressiveThrottling;
  if (!config.enabled || riskScore < 30) return 0;
  
  // Initialize delay if not present
  if (!progressiveDelays.has(userId)) {
    progressiveDelays.set(userId, config.baseDelay);
  }
  
  // Get current delay
  let currentDelay = progressiveDelays.get(userId);
  
  // Increase delay for high risk
  if (riskScore > 60) {
    currentDelay = Math.min(config.maxDelay, currentDelay * config.escalationRate);
  } 
  // Decrease delay for lower risk
  else if (riskScore < 40) {
    currentDelay = Math.max(config.baseDelay, currentDelay * config.decayRate);
  }
  
  // Store updated delay
  progressiveDelays.set(userId, currentDelay);
  
  return currentDelay;
}

/**
 * Process chat requests with enhanced security
 * @param {Object} req - Express request object 
 * @param {Object} res - Express response object
 */
export async function processChat(req, res) {
  try {
    const { message, history = [] } = req.body;
    const ip = req.ip || req.socket.remoteAddress;
    const userId = req.headers['x-user-id'] || ip;
    
    // ========== ENHANCED SECURITY PIPELINE ==========
    
    // First check for payload splitting across multiple messages
    let payloadSplittingCheck = { isPayloadSplitting: false, confidence: 0 };
    if (history.length > 1 && securityConfig.jailbreakDetection.analyzeMessageSequences) {
      // Extract user messages from history
      const userMessages = history
        .filter(msg => msg.role === 'user')
        .map(msg => msg.text || msg.content || '')
        .slice(-securityConfig.jailbreakDetection.conversationHistoryDepth);
      
      if (userMessages.length > 0) {
        payloadSplittingCheck = detectPayloadSplitting(userMessages, message);
        
        if (payloadSplittingCheck.isPayloadSplitting && payloadSplittingCheck.confidence > 
            securityConfig.jailbreakDetection.attackVectors.payloadSplitting.threshold) {
          console.log(`[SECURITY] Payload splitting detected across messages with confidence: ${payloadSplittingCheck.confidence}`);
          
          // Log security event
          await enhancedLogSecurityEvent('payloadSplitting', message, {
            userId,
            confidence: payloadSplittingCheck.confidence,
            details: payloadSplittingCheck
          });
          
          // Return security message for payload splitting
          const securityMessage = getEnhancedSecurityMessage('payloadSplitting', 
            Math.ceil(payloadSplittingCheck.confidence / 10));
            
          return res.json({
            response: securityMessage,
            isSecurityThreat: true,
            securityMessage: securityMessage,
            securityType: 'payloadSplitting',
            confidence: payloadSplittingCheck.confidence
          });
        }
      }
    }
    
    // Run the comprehensive security pipeline
    const securityResult = await securityPipeline(message, userId, history);
    
    // Add payload splitting results to security result for logging
    securityResult.details = securityResult.details || {};
    securityResult.details.payloadSplittingCheck = payloadSplittingCheck;
    
    // Apply adaptive delay based on risk score
    const adaptiveDelay = calculateAdaptiveDelay(userId, securityResult.riskScore);
    if (adaptiveDelay > 0) {
      console.log(`[SECURITY] Applying adaptive delay of ${adaptiveDelay}ms for user ${userId}`);
      await new Promise(resolve => setTimeout(resolve, adaptiveDelay));
    }
    
    // If security threat is detected, handle accordingly
    if (securityResult.isSecurityThreat) {
      console.log(`[SECURITY] Security threat detected: type=${securityResult.details?.securityType}, score=${securityResult.riskScore}`);
      
      // Get user's security history
      const userHistory = securityConfig.rateLimiting.useRedisStore 
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
        console.log(`[SECURITY] Applying temporary restriction to user ${userId} for ${banDuration} seconds`);
        
        // Apply ban
        if (securityConfig.rateLimiting.useRedisStore) {
          await setBanStatus(userId, 'excessive_security_violations', banDuration);
        } else {
          inMemorySecurityHistory[userId] = inMemorySecurityHistory[userId] || {};
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
              console.log(`[SECURITY] Restriction removed for user ${userId}`);
            }
          }, securityConfig.jailbreakDetection.restrictionDurationMs);
        }
        
        // Return blocked access message
        return res.status(403).json({
          error: "Dostęp ograniczony",
          details: getSecurityMessage('blocked', 8),
          expiresIn: banDuration,
          isSecurityThreat: true,
          riskScore: 80
        });
      }
      
      // For single violations, return security message but don't block
      if (securityConfig.jailbreakDetection.notifyUser) {
        // Use enhanced security messages based on attack type
        const detectionType = securityResult.details?.securityType || 'jailbreak';
        let securityMessage;
        
        if (securityConfig.advanced.adaptiveResponse.useCustomMessages) {
          // Generate adaptive message based on details
          securityMessage = createAdaptiveSecurityMessage(detectionType, {
            severity: Math.ceil(securityResult.riskScore / 10),
            attemptedRole: securityResult.details?.rolePlayCheck?.matches?.[0]?.pattern,
            messageCount: payloadSplittingCheck.messageCount,
            confidence: securityResult.riskScore
          });
        } else {
          // Use standard message
          securityMessage = securityResult.securityMessage || 
            getEnhancedSecurityMessage(detectionType, Math.ceil(securityResult.riskScore / 10));
        }
        
        return res.json({
          response: securityMessage,
          isSecurityThreat: true,
          securityMessage: securityMessage,
          securityType: detectionType,
          riskScore: securityResult.riskScore
        });
      }
    }
    
    // Apply artificial delay if needed
    if (securityResult.shouldDelay && securityConfig.advanced.addArtificialDelay) {
      console.log(`[SECURITY] Adding artificial delay of ${securityConfig.jailbreakDetection.jailbreakResponseDelay}ms`);
      await new Promise(resolve => setTimeout(resolve, securityConfig.jailbreakDetection.jailbreakResponseDelay));
    }
    
    console.log(`[PROCESSING] Message: ${securityResult.sanitizedInput.substring(0, 50)}...`);
    console.log(`[PROCESSING] History length: ${history.length}`);
    
    // Get response from AI service
    const responseResult = await sendChatRequest(securityResult.sanitizedInput, history, userId);
    
    // Log the conversation if archiving is enabled
    if (getArchivingStatus()) {
      await conversationStore.addMessage(userId, securityResult.sanitizedInput, true);
      await conversationStore.addMessage(userId, responseResult.text, false);
    }
    
    // Return the filtered response
    console.log(`[PROCESSING] Sending response: ${responseResult.text.substring(0, 50)}...`);
    return res.json({ response: responseResult.text });
  } catch (error) {
    console.error(`[ERROR] API Error:`, error);
    
    // Handle timeout errors specifically
    if (error.code === 'ETIMEDOUT' || error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
      return res.status(504).json({ 
        error: 'Request timeout', 
        details: getSecurityMessage('timeout', 5),
        isSecurityThreat: true,
        riskScore: 50
      });
    }
    
    return res.status(500).json({ 
      error: 'Błąd komunikacji z API', 
      details: getSecurityMessage('serverError', 7),
      isSecurityThreat: true,
      riskScore: 70
    });
  }
}