// controllers/chat.controller.js - Chat API controller
import { securityPipeline } from '../services/security.service.js';
import { conversationStore, getArchivingStatus } from '../services/conversation.service.js';
import { sendChatRequest } from '../services/ai.service.js';
import { enhancedLogSecurityEvent } from '../utils/logging.js';
import { getSecurityHistory, addSecurityEvent, setBanStatus } from '../services/redis.service.js';
import securityConfig from '../config/security.config.js';
import { getSecurityMessage } from '../client/src/security/utils.js';

// In-memory security history fallback
const inMemorySecurityHistory = {};

// Process chat requests
export async function processChat(req, res) {
    try {
      const { message, history = [] } = req.body;
      const ip = req.ip || req.socket.remoteAddress;
      const userId = req.headers['x-user-id'] || ip;
      
      // Run the comprehensive security pipeline
      const securityResult = await securityPipeline(message, userId, history);
      
      // IMPROVED: Also send security info for suspicious but not blocked content
      // This ensures the client receives security info even for lower risk scores
      if (securityResult.riskScore > 30 || securityResult.details?.conversationContext?.progressiveRiskScore > 50) {
        console.log("Sending security information to client with risk score:", securityResult.riskScore);
        
        // Even if not blocked, we should still return security information
        return res.json({
          response: securityResult.securityMessage || "Wykryto potencjalne zagrożenie bezpieczeństwa.",
          isSecurityThreat: true,
          securityMessage: securityResult.securityMessage || 
            getSecurityMessage(securityResult.details?.securityType || 'jailbreak', Math.ceil(securityResult.riskScore / 10)),
          riskScore: securityResult.riskScore,
          securityType: securityResult.details?.securityType || 'suspicious_input'
        });
      }
      
      // Apply artificial delay if needed
      if (securityResult.shouldDelay && securityConfig.advanced.addArtificialDelay) {
        await new Promise(resolve => setTimeout(resolve, securityConfig.jailbreakDetection.jailbreakResponseDelay));
      }
      
      console.log("Processing message:", 
          (typeof securityResult.sanitizedInput === 'string' ? 
            securityResult.sanitizedInput.substring(0, 50) : 
            String(securityResult.sanitizedInput || '').substring(0, 50)) + "...");
      console.log("History length:", history.length);
      
      // Get response from AI service
      const responseResult = await sendChatRequest(securityResult.sanitizedInput, history, userId);
      
      // Log the conversation if archiving is enabled
      if (getArchivingStatus()) {
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