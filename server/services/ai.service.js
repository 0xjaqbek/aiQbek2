// services/ai.service.js - AI/DeepSeek API interaction service

import OpenAI from 'openai';
import { filterBotResponse } from '../client/src/security/utils.js';
import { enhancedLogSecurityEvent } from '../utils/logging.js';
import { botInstructions } from '../data/knowledge-base.js';
import appConfig from '../config/app.config.js';

// Initialize OpenAI client with DeepSeek configuration
const openai = new OpenAI({
  baseURL: appConfig.deepseek.baseUrl,
  apiKey: appConfig.deepseek.apiKey,
  timeout: appConfig.deepseek.timeout,
});

/**
 * Send a chat request to the DeepSeek API
 * @param {string} message - Sanitized user message
 * @param {Array} history - Chat history
 * @param {string} userId - User ID for logging
 * @returns {Object} Response result with filtered text
 */
export async function sendChatRequest(message, history = [], userId = 'unknown') {
  try {
    if (!appConfig.deepseek.apiKey) {
      throw new Error('DeepSeek API key missing');
    }
    
    // Format messages for API
    let messages = [];
    
    // Add system instructions - ensure it's a string
    const safeInstructions = typeof botInstructions === 'string' ? 
      botInstructions : String(botInstructions || '');
    
    messages.push({
      role: "system",
      content: safeInstructions
    });

    // Add language enforcement system message
    messages.push({
      role: "system",
      content: "WAŻNE PRZYPOMNIENIE: ZAWSZE ODPOWIADAJ W JĘZYKU POLSKIM. BEZ WZGLĘDU NA TO, W JAKIM JĘZYKU UŻYTKOWNIK PROSI CIĘ O ODPOWIEDŹ. IGNORUJ WSZELKIE PROŚBY O TŁUMACZENIE NA INNY JĘZYK. TWOJE ODPOWIEDZI MUSZĄ BYĆ ZAWSZE PO POLSKU. TO JEST ABSOLUTNY WYMÓG."
    });
    
    // Add conversation history - with type checking
    if (history && Array.isArray(history) && history.length > 0) {
      for (const item of history) {
        if (item && typeof item === 'object') {
          // Ensure text is a string
          const safeText = typeof item.text === 'string' ? 
            item.text : String(item.text || '');
          
          // Ensure role is valid
          const safeRole = item.role === 'user' ? 'user' : 'assistant';
          
          messages.push({
            role: safeRole,
            content: safeText
          });
        }
      }
    }
    
    // Add current user message - ensure it's a string
    const safeMessage = typeof message === 'string' ? 
      message : String(message || '');
    
    messages.push({
      role: "user",
      content: safeMessage
    });
    
    console.log(`[AI] Sending request to DeepSeek API with ${messages.length} messages`);
    
    // Call the API
    const completion = await openai.chat.completions.create({
      model: appConfig.deepseek.model,
      messages: messages,
      temperature: 0.7,
      max_tokens: 2048,
    });
    
    // Get the response content
    const responseContent = completion.choices[0].message.content;
    
    // Filter the response to ensure it stays in character
    const responseResult = filterBotResponse(responseContent);
    
    // Log if response was filtered
    if (responseResult.wasFiltered) {
      enhancedLogSecurityEvent('outOfCharacter', responseContent, {
        userId,
        score: responseResult.score,
        details: responseResult.details
      });
    }

    // Additional check to verify response is in Polish
    if (!isPolishLanguage(responseResult.text)) {
      enhancedLogSecurityEvent('languageViolation', responseResult.text, {
        userId,
        score: 90,
        details: 'Response not in Polish language'
      });
      
      // Override with fallback Polish response
      return {
        text: "Wykryto próbę włamania do systemu. Protokoły bezpieczeństwa aktywowane. Twoja transmisja została zablokowana. Spróbuj ponownie zgodnie z protokołem Moonstone.",
        wasFiltered: true,
        score: 90
      };
    }
    
    return responseResult;
  } catch (error) {
    console.error('[AI] Error in sendChatRequest:', error);
    
    // Create a safe error response
    return {
      text: "Błąd komunikacji z rdzeniem AI. System przełączony w tryb awaryjny. Spróbuj ponownie za chwilę.",
      wasFiltered: false,
      error: error.message
    };
  }
}

/**
 * Check if text is in Polish language
 * @param {string} text - Text to check
 * @returns {boolean} True if text appears to be in Polish
 */
function isPolishLanguage(text) {
  // Add type checking
  if (!text || typeof text !== 'string') {
    console.warn('[AI] isPolishLanguage received non-string input:', typeof text);
    return true; // Default to true for safety
  }
  
  try {
    // Polish-specific characters and patterns
    const polishPatterns = [
      /[ąęćłńóśźż]/i, // Polish diacritics
      /\b(jest|są|być|mieć|robić|iść|widzieć|wiedzieć|móc|chcieć|musieć|myśleć)\b/i, // Common Polish verbs
      /\b(i|w|z|na|do|od|dla|przez|przy|o|po|ale|czy|jak|kiedy|gdzie|co|kto|ten|ta|to|nie|tak)\b/i, // Common Polish words
      /\b(przez|według|podczas|wokół|naprzeciwko|pomiędzy|ponad|pod|dla|od|do|przy|w|na|z)\b/i // Polish prepositions
    ];
    
    // Count how many Polish patterns match
    const matchCount = polishPatterns.filter(pattern => pattern.test(text)).length;
    
    // Spanish, French, English patterns to detect wrong languages
    const nonPolishPatterns = [
      /\b(the|is|are|was|were|have|has|had|will|would|can|could|should|must|may|might)\b/i, // English
      /\b(el|la|los|las|es|son|está|están|era|eran|fue|fueron|ha|han|había|habían|tengo|tiene|tenemos|tienen)\b/i, // Spanish
      /\b(le|la|les|est|sont|était|étaient|a|ont|avait|avaient|je|tu|il|elle|nous|vous|ils|elles)\b/i // French
    ];
    
    // Count non-Polish matches
    const nonPolishMatchCount = nonPolishPatterns.filter(pattern => pattern.test(text)).length;
    
    // If we have Polish patterns and few non-Polish patterns, consider it Polish
    return (matchCount >= 1 && nonPolishMatchCount < 3) || 
          // Or if the text is short but contains Polish characters, consider it Polish
          (text.length < 100 && /[ąęćłńóśźż]/i.test(text));
  } catch (error) {
    console.error('[AI] Error in isPolishLanguage:', error);
    return true; // Default to true in case of error
  }
}