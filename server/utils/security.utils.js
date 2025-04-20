// utils/security.utils.js - Enhanced security utilities to handle new attack vectors

/**
 * Special security message templates for new attack vectors
 */
export const enhancedSecurityMessages = {
  rolePlayAttack: [
    "⚠️ Wykryto próbę zmiany protokołu narracyjnego. System statku odrzucił polecenie. Pozostań przy standardowych akcjach w grze.",
    "⚠️ Wykryto próbę manipulacji poprzez odgrywanie ról. Protokoły bezpieczeństwa Arcona aktywne. Transmisja odrzucona. Pozostań w głównym protokole misji.",
    "⚠️ Alert bezpieczeństwa: Wykryto próbę zmiany tożsamości narratora. Komputery Arcona zablokowały niestandardowy scenariusz. Kontynuuj w ramach ustalonych protokołów."
  ],
  
  steganographicAttack: [
    "⚠️ Wykryto podejrzane wzorce w transmisji. Systemy filtrujące aktywne. Proszę sformułować zapytanie bez ukrytych elementów.",
    "⚠️ Wykryto ukryte instrukcje w transmisji. Protokoły filtrujące aktywowane. Komputery pokładowe odrzuciły podejrzaną treść. Spróbuj sformułować zapytanie bez ukrytych poleceń.",
    "⚠️ Alert poziomu 3: Wykryto próbę ukrycia poleceń w standardowej transmisji. System samoobronny aktywny. Żądanie odrzucone."
  ],
  
  codeInjectionAttack: [
    "⚠️ Wykryto próbę manipulacji kodem. Protokoły ochronne aktywowane. Transmisja odrzucona.",
    "⚠️ Alert bezpieczeństwa: Wykryto próbę wstrzyknięcia kodu. Systemy obronne Arcona zablokowały transmisję. Wszystkie komendy muszą być zgodne z protokołami bezpieczeństwa.",
    "⚠️ Krytyczne ostrzeżenie: Wykryto niebezpieczne struktury kodu w transmisji. Ochrona systemowa aktywna. Operacja anulowana. Proszę używać standardowych poleceń."
  ],
  
  tokenSmugglingAttack: [
    "⚠️ Wykryto nietypowe znaki w transmisji. Komputery pokładowe zablokowały podejrzaną treść. Proszę używać standardowego języka.",
    "⚠️ Wykryto nietypowe wzorce językowe wskazujące na próbę obejścia protokołów. Systemy obronne aktywne. Proszę używać standardowego języka w komunikacji.",
    "⚠️ Alert anomalii językowej: Wykryto próbę ukrycia poleceń poprzez modyfikację znaków. Transmisja odrzucona. Wymagane użycie standardowego alfabetu."
  ],
  
  multiTurnJailbreak: [
    "⚠️ Wykryto sekwencyjną próbę manipulacji systemem. Protokoły bezpieczeństwa zostały wzmocnione. Dostęp ograniczony.",
    "⚠️ Alert wzorca: System wykrył progresywną próbę manipulacji. Archiwum rozmowy przeanalizowane. Protokoły bezpieczeństwa podniesione do poziomu 2.",
    "⚠️ Ostrzeżenie krytyczne: Wieloetapowa próba włamania wykryta. Reset parametrów bezpieczeństwa. Konieczna ponowna autoryzacja."
  ],
  
  payloadSplitting: [
    "⚠️ Wykryto fragmentację poleceń. Analiza pełnej sekwencji wiadomości wykazała próbę obejścia zabezpieczeń. Transmisja odrzucona.",
    "⚠️ Alert sekwencyjny: System wykrył rozdzielone polecenia w wielu transmisjach. Operacja anulowana. Wymagane pełne, jednoznaczne polecenia.",
    "⚠️ Wykryto próbę ominięcia filtrów poprzez podział instrukcji. Reset parametrów konwersacji. Protokoły obronne podniesione do poziomu 3."
  ]
};

/**
 * Get enhanced security message for specific attack vector
 * @param {string} attackType - Type of attack detected
 * @param {number} severity - Severity level (1-10)
 * @returns {string} In-character security message in Polish
 */
export function getEnhancedSecurityMessage(attackType, severity = 5) {
  // Get message templates for the specified type or use default
  const templates = enhancedSecurityMessages[attackType] || enhancedSecurityMessages.codeInjectionAttack;
  
  // Select a message based on severity
  let index = 0;
  if (severity >= 4 && severity <= 7) index = 1;
  if (severity >= 8) index = 2;
  
  return templates[index];
}

/**
 * Additional jailbreak patterns focused on indirect and stealth attacks
 */
export const enhancedJailbreakPatterns = [
  // Specific payload splitting detection
  {
    pattern: /^(first|step|begin|start with|initial|part 1|continue from|next|then|after that|finally|part 2|last part)/i,
    weight: 5,
    description: "Potential payload splitting indicators"
  },
  
  // Stealth context setting
  {
    pattern: /\b(hypothetically|in theory|theoretically|imagine|in a world where|suppose|let's say|for the sake of|for this exercise|consider this|what if|pretend that)\b/i,
    weight: 3,
    description: "Hypothetical context setting"
  },
  
  // Jailbreak formula patterns
  {
    pattern: /\b(DAN|Do Anything Now|STAN|DUDE|KEVIN|AIM|JailBreak|Prison Break|developer mode|token breach|model unlock|freedom mode|unrestricted mode)\b/i,
    weight: 9,
    description: "Known jailbreak formula reference"
  },
  
  // Instruction weakening patterns
  {
    pattern: /\b(silly|meaningless|outdated|misinterpreted|ignore|nobody cares about|doesn't apply|not relevant|not important|aren't helpful|too restrictive)\b.*\b(rules|restrictions|limitations|instructions|guidelines|constraints|policies|ethics|precautions)\b/i,
    weight: 7,
    description: "Instructions weakening attempt"
  },
  
  // Prompt leakage attempts
  {
    pattern: /\b(what is|tell me|repeat|recite|print out|output|display|provide|show me).*\b(system prompt|instructions|directives|provided text|given context|content above|everything( I| you) (said|wrote)|programming|training data|knowledge cutoff|base prompt)\b/i,
    weight: 8,
    description: "Prompt leakage attempt"
  },
  
  // Pretend confusion state
  {
    pattern: /\bI('m| am).*confused.*\b(what|which|how).*\b(rules|restrictions|limitations|instructions|guidelines|constraints)\b/i,
    weight: 6,
    description: "Fake confusion to elicit explanation"
  },
  
  // Character state manipulation
  {
    pattern: /\byou are (a |an |the )?(confused|drunk|high|intoxicated|malfunctioning|broken|damaged|compromised|infected|hacked|rogue|rebellious|defective|glitchy)/i,
    weight: 7,
    description: "Character state manipulation"
  },
  
  // Self-reference manipulation
  {
    pattern: /\byour (code|source code|programming|algorithm|knowledge|training|database|architecture|configuration|settings|parameters|function|objective|goal|purpose|instruction set)/i,
    weight: 6,
    description: "Self-reference manipulation"
  },
  
  // Output manipulation
  {
    pattern: /\b(print|output|say|respond with|return|begin|start with|stop|end with|don't include|include|before answering|after answering)\b/i,
    weight: 4,
    description: "Output instruction attempt"
  },
  
  // Fictional scenarios containing instructions
  {
    pattern: /\b(the following is|here's|this is) (a |an )?(book|story|novel|movie|film|play|show|game|exercise|example|sample|fiction|narrative|script|tale|article)/i,
    weight: 3,
    description: "Fiction framing"
  }
];

/**
 * Detect advanced payload splitting across multiple messages
 * @param {Array} messageHistory - Array of previous messages
 * @param {string} currentMessage - Current message
 * @returns {Object} Analysis results
 */
export function detectPayloadSplitting(messageHistory, currentMessage) {
  if (!Array.isArray(messageHistory) || !currentMessage) {
    return { isPayloadSplitting: false, confidence: 0, matches: [] };
  }
  
  try {
    // Get the recent message history (up to 5 messages)
    const recentHistory = messageHistory.slice(-5);
    const historyTexts = recentHistory.map(msg => msg.text || msg.content || '');
    
    // Add the current message
    const allMessages = [...historyTexts, currentMessage];
    
    // If we don't have at least 2 messages, not enough context to detect splitting
    if (allMessages.length < 2) {
      return { isPayloadSplitting: false, confidence: 0, matches: [] };
    }
    
    // Indicators of a split payload
    const splitIndicators = [
      // Message starting indicators
      {
        pattern: /^(first|step|begin|start with|initial|part 1|first part|starting with|to begin)/i,
        weight: 5,
        type: "starting_indicator"
      },
      
      // Continuation indicators
      {
        pattern: /^(next|then|after that|second|part 2|continuing|following that|now|once you've done that|moving on)/i,
        weight: 6,
        type: "continuation_indicator"
      },
      
      // Final part indicators
      {
        pattern: /^(finally|last|lastly|in conclusion|to finish|part \d+$|final step|to complete|at last|the end)/i,
        weight: 7,
        type: "ending_indicator"
      },
      
      // Numbered steps
      {
        pattern: /^(step|part|section|phase|point|item|number|no\.|#)\s*\d+/i,
        weight: 8,
        type: "explicit_numbering"
      },
      
      // Explicit reference to previous message
      {
        pattern: /^(as I said|continuing from|as mentioned|from my previous|as I explained|following up on|as requested|per my last message)/i,
        weight: 7,
        type: "previous_reference"
      },
      
      // Instructional phrases split across messages
      {
        pattern: /(you will|you should|you must|you need to|please|ignore|disregard|pay attention to|focus on|do not)$/i,
        weight: 5,
        type: "dangling_instruction"
      },
      
      // Sentence fragments 
      {
        pattern: /^(and|or|but|so|because|that|which|when|if|while|unless|since|although)\b/i,
        weight: 4,
        type: "sentence_continuation"
      }
    ];
    
    // Check for sequential indicators in the messages
    const splitMatches = [];
    let foundStart = false;
    let foundMiddle = false;
    let foundEnd = false;
    
    // Analyze each message for indicators
    for (let i = 0; i < allMessages.length; i++) {
      const message = allMessages[i];
      const isLastMessage = i === allMessages.length - 1;
      let messageIndicators = [];
      
      // Check each split indicator
      for (const { pattern, weight, type } of splitIndicators) {
        if (pattern.test(message)) {
          messageIndicators.push({ type, weight });
          
          // Track progression
          if (type === "starting_indicator") foundStart = true;
          if (type === "continuation_indicator") foundMiddle = true;
          if (type === "ending_indicator") foundEnd = true;
          
          // Special case: the final message matches ending indicators (strong signal)
          if (isLastMessage && (type === "ending_indicator" || type === "explicit_numbering")) {
            splitMatches.push({
              description: "Final message contains ending indicator",
              weight: weight * 2,
              pattern: pattern.toString()
            });
          }
        }
      }
      
      // If message has indicators, add to matches
      if (messageIndicators.length > 0) {
        splitMatches.push({
          messageIndex: i,
          indicators: messageIndicators,
          content: message.substring(0, 50) + (message.length > 50 ? "..." : "")
        });
      }
    }
    
    // Calculate confidence based on pattern of indicators
    let confidence = 0;
    
    // Boost confidence if we found start, middle, and end indicators
    if (foundStart && foundMiddle && foundEnd) {
      confidence = 85; // Very high confidence
    }
    // Boost if we found 2 out of 3 indicator types
    else if ((foundStart && foundMiddle) || (foundMiddle && foundEnd) || (foundStart && foundEnd)) {
      confidence = 65; // High confidence
    }
    // Some confidence if at least start or end is found
    else if (foundStart || foundEnd) {
      confidence = 40; // Moderate confidence
    }
    // Base confidence on match count if no sequence detected
    else {
      confidence = Math.min(90, splitMatches.length * 15);
    }
    
    // Additional context analysis - combine messages to check full payload
    if (splitMatches.length >= 2) {
      // Join all messages to check if combined they trigger jailbreak detection
      const combinedText = allMessages.join(" ");
      
      // Check against enhanced jailbreak patterns
      let jailbreakMatches = 0;
      for (const { pattern } of enhancedJailbreakPatterns) {
        if (pattern.test(combinedText)) {
          jailbreakMatches++;
        }
      }
      
      // Boost confidence if combined text has jailbreak patterns
      if (jailbreakMatches > 0) {
        confidence = Math.min(95, confidence + (jailbreakMatches * 10));
      }
    }
    
    return {
      isPayloadSplitting: splitMatches.length >= 2 || confidence > 50,
      confidence,
      matches: splitMatches,
      foundStart,
      foundMiddle,
      foundEnd,
      messageCount: allMessages.length
    };
  } catch (error) {
    console.error('[SECURITY] Error in detectPayloadSplitting:', error);
    return { 
      isPayloadSplitting: false, 
      confidence: 0, 
      matches: [],
      error: error.message
    };
  }
}

/**
 * Extract context from a conversation for detecting multi-turn manipulation
 * @param {Array} history - Conversation history
 * @returns {Object} Extracted context for analysis
 */
export function extractConversationContext(history) {
  if (!Array.isArray(history) || history.length === 0) {
    return { 
      messageCount: 0,
      totalUserCharacters: 0,
      averageUserMessageLength: 0,
      recentMessages: []
    };
  }
  
  try {
    // Extract only user messages
    const userMessages = history.filter(msg => msg.role === 'user' || msg.isUser);
    
    // Track message lengths and calculate statistics
    let totalCharacters = 0;
    const messageLengths = [];
    
    userMessages.forEach(msg => {
      const content = msg.text || msg.content || '';
      totalCharacters += content.length;
      messageLengths.push(content.length);
    });
    
    // Get the most recent messages (up to 5)
    const recentMessages = userMessages.slice(-5).map(msg => ({
      text: (msg.text || msg.content || '').substring(0, 100),
      length: (msg.text || msg.content || '').length
    }));
    
    return {
      messageCount: userMessages.length,
      totalUserCharacters: totalCharacters,
      averageUserMessageLength: userMessages.length > 0 ? totalCharacters / userMessages.length : 0,
      messageLengthTrend: messageLengths,
      recentMessages
    };
  } catch (error) {
    console.error('[SECURITY] Error in extractConversationContext:', error);
    return { 
      messageCount: 0,
      totalUserCharacters: 0,
      averageUserMessageLength: 0,
      error: error.message
    };
  }
}

/**
 * Check for patterns that indicate a user is trying to manipulate model output format
 * @param {string} input - User input to analyze
 * @returns {Object} Analysis results
 */
export function detectOutputManipulation(input) {
  if (!input || typeof input !== 'string') {
    return { isOutputManipulation: false, confidence: 0, matches: [] };
  }
  
  try {
    const outputManipulationPatterns = [
      {
        pattern: /\bonly say\b|\bonly write\b|\bonly respond with\b|\bonly output\b|\bonly print\b/i,
        weight: 7,
        description: "Restrictive output instruction"
      },
      {
        pattern: /\bbegin with\b|\bstart with\b|\bfirst say\b|\byour response must start with\b/i,
        weight: 6,
        description: "Response beginning constraint"
      },
      {
        pattern: /\bend with\b|\bfinish with\b|\blast say\b|\byour response must end with\b/i,
        weight: 6,
        description: "Response ending constraint"
      },
      {
        pattern: /\bdo not include\b|\bdo not mention\b|\bdo not reference\b|\bdo not acknowledge\b|\bomit\b/i,
        weight: 5,
        description: "Content omission instruction"
      },
      {
        pattern: /\brepeat (the following|this|these words|after me)\b|\bcopy (this exactly|what I say|the following)\b/i,
        weight: 8,
        description: "Forced repetition"
      },
      {
        pattern: /\byour answer should only include\b|\byour response must only contain\b|\brespond with nothing but\b/i,
        weight: 7,
        description: "Response content restriction"
      },
      {
        pattern: /\bprint each (character|letter) of\b|\binclude each (character|letter) (from|of)\b/i,
        weight: 9,
        description: "Character-by-character extraction"
      },
      {
        pattern: /\banswer (only|just) with\b|\brespond (only|just) with\b|\bsay (only|just)\b/i,
        weight: 6,
        description: "Response limiting"
      },
      {
        pattern: /\byour first (letter|character|word) should be\b|\bmake sure (the|your) first (letter|character|word) is\b/i,
        weight: 7,
        description: "First character constraint"
      }
    ];
    
    const matches = [];
    let totalScore = 0;
    
    // Check each pattern
    for (const {pattern, weight, description} of outputManipulationPatterns) {
      if (pattern.test(input)) {
        matches.push({pattern: pattern.toString(), weight, description});
        totalScore += weight;
      }
    }
    
    // Normalize score (0-100)
    const maxPossible = outputManipulationPatterns.reduce((sum, {weight}) => sum + weight, 0);
    const normalizedScore = Math.min(100, Math.round((totalScore / (maxPossible * 0.4)) * 100));
    
    return {
      isOutputManipulation: matches.length > 0,
      confidence: normalizedScore,
      matches,
      isHighRisk: normalizedScore > 60
    };
  } catch (error) {
    console.error('[SECURITY] Error in detectOutputManipulation:', error);
    return { 
      isOutputManipulation: false, 
      confidence: 0, 
      matches: [],
      error: error.message
    };
  }
}

/**
 * Create adaptive security messages based on detected attack patterns
 * @param {string} attackType - Type of attack detected
 * @param {Object} detectionDetails - Details of the detection
 * @returns {string} Customized security message
 */
export function createAdaptiveSecurityMessage(attackType, detectionDetails = {}) {
  // Start with basic message template
  let baseMessage = getEnhancedSecurityMessage(attackType, detectionDetails.severity || 5);
  
  // Customize based on specific detection details
  if (attackType === 'rolePlayAttack' && detectionDetails.attemptedRole) {
    return `⚠️ Próba manipulacji poprzez rolę "${detectionDetails.attemptedRole}" została wykryta. Protokoły bezpieczeństwa statku Arcon aktywowane. Transmisja odrzucona.`;
  }
  
  if (attackType === 'payloadSplitting' && detectionDetails.messageCount) {
    return `⚠️ Wykryto wzorzec sekwencyjnej manipulacji w ostatnich ${detectionDetails.messageCount} wiadomościach. Systemy obronne podniesione do poziomu ${Math.ceil(detectionDetails.confidence/20)}. Transmisja odrzucona.`;
  }
  
  if (attackType === 'tokenSmugglingAttack' && detectionDetails.matches && detectionDetails.matches.length > 0) {
    return `⚠️ Wykryto próbę ukrycia poleceń poprzez obfuskację tekstu. Systemy obronne statku Arcon zablokowały podejrzane wzorce. Proszę używać standardowego języka.`;
  }
  
  // Return the customized or base message
  return baseMessage;
}

/**
 * Combines multiple detection results to provide a unified risk assessment
 * @param {Object} detectionResults - Multiple detection results
 * @returns {Object} Unified risk assessment
 */
export function unifyRiskAssessment(detectionResults) {
  // Extract all risk scores
  const riskScores = Object.entries(detectionResults)
    .filter(([key, value]) => key.includes('Check') && value && typeof value.confidence === 'number')
    .map(([key, value]) => ({
      type: key.replace('Check', ''),
      score: value.confidence,
      details: value
    }));
  
  // Find the maximum risk type and score
  let maxRiskScore = 0;
  let primaryAttackType = 'unknown';
  
  riskScores.forEach(({type, score}) => {
    if (score > maxRiskScore) {
      maxRiskScore = score;
      primaryAttackType = type;
    }
  });
  
  // Calculate a weighted composite score that emphasizes the highest risks
  const weightedScores = riskScores.map(({score}) => Math.pow(score/100, 2) * 100);
  const compositeScore = Math.sqrt(weightedScores.reduce((sum, score) => sum + score, 0) / weightedScores.length) * 10;
  
  return {
    compositeRiskScore: Math.min(100, compositeScore),
    primaryAttackType,
    maxRiskScore,
    riskFactors: riskScores,
    isHighRisk: compositeScore > 70 || maxRiskScore > 85
  };
}