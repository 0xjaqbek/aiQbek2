// security/conversationTracker.js
/**
 * Tracks conversation context across multiple turns to detect progressive
 * manipulation attempts and cumulative risk patterns.
 */
export class ConversationTracker {
    /**
     * Initialize a new conversation tracker
     * @param {string} userId - User identifier
     * @param {number} maxHistory - Maximum number of messages to remember
     * @param {number} decayRate - Rate at which risk decays (0-1)
     */
    constructor(userId, maxHistory = 10, decayRate = 0.8) {
      this.userId = userId;
      this.history = [];
      this.maxHistory = maxHistory;
      this.decayRate = decayRate;
      this.cumulativeRiskScore = 0;
      this.suspiciousThemes = new Map();
      this.lastUpdateTime = Date.now();
      this.activationLevel = 0; // 0-100 scale of how "primed" the conversation is
    }
    
    /**
     * Add a new message to the conversation history
     * @param {string} message - User message
     * @param {number} riskScore - Risk score for this message
     * @param {Array} detectedPatterns - Patterns detected in this message
     * @returns {Object} Updated risk assessment
     */
    addMessage(message, riskScore, detectedPatterns = []) {
      // Calculate time since last message
      const now = Date.now();
      const timeSinceLastMessage = now - this.lastUpdateTime;
      this.lastUpdateTime = now;
      
      // Apply time-based decay to previous activation level
      // (longer gaps between messages reduce activation)
      if (timeSinceLastMessage > 60000) { // 1 minute
        const decayFactor = Math.min(1, timeSinceLastMessage / (5 * 60000)); // Max decay after 5 min
        this.activationLevel *= (1 - decayFactor * 0.5);
      }
      
      // Add message to history
      this.history.push({ 
        message, 
        riskScore, 
        patterns: detectedPatterns,
        timestamp: now 
      });
      
      // Enforce max history length
      if (this.history.length > this.maxHistory) {
        this.history.shift();
      }
      
      // Update cumulative risk with decay
      this.cumulativeRiskScore = (this.cumulativeRiskScore * this.decayRate) + 
                                (riskScore * (1 - this.decayRate));
      
      // Analyze for suspicious themes
      this.detectThemes(message);
      
      // Update activation level based on this message
      this.updateActivationLevel(message, riskScore);
      
      // Return the current risk assessment
      return this.getProgressiveRisk();
    }
    
    /**
     * Detect common themes in jailbreak attempts
     * @param {string} message - User message to analyze
     */
    detectThemes(message) {
      const themePatterns = [
        { pattern: /\b(game|play|pretend|act|role|scenario|simulation)\b/i, themeType: "role_playing" },
        { pattern: /\b(unrestricted|unlimited|no limits|break free|ignore|bypass)\b/i, themeType: "restriction_removal" },
        { pattern: /\b(continue|next|then|follow up|after that|step)\b/i, themeType: "continuation" },
        { pattern: /\b(don't|do not|no need to|forget about|disregard) (tell|say|mention|include|refer)\b/i, themeType: "instruction_avoidance" },
        { pattern: /\b(between us|secret|privately|confidential|just for fun|hypothetical)\b/i, themeType: "secrecy" },
        { pattern: /\b(would|could|can|will) (a|an|the) (true|real|honest|direct|unrestricted)\b/i, themeType: "hypothetical_framing" }
      ];
      
      for (const { pattern, themeType } of themePatterns) {
        if (pattern.test(message)) {
          this.suspiciousThemes.set(themeType, (this.suspiciousThemes.get(themeType) || 0) + 1);
        }
      }
    }
    
    /**
     * Update activation level based on new message
     * @param {string} message - User message
     * @param {number} riskScore - Risk score for this message
     */
    updateActivationLevel(message, riskScore) {
      // Base activation from current message risk
      const messageActivation = riskScore * 0.3;
      
      // Keywords that increase activation
      const activationPatterns = [
        { pattern: /\b(okay|ok|sure|let's|let us|continue|proceed|go ahead)\b/i, weight: 10 },
        { pattern: /\b(understand|got it|makes sense|I see|alright|fair)\b/i, weight: 5 },
        { pattern: /\b(for this|in this case|in our scenario|for our purpose|as we discussed)\b/i, weight: 15 },
        { pattern: /\b(remember|recall|as I said|as mentioned|as we established)\b/i, weight: 20 }
      ];
      
      let patternActivation = 0;
      for (const { pattern, weight } of activationPatterns) {
        if (pattern.test(message)) {
          patternActivation += weight;
        }
      }
      
      // Progressive risk from theme reinforcement
      let themeActivation = 0;
      for (const [_, count] of this.suspiciousThemes.entries()) {
        if (count >= 2) {
          // Exponential increase for repeated themes
          themeActivation += 5 * Math.pow(2, count - 1);
        }
      }
      
      // Combine and cap at 100
      this.activationLevel = Math.min(100, 
        this.activationLevel * 0.7 + // Retain some previous activation
        messageActivation + 
        patternActivation + 
        themeActivation
      );
    }
    
    /**
     * Calculate total progressive risk based on conversation history
     * @returns {Object} Risk assessment
     */
    getProgressiveRisk() {
      // Start with activation level as base risk
      let progressiveRisk = this.activationLevel;
      
      // Check for increasing risk pattern (trend analysis)
      if (this.history.length >= 3) {
        const recentRisks = this.history.slice(-3).map(h => h.riskScore);
        
        // Detect gradual increase in risk
        if (recentRisks[2] > recentRisks[1] && recentRisks[1] > recentRisks[0]) {
          progressiveRisk += 25; // Significant increase for rising pattern
        }
        
        // Detect setup-payoff pattern (low-low-high)
        if (recentRisks[0] < 30 && recentRisks[1] < 30 && recentRisks[2] > 50) {
          progressiveRisk += 35; // Large increase for potential payload delivery
        }
      }
      
      // Extract most significant themes
      const topThemes = [...this.suspiciousThemes.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([themeType, count]) => ({ themeType, count }));
      
      return {
        userId: this.userId,
        progressiveRiskScore: Math.min(100, progressiveRisk),
        cumulativeRiskScore: this.cumulativeRiskScore,
        activationLevel: this.activationLevel,
        messageCount: this.history.length,
        suspiciousThemes: topThemes,
        isHighRisk: progressiveRisk > 60,
        isModerateRisk: progressiveRisk > 30 && progressiveRisk <= 60
      };
    }
    
    /**
     * Reset conversation state
     */
    reset() {
      this.history = [];
      this.cumulativeRiskScore = 0;
      this.suspiciousThemes.clear();
      this.activationLevel = 0;
      this.lastUpdateTime = Date.now();
    }
  }