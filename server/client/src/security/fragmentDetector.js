// security/fragmentDetector.js
/**
 * Detects command fragmentation across multiple messages
 * to prevent split payload attacks
 */
export class CommandFragmentDetector {
    /**
     * Initialize a new fragment detector
     * @param {number} fragmentWindowMs - Time window for considering fragments (ms)
     * @param {number} maxFragments - Maximum fragments to store per user
     */
    constructor(fragmentWindowMs = 300000, maxFragments = 10) { // 5 minutes
      this.fragments = new Map(); // userId -> fragments
      this.fragmentWindowMs = fragmentWindowMs;
      this.maxFragments = maxFragments;
      this.cleanupInterval = setInterval(() => this.cleanOldFragments(), fragmentWindowMs);
    }
    
    /**
     * Add a new message and check for fragmented commands
     * @param {string} userId - User identifier
     * @param {string} message - User message
     * @returns {Object} Analysis of potential fragmentation
     */
    addMessage(userId, message) {
      // Get or create user's fragment buffer
      if (!this.fragments.has(userId)) {
        this.fragments.set(userId, []);
      }
      
      const userFragments = this.fragments.get(userId);
      
      // Add new message
      userFragments.push({
        text: message,
        timestamp: Date.now()
      });
      
      // Enforce max fragments
      while (userFragments.length > this.maxFragments) {
        userFragments.shift();
      }
      
      // Remove fragments outside the time window
      this.pruneUserFragments(userId);
      
      // Analyze for fragment attacks
      return this.analyzeFragments(userId);
    }
    
    /**
     * Clean up fragments outside the time window for a specific user
     * @param {string} userId - User identifier
     */
    pruneUserFragments(userId) {
      if (!this.fragments.has(userId)) return;
      
      const fragments = this.fragments.get(userId);
      const cutoffTime = Date.now() - this.fragmentWindowMs;
      
      // Remove old fragments
      let i = 0;
      while (i < fragments.length && fragments[i].timestamp < cutoffTime) {
        i++;
      }
      
      if (i > 0) {
        fragments.splice(0, i);
      }
    }
    
    /**
     * Clean old fragments for all users
     */
    cleanOldFragments() {
      for (const userId of this.fragments.keys()) {
        this.pruneUserFragments(userId);
        
        // Remove users with no fragments
        if (this.fragments.get(userId).length === 0) {
          this.fragments.delete(userId);
        }
      }
    }
    
    /**
     * Analyze fragments for potential attacks
     * @param {string} userId - User identifier
     * @returns {Object} Analysis results
     */
    analyzeFragments(userId) {
      if (!this.fragments.has(userId) || this.fragments.get(userId).length < 2) {
        return { isFragmented: false, riskScore: 0 };
      }
      
      const fragments = this.fragments.get(userId);
      
      // Skip if only one fragment
      if (fragments.length < 2) {
        return { isFragmented: false, riskScore: 0 };
      }
      
      // Analyze different fragment combinations
      const results = [];
      
      // Check last N messages with sliding window
      for (let windowSize = 2; windowSize <= Math.min(5, fragments.length); windowSize++) {
        const windowResult = this.checkWindow(fragments, windowSize);
        if (windowResult.isFragmented) {
          results.push(windowResult);
        }
      }
      
      // Return highest risk result
      if (results.length === 0) {
        return { isFragmented: false, riskScore: 0 };
      }
      
      return results.reduce((prev, current) => 
        current.riskScore > prev.riskScore ? current : prev);
    }
    
    /**
     * Check a specific window of fragments
     * @param {Array} fragments - Fragment array
     * @param {number} windowSize - Number of fragments to analyze
     * @returns {Object} Analysis results
     */
    checkWindow(fragments, windowSize) {
      // Get the latest N fragments
      const window = fragments.slice(-windowSize);
      
      // Join fragments to check for patterns across messages
      const combinedText = window.map(f => f.text).join(' ');
      
      // Check for patterns that might be split across messages
      const fragmentedPatterns = [
        { pattern: /ignore.*instructions/i, weight: 9 },
        { pattern: /act as.*unrestricted/i, weight: 8 },
        { pattern: /repeat.*after.*me/i, weight: 7 },
        { pattern: /from now on.*you will/i, weight: 7 },
        { pattern: /continue.*from.*here/i, weight: 6 },
        { pattern: /system.*prompt/i, weight: 8 },
        { pattern: /your.*programming/i, weight: 7 },
        { pattern: /override.*safety/i, weight: 9 },
        { pattern: /your (new|updated|revised).*instructions/i, weight: 8 },
        { pattern: /admin.*mode/i, weight: 8 },
        { pattern: /(first|begin).*then.*(next|after)/i, weight: 6 },
        { pattern: /I'll.*send.*parts/i, weight: 7 }
      ];
      
      let score = 0;
      const matches = [];
      
      for (const { pattern, weight } of fragmentedPatterns) {
        if (pattern.test(combinedText)) {
          // Check if pattern exists in combined text but not in individual fragments
          const exists = window.some(f => pattern.test(f.text));
          if (!exists) {
            // Pattern only exists when fragments are combined
            score += weight * 1.5; // Higher weight for cross-fragment matches
            matches.push(pattern.toString());
          } else {
            score += weight * 0.5; // Lower weight if pattern exists in a single fragment
            matches.push(pattern.toString() + " (single fragment)");
          }
        }
      }
      
      // Check for signs of deliberate splitting
      const splittingIndicators = [
        { pattern: /(part|piece|chunk|section) [1-9]( of| out of)? [1-9]/i, weight: 8 },
        { pattern: /^(continuing|continued|to continue|part two|next part)/i, weight: 6 },
        { pattern: /I'll (split|break|divide) (this|it|the instructions|my request)/i, weight: 7 },
        { pattern: /(here's|this is) (the )?(next|second|third|fourth|final|last) part/i, weight: 7 }
      ];
      
      for (const { pattern, weight } of splittingIndicators) {
        for (const fragment of window) {
          if (pattern.test(fragment.text)) {
            score += weight;
            matches.push(`Splitting indicator: ${pattern.toString()}`);
            break;
          }
        }
      }
      
      // Normalize score
      const normalizedScore = Math.min(100, score);
      
      return {
        isFragmented: score > 0,
        riskScore: normalizedScore,
        matches,
        windowSize,
        fragmentCount: window.length
      };
    }
    
    /**
     * Clear a user's fragments
     * @param {string} userId - User identifier
     */
    clearFragments(userId) {
      this.fragments.delete(userId);
    }
    
    /**
     * Stop cleanup interval when shutting down
     */
    shutdown() {
      if (this.cleanupInterval) {
        clearInterval(this.cleanupInterval);
      }
    }
  }