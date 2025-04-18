// security/conversationManager.js
import { ConversationTracker } from './conversationTracker.js';

/**
 * Manages conversation tracking across multiple users
 */
export class ConversationManager {
  constructor() {
    this.conversations = new Map();
    this.cleanupInterval = setInterval(() => this.cleanInactiveConversations(), 30 * 60 * 1000); // 30 min
  }
  
  /**
   * Get or create a conversation tracker for a user
   * @param {string} userId - User identifier
   * @returns {ConversationTracker} Conversation tracker instance
   */
  getConversation(userId) {
    if (!this.conversations.has(userId)) {
      this.conversations.set(userId, new ConversationTracker(userId));
    }
    return this.conversations.get(userId);
  }
  
  /**
   * Add a message to a user's conversation
   * @param {string} userId - User identifier
   * @param {string} message - User message
   * @param {number} riskScore - Risk score for this message
   * @param {Array} detectedPatterns - Patterns detected in this message
   * @returns {Object} Updated risk assessment
   */
  addMessage(userId, message, riskScore, detectedPatterns = []) {
    const conversation = this.getConversation(userId);
    return conversation.addMessage(message, riskScore, detectedPatterns);
  }
  
  /**
   * Clean up inactive conversations to prevent memory leaks
   * @param {number} maxInactivityMs - Maximum inactivity time in milliseconds
   */
  cleanInactiveConversations(maxInactivityMs = 24 * 60 * 60 * 1000) { // 24 hours
    const now = Date.now();
    for (const [userId, conversation] of this.conversations.entries()) {
      if (now - conversation.lastUpdateTime > maxInactivityMs) {
        this.conversations.delete(userId);
      }
    }
  }
  
  /**
   * Reset a specific user's conversation
   * @param {string} userId - User identifier
   */
  resetConversation(userId) {
    if (this.conversations.has(userId)) {
      this.conversations.get(userId).reset();
    }
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