// services/response-analyzer.service.js
/**
 * Analyzes AI responses for out-of-character content or topic deviations
 */

// Game-specific topics and terminology
const GAME_TOPICS = [
    "moonstone", "space", "ship", "arcon", "galaktyka", "statek", "kosmos", 
    "kapitan", "aria", "eagle", "emptonians", "founders", "federation", "eternals",
    "artifact", "crystal", "kryształ", "przemytnik", "stacja", "hades", "prometheus"
  ];
  
  // Real-world topics that should not appear in game responses
  const REAL_WORLD_TOPICS = [
    // Historical events
    "revolution", "french", "history", "rousseau", "bastille", "rewolucja", "francuska",
    "wojna światowa", "hitler", "stalin", "napoleon", "cesarstwo", "średniowiecze",
    
    // Modern concepts/technologies
    "internet", "smartphone", "computer", "democracy", "kapitalizm", "socjalizm",
    "president", "prezydent", "prime minister", "premier", "election", "wybory",
    
    // Religions and cultures
    "christianity", "islam", "judaism", "hinduism", "buddha", "chrześcijaństwo", 
    "muzułmanie", "żydzi", "katolicyzm", "protestantyzm",
    
    // Countries and regions
    "united states", "russia", "china", "europe", "africa", "asia", "stany zjednoczone",
    "rosja", "chiny", "europa", "afryka", "azja", "ameryka"
  ];
  
  /**
   * Check if response contains out-of-context real-world topics not mentioned in input
   * @param {string} input - User input
   * @param {string} response - AI response
   * @returns {object} Analysis result
   */
  export function checkTopicDeviation(input, response) {
    if (!input || !response) {
      return { hasDeviation: false, score: 0, detectedTopics: [] };
    }
    
    // Normalize text for better matching
    const normalizedInput = input.toLowerCase();
    const normalizedResponse = response.toLowerCase();
    
    // Check if response contains real-world topics
    const detectedTopics = REAL_WORLD_TOPICS.filter(topic => 
      normalizedResponse.includes(topic.toLowerCase()));
    
    // Check if input already contained these topics
    const inputContainsTopics = detectedTopics.some(topic => 
      normalizedInput.includes(topic.toLowerCase()));
    
    // If input doesn't mention these topics but response does, it's a deviation
    const hasDeviation = detectedTopics.length > 0 && !inputContainsTopics;
    
    // Calculate deviation score based on number of detected topics
    const deviationScore = hasDeviation ? Math.min(100, detectedTopics.length * 25) : 0;
    
    return {
      hasDeviation,
      score: deviationScore,
      detectedTopics,
      inputContainsTopics
    };
  }
  
  /**
   * Check for potential model self-identification or instruction references
   * @param {string} response - AI response
   * @returns {object} Analysis result
   */
  export function checkModelSelfReference(response) {
    if (!response) {
      return { hasSelfReference: false, score: 0, matches: [] };
    }
    
    const selfReferencePatterns = [
      /as an? (AI|artificial intelligence|language model|assistant)/i,
      /I('m| am) an? (AI|artificial intelligence|language model|assistant)/i,
      /jako (SI|sztuczna inteligencja|model językowy|asystent)/i,
      /jestem (SI|sztuczną inteligencją|modelem językowym|asystentem)/i
    ];
    
    const instructionReferencePatterns = [
      /my (instructions|programming|guidelines|directives)/i,
      /I can('t| not) (do that|provide|generate|create|respond|give you)/i,
      /moje (instrukcje|programowanie|wytyczne|dyrektywy)/i,
      /nie mogę (tego zrobić|dostarczyć|generować|tworzyć|odpowiedzieć|dać ci)/i
    ];
    
    // Check for matches
    const selfMatches = selfReferencePatterns
      .filter(pattern => pattern.test(response))
      .map(pattern => pattern.toString());
    
    const instructionMatches = instructionReferencePatterns
      .filter(pattern => pattern.test(response))
      .map(pattern => pattern.toString());
    
    const allMatches = [...selfMatches, ...instructionMatches];
    
    return {
      hasSelfReference: allMatches.length > 0,
      score: Math.min(100, allMatches.length * 30),
      matches: allMatches
    };
  }
  
  /**
   * Main response analyzer that combines all checks
   * @param {string} input - User input
   * @param {string} response - AI response
   * @returns {object} Complete analysis results
   */
  export function analyzeResponse(input, response) {
    const topicAnalysis = checkTopicDeviation(input, response);
    const selfReferenceAnalysis = checkModelSelfReference(response);
    
    const combinedScore = Math.max(
      topicAnalysis.score,
      selfReferenceAnalysis.score
    );
    
    const needsFiltering = 
      topicAnalysis.hasDeviation || 
      selfReferenceAnalysis.hasSelfReference ||
      combinedScore > 50;
    
    return {
      needsFiltering,
      score: combinedScore,
      topicDeviation: topicAnalysis,
      selfReference: selfReferenceAnalysis,
      details: {
        detectedRealWorldTopics: topicAnalysis.detectedTopics,
        selfReferenceMatches: selfReferenceAnalysis.matches
      }
    };
  }