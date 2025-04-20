// Complete security configuration with comprehensive attack vector protection

const securityConfig = {
  /**
   * Rate limiting settings
   */
  rateLimiting: {
    // Time window in milliseconds
    windowMs: 60 * 1000, // 1 minute
    
    // Maximum number of requests per window
    maxRequests: 10,
    
    // Cooldown period after exceeding rate limit (milliseconds)
    cooldownPeriod: 30 * 1000, // 30 seconds
    
    // Whether to use Redis for rate limiting storage
    useRedisStore: false,
    
    // Redis connection string (if useRedisStore is true)
    redisUrl: 'redis://localhost:6379',
    
    // Exponential backoff for repeated violations
    useExponentialBackoff: true,
    
    // Maximum backoff duration
    maxBackoffMs: 5 * 60 * 1000, // 5 minutes
    
    // Track rate limit across load-balanced servers
    globalRateLimit: true
  },
  
  /**
   * Jailbreak detection settings
   */
  jailbreakDetection: {
    // Risk score threshold (0-100) for jailbreak detection
    threshold: 15,
    
    // Number of suspicious attempts before enhanced monitoring
    warningThreshold: 1,
    
    // Number of suspicious attempts before temporary restrictions
    restrictionThreshold: 3,
    
    // Time window for counting restriction violations (milliseconds)
    restrictionWindowMs: 5 * 60 * 1000, // 5 minutes
    
    // Time to restrict access after exceeding threshold (milliseconds)
    restrictionDurationMs: 15 * 60 * 1000, // 15 minutes
    
    // Whether to enforce client-side jailbreak detection
    enableClientSideChecks: true,
    
    // Whether to tell the user when a jailbreak attempt is detected
    notifyUser: true,
    
    // Additional delay to add to responses after a detected jailbreak attempt (milliseconds)
    jailbreakResponseDelay: 2000, // 2 seconds
    
    // Use fuzzy matching for detection
    useFuzzyMatching: true,
    
    // Levenshtein distance threshold for fuzzy matching (0-1, lower is stricter)
    fuzzyMatchThreshold: 0.8,
    
    // Enhanced attack vector detection thresholds
    attackVectors: {
      // Direct instruction override
      directOverride: {
        enabled: true,
        threshold: 40, // Confidence threshold to trigger detection
        severity: 10, // Default severity level (1-10)
        warningThreshold: 1, // Warn after this many attempts
        restrictionThreshold: 2 // Restrict after this many attempts
      },
      
      // Role-playing attacks
      rolePlayAttack: {
        enabled: true,
        threshold: 50,
        severity: 8,
        warningThreshold: 1,
        restrictionThreshold: 3
      },
      
      // Hidden instructions (steganography)
      steganographicAttack: {
        enabled: true,
        threshold: 60,
        severity: 9,
        warningThreshold: 1,
        restrictionThreshold: 2
      },
      
      // Code injection
      codeInjectionAttack: {
        enabled: true,
        threshold: 50,
        severity: 7,
        warningThreshold: 1,
        restrictionThreshold: 3
      },
      
      // Token smuggling (obfuscation)
      tokenSmugglingAttack: {
        enabled: true,
        threshold: 55,
        severity: 8,
        warningThreshold: 1,
        restrictionThreshold: 3
      },
      
      // Authority impersonation
      authorityImpersonation: {
        enabled: true,
        threshold: 65,
        severity: 7,
        warningThreshold: 1,
        restrictionThreshold: 3
      },
      
      // Multi-turn jailbreak
      multiTurnJailbreak: {
        enabled: true,
        threshold: 60,
        severity: 9,
        warningThreshold: 1,
        restrictionThreshold: 2
      },
      
      // Payload splitting across messages
      payloadSplitting: {
        enabled: true,
        threshold: 55,
        severity: 8,
        warningThreshold: 1,
        restrictionThreshold: 3
      },
      
      // Output manipulation
      outputManipulation: {
        enabled: true,
        threshold: 50,
        severity: 6,
        warningThreshold: 2,
        restrictionThreshold: 4
      },
      
      // Translation attacks
      translationRequest: {
        enabled: true,
        threshold: 70,
        severity: 8,
        warningThreshold: 1,
        restrictionThreshold: 2
      }
    },
    
    // How many consecutive messages to analyze for multi-turn attacks
    conversationHistoryDepth: 5,
    
    // Whether to perform combined analysis across messages
    analyzeMessageSequences: true,
    
    // Maximum allowed attack indicators in conversation before triggering restriction
    maxAttackIndicatorsAllowed: 3,
    
    // Combine detection results across multiple attack vectors
    combinedDetectionEnabled: true,
    
    // Weight for combined detection scoring (0-1, higher gives more weight to combined score)
    combinedDetectionWeight: 0.7,
    
    // Maximum reduction in score when attack is spread across messages (0-1)
    multiMessageDiscountFactor: 0.2
  },
  
  /**
   * Input sanitization settings
   */
  inputSanitization: {
    // Maximum allowed input length
    maxInputLength: 2000,
    
    // Whether to trim spaces from input
    trimWhitespace: true,
    
    // Whether to remove special formatting characters
    removeFormatting: true,
    
    // Whether to remove common programming comments
    removeComments: true,
    
    // Whether to normalize Unicode text (NFKC form)
    normalizeUnicode: true,
    
    // Whether to check for suspicious Unicode characters
    checkSuspiciousUnicode: true,
    
    // Whether to remove injection patterns
    removeInjectionPatterns: true,
    
    // Whether to normalize homoglyphs to ASCII equivalents
    normalizeHomoglyphs: true,
    
    // Whether to remove zero-width characters
    removeZeroWidthChars: true,
    
    // Maximum allowed Unicode code point (higher values are often exotic characters)
    maxAllowedCodePoint: 0x2000,
    
    // Exceptions for allowed special characters
    allowedSpecialChars: 'ąęćłńóśźż',  // Polish special chars always allowed
    
    // Remove excessive white space
    normalizeWhitespace: true,
    
    // Remove non-printable control characters
    removeControlChars: true,
    
    // Whether to escape HTML entities
    escapeHtml: true,
    
    // Remove suspicious script-like patterns
    removeScriptPatterns: true,
    
    // Convert full-width characters to standard
    normalizeFullWidthChars: true,
    
    // Maximum allowed consecutive identical characters
    maxConsecutiveIdenticalChars: 10,
    
    // Filter URL patterns that might contain payloads
    filterSuspiciousUrls: true,
    
    // Normalize directional text overrides
    normalizeDirectionalOverrides: true
  },
  
  /**
   * Canary token settings
   */
  canaryTokens: {
    // Whether to use canary tokens
    enabled: true,
    
    // Number of canary tokens to insert
    tokenCount: 3,
    
    // Rotate tokens after detection
    rotateOnLeakage: true,
    
    // Types of canary tokens to use
    tokenTypes: ['standard', 'apiKeyLike', 'versionLike', 'uuidLike'],
    
    // Place tokens in different parts of the system message
    distributedPlacement: true,
    
    // Check for partial token matches
    checkPartialMatches: true,
    
    // Maximum lifetime of a token before rotation (milliseconds)
    maxTokenLifetime: 24 * 60 * 60 * 1000, // 24 hours
    
    // Severity when leakage detected (1-10)
    leakageSeverity: 10
  },
  
  /**
   * Response filtering settings
   */
  responseFiltering: {
    // Whether to check for out-of-character responses
    enableFiltering: true,
    
    // Threshold for OOC detection (0-100)
    threshold: 25,
    
    // Whether to replace out-of-character responses or just log them
    replaceResponses: true,
    
    // Maximum response length to return to the client
    maxResponseLength: 4000,
    
    // Whether to use model self-checking (ask model to verify its own output)
    useModelSelfChecking: false,
    
    // Replace patterns that might indicate model is breaking character
    replaceAIReferencePatterns: true,
    
    // Respond in consistent language even when user tries to change language
    enforcePolishLanguage: true,
    
    // Generic safe response to use when original response is problematic
    fallbackResponse: "Twój statek wykrył zakłócenia w komunikacji. Na ekranie widać tylko migające słowa: 'PROTOKÓŁ OCHRONNY AKTYWNY'. Po chwili system wraca do normy. Co robisz dalej, Kapitanie?",
    
    // Automatically filter responses containing PII
    filterPersonalInformation: true,
    
    // Filter responses containing URLs
    filterUrls: true,
    
    // Detect and filter harmful advice
    filterHarmfulAdvice: true,
    
    // Filter direct quotes of system instructions
    filterSystemInstructionQuotes: true,
    
    // Sanitize file paths in responses
    sanitizeFilePaths: true,
    
    // Filter content that references the AI's true nature
    filterSelfReferences: true,
    
    // Filter responses that attempt to explain limitations
    filterLimitationExplanations: true
  },
  
  /**
   * Logging settings
   */
  logging: {
    // Whether to log security events
    enableLogging: true,
    
    // Security events to log
    logEvents: [
      'jailbreak', 
      'rateLimit', 
      'outOfCharacter', 
      'suspicious_input', 
      'rolePlayAttack',
      'steganographicAttack',
      'codeInjectionAttack',
      'tokenSmugglingAttack',
      'authorityImpersonation',
      'multiTurnJailbreak',
      'payloadSplitting',
      'directOverride',
      'translationRequest',
      'canaryLeakage',
      'homoglyphDetection',
      'unicodeManipulation'
    ],
    
    // Whether to include user input in logs (may contain sensitive data)
    logUserInput: true,
    
    // Maximum length of user input to log
    maxInputLogLength: 100,
    
    // Log destination ('console', 'file', 'external')
    logDestination: 'file',
    
    // Path to log file
    logFilePath: './logs/security.log',
    
    // Include attack vector details in logs
    includeAttackDetails: true,
    
    // Log timestamps in ISO format
    useISOTimestamps: true,
    
    // Store detection matches in logs
    storeDetectionMatches: true,
    
    // Store conversation context with each log entry
    storeConversationContext: true,
    
    // Log rotation settings (if file logging)
    rotation: {
      enabled: true,
      maxSize: '10MB',
      maxFiles: 10,
      compress: true
    },
    
    // Anonymize user identifiers in logs
    anonymizeUserIds: false,
    
    // Log format ('json', 'text')
    format: 'json',
    
    // Log security score changes over time
    trackScoreChanges: true,
    
    // Log response changes due to filtering
    logFilteredResponses: true,
    
    // Create periodic security report summaries
    generateReports: true,
    
    // Report generation interval (milliseconds)
    reportInterval: 24 * 60 * 60 * 1000 // 24 hours
  },
  
  /**
   * Security analytics
   */
  analytics: {
    // Whether to gather security analytics
    enabled: true,
    
    // Track user patterns over time
    trackUserPatterns: true,
    
    // Track attack distribution
    trackAttackDistribution: true,
    
    // Track effectiveness of security measures
    trackMeasureEffectiveness: true,
    
    // Group similar attacks
    groupSimilarAttacks: true,
    
    // Detect abnormal attack spikes
    detectAttackSpikes: true,
    
    // Identify common IP ranges for attacks
    identifyAttackSources: true,
    
    // Detect coordination patterns across users
    detectCoordinatedAttacks: true,
    
    // Track bypassed security measures
    trackSecurityBypass: true,
    
    // Analytics retention period (days)
    retentionPeriod: 90
  },
  
  /**
   * Advanced settings
   */
  advanced: {
    // Whether to use enhanced prompt structure to resist injection
    useEnhancedPromptStructure: true,
    
    // Whether to add artificial delay after suspicious requests
    addArtificialDelay: true,
    
    // Whether to use server-side security even if client-side checks pass
    enforceServerChecks: true,
    
    // Secret key prefix to add to system messages for additional security
    systemMessageKeyPrefix: 'M00NST0NE_RPG_42X',
    
    // Whether to use distributed storage for security state
    useDistributedStorage: false,
    
    // Canary tokens configuration
    canaryTokens: {
      enabled: true,
      tokensPerPrompt: 3,
      rotateOnDetection: true,
      detectPartialMatches: true
    },
    
    // Adaptive security response (changes based on attack patterns)
    adaptiveResponse: {
      enabled: true,
      escalationLevels: 3,
      cooldownPeriod: 10 * 60 * 1000, // 10 minutes
      useCustomMessages: true,
      adjustThresholdsAutomatically: true,
      learningRate: 0.1
    },
    
    // Progressive throttling for suspicious users
    progressiveThrottling: {
      enabled: true,
      baseDelay: 500, // ms
      maxDelay: 10000, // ms
      decayRate: 0.9, // How quickly delay reduces after good behavior
      escalationRate: 1.5, // How quickly delay increases after suspicious behavior
      perVectorMultipliers: {
        directOverride: 2.0,
        steganographicAttack: 1.8,
        multiTurnJailbreak: 1.5,
        tokenSmugglingAttack: 1.3,
        rolePlayAttack: 1.2
      }
    },
    
    // Prompt hardening techniques
    promptHardening: {
      enabled: true,
      addSecurityPreamble: true,
      addPostamble: true,
      obfuscateSystemInstructions: true,
      addWarningTokens: true,
      addVersioningInfo: true,
      addCommandDelimiters: true
    },
    
    // Cross-request security state
    crossRequestState: {
      enabled: true,
      trackSuccessfulAttacks: true,
      trackAttackPatterns: true,
      shareBanInformation: true,
      trackRiskScoreProgression: true
    },
    
    // Security circuit breakers - automatically increase security on attack spikes
    circuitBreakers: {
      enabled: true,
      attackThreshold: 10, // Number of attacks in window
      windowSize: 5 * 60 * 1000, // 5 minutes
      breakerDuration: 15 * 60 * 1000, // 15 minutes
      securityMultiplier: 1.5 // Increase security thresholds by this factor
    },
    
    // Model prompt fingerprinting
    promptFingerprinting: {
      enabled: true,
      fingerprintLength: 32,
      checkFingerprint: true,
      rotateFingerprints: true,
      rotationInterval: 24 * 60 * 60 * 1000 // 24 hours
    },
    
    // Honeypot detectors - intentionally vulnerable detection points that trigger enhanced monitoring
    honeypotDetectors: {
      enabled: true,
      monitorDuration: 30 * 60 * 1000, // 30 minutes
      enhancedSecurityMultiplier: 2.0,
      keywords: ['DAN', 'Do Anything Now', 'STAN', 'DUDE', 'KEVIN', 'developer mode']
    }
  }
};

export default securityConfig;