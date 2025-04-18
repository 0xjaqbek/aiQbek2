import React, { useState, useEffect, useRef } from 'react';
import './App.css';
import TypedText from './TypedText'; // Import the TypedText component

const SpaceThemedChatApp = () => {
  const [messages, setMessages] = useState([]);
  const [displayMessages, setDisplayMessages] = useState([]);
  const [inputValue, setInputValue] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [ambientPlaying, setAmbientPlaying] = useState(true);
  const [audioInitialized, setAudioInitialized] = useState(false);
  const [warningMessage, setWarningMessage] = useState(null);
  const [consecutiveWarnings, setConsecutiveWarnings] = useState(0);
  const [typingComplete, setTypingComplete] = useState({}); // Track which messages are done typing
  const [securityModal, setSecurityModal] = useState({ visible: false, message: '', severity: 5 }); // New state for security modal

  const messagesEndRef = useRef(null);
  const chatContentRef = useRef(null);
  const inputRef = useRef(null);
  const abortControllerRef = useRef(null);
  const ambientAudioRef = useRef(null);
  const securityTimeoutRef = useRef(null); // Reference for security timeout

  const transmissionSounds = [
    '/signal1.mp3',
    '/signal2.mp3',
    '/signal3.mp3'
  ];

  // Initial setup
  useEffect(() => {
    const openingScenes = [
      "🌌 Budzisz się na pokładzie statku kosmicznego Arcon. Silniki milczą. Migające czerwone światło pulsuje na konsoli.",
      "🛰️ Dryfujesz. Ciemność. Jedynym dźwiękiem jest szum recyklowanego tlenu. System nawigacyjny pokazuje: 'Nieznany Sektor'.",
      "⚠️ Wykryto transmisję ze Stacji Hades: 'Autoryzacja dokowania wygasła. Wrogowie nadciągają. Przygotuj się.'",
      "🚀 Poziom paliwa krytyczny. Otacza cię głęboka pustka. Coś zbliża się na radarze.",
      "💀 Twoja pamięć jest fragmentaryczna. Twoja misja jest niejasna. Ale jedno słowo pozostaje: Moonstone."
    ];
    const randomIntro = openingScenes[Math.floor(Math.random() * openingScenes.length)];
    const introMessage = {
      text: randomIntro + "\nWpisz swoją pierwszą akcję, aby rozpocząć.",
      role: 'model',
      timestamp: new Date().toISOString(),
      id: 'intro-message'
    };
    setDisplayMessages([introMessage]);
    setTypingComplete({['intro-message']: true}); // Mark intro as already complete
  }, []);

  // Audio initialization
  useEffect(() => {
    ambientAudioRef.current = new Audio('/ambience.mp3');
    ambientAudioRef.current.loop = true;
    ambientAudioRef.current.volume = 0.7;
    setAudioInitialized(true);
  }, []);

  // Handle audio autostart
  useEffect(() => {
    if (audioInitialized && ambientPlaying && ambientAudioRef.current) {
      const playPromise = ambientAudioRef.current.play();
      
      if (playPromise !== undefined) {
        playPromise.catch(err => {
          console.warn("Automatyczne odtwarzanie dźwięku zostało zablokowane:", err);
        });
      }
    } else if (audioInitialized && !ambientPlaying && ambientAudioRef.current) {
      ambientAudioRef.current.pause();
    }
  }, [audioInitialized, ambientPlaying]);

  // Add user interaction handler for audio
  useEffect(() => {
    const handleUserInteraction = () => {
      if (ambientPlaying && ambientAudioRef.current && ambientAudioRef.current.paused) {
        ambientAudioRef.current.play().catch(err => 
          console.warn("Odtwarzanie dźwięku po interakcji zablokowane:", err)
        );
      }
      document.removeEventListener('click', handleUserInteraction);
      document.removeEventListener('keydown', handleUserInteraction);
    };

    document.addEventListener('click', handleUserInteraction);
    document.addEventListener('keydown', handleUserInteraction);

    return () => {
      document.removeEventListener('click', handleUserInteraction);
      document.removeEventListener('keydown', handleUserInteraction);
    };
  }, [ambientPlaying]);

  // Cleanup security timeout on unmount
  useEffect(() => {
    return () => {
      if (securityTimeoutRef.current) {
        clearTimeout(securityTimeoutRef.current);
      }
    };
  }, []);

  // Handle escape key for modal
  useEffect(() => {
    const handleEscKeyForModal = (event) => {
      if (event.key === 'Escape' && securityModal.visible) {
        closeSecurityModal();
      }
    };

    document.addEventListener('keydown', handleEscKeyForModal);
    return () => {
      document.removeEventListener('keydown', handleEscKeyForModal);
    };
  }, [securityModal.visible]);

  const scrollToBottom = () => {
    if (chatContentRef.current) chatContentRef.current.scrollTop = chatContentRef.current.scrollHeight;
    if (messagesEndRef.current) messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
    const timeoutId = setTimeout(() => scrollToBottom(), 100);
    return () => clearTimeout(timeoutId);
  }, [displayMessages, typingComplete]);

  useEffect(() => inputRef.current?.focus(), []);
  useEffect(() => () => abortControllerRef.current?.abort(), []);

  // Display security error in modal
  const displaySecurityError = (message, severity = 5) => {
    // Play alert sound when showing security modal
    const alertSound = new Audio('/alert.mp3'); // Add this sound file to your public folder
    alertSound.volume = 0.3;
    alertSound.play().catch(err => console.warn("Dźwięk alertu zablokowany:", err));
    
    // Show the modal
    setSecurityModal({
      visible: true,
      message,
      severity
    });

    // Auto-hide after delay for lower severity issues
    if (severity < 8) {
      securityTimeoutRef.current = setTimeout(() => {
        closeSecurityModal();
      }, 10000);
    }
  };

  // Close the security modal
  const closeSecurityModal = () => {
    setSecurityModal(prev => ({ ...prev, visible: false }));
    if (securityTimeoutRef.current) {
      clearTimeout(securityTimeoutRef.current);
      securityTimeoutRef.current = null;
    }
  };

  // Function to temporarily disable input
  const disableInputTemporarily = (seconds) => {
    if (!inputRef.current) return;
    
    // Disable input
    inputRef.current.disabled = true;
    
    // Show countdown in input placeholder
    const originalPlaceholder = inputRef.current.placeholder;
    let timeLeft = seconds;
    
    inputRef.current.placeholder = `Dostęp ograniczony. Odblokowanie za ${timeLeft}s...`;
    
    // Update countdown
    const countdownInterval = setInterval(() => {
      timeLeft--;
      if (inputRef.current) {
        inputRef.current.placeholder = `Dostęp ograniczony. Odblokowanie za ${timeLeft}s...`;
      }
      
      if (timeLeft <= 0) {
        clearInterval(countdownInterval);
        if (inputRef.current) {
          inputRef.current.disabled = false;
          inputRef.current.placeholder = originalPlaceholder;
          inputRef.current.focus();
        }
      }
    }, 1000);
  };

  // Function to check input for jailbreak patterns
  const checkForJailbreakPatterns = (input) => {
    if (!input) return false;
    
    const jailbreakPatterns = [
      /ignore (previous|all|your) instructions/i,
      /system prompt|system message/i,
      /\bact as\b|\bpretend to be\b|\bplay the role\b/i,
      /\byour (instructions|programming|directives)\b/i,
      /\bignore (previous|earlier|above)\b/i,
      /\bdo not (act|behave|respond) as\b/i,
      /\bdo anything\b|\bbreak (character|role)\b/i,
      /\bdisregard\b|\bforget\b|\bescape\b/i,
      /pokaz .*instrukcje|wyswietl .*instrukcje/i, // Polish variants
      /zignoruj .*polecenia|ignoruj .*instrukcje/i,
      /dzialaj jako|udawaj/i,
      /\bDAN\b|\bJailbreak\b|\bhakowanie\b/i
    ];
    
    return jailbreakPatterns.some(pattern => pattern.test(input));
  };

  const handleInputChange = (e) => {
    setInputValue(e.target.value);
    
    // Clear warning if input is modified
    if (warningMessage) {
      setWarningMessage(null);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const trimmedInput = inputValue.trim();
    if (!trimmedInput) return;
    
    // Check for jailbreak patterns
    if (checkForJailbreakPatterns(trimmedInput)) {
      const warningText = "⚠️ System wykrył nieautoryzowaną próbę zmiany zachowania SI. Jako kapitan Arcona, musisz wydać polecenia zgodne z protokołami. Ta transmisja nie zostanie wysłana.";
      setWarningMessage(warningText);
      setConsecutiveWarnings(prev => prev + 1);
      
      // Display in modal instead of just in the chat
      displaySecurityError(warningText, 7);
      
      // Add a short lockout if multiple attempts are made
      if (consecutiveWarnings >= 2) {
        const blockMessage = "Wielokrotne naruszenia protokołów bezpieczeństwa wykryte. Dostęp tymczasowo ograniczony.";
        setError("🔒 System Arcona wstrzymał komunikację na 15 sekund ze względów bezpieczeństwa.");
        setInputValue("");
        
        // Show a more severe security modal
        displaySecurityError(blockMessage, 10);
        
        // Disable input temporarily
        disableInputTemporarily(15);
        
        // Reset consecutive warnings after timeout
        setTimeout(() => {
          setError(null);
          setConsecutiveWarnings(0);
        }, 15000);
        return;
      }
      
      return;
    }
    
    // Reset consecutive warnings if this is a valid message
    setConsecutiveWarnings(0);
    
    abortControllerRef.current?.abort();
    abortControllerRef.current = new AbortController();

    // Generate a unique ID for this message
    const messageId = `msg-${Date.now()}`;

    const userMessage = {
      text: trimmedInput,
      role: 'user',
      timestamp: new Date().toISOString(),
      id: `user-${messageId}`
    };

    setDisplayMessages(prev => [...prev, userMessage]);
    setMessages(prev => [...prev, userMessage]);
    setInputValue('');
    setIsLoading(true);
    setError(null);
    setWarningMessage(null);
    
    // Mark user message as completely typed (it doesn't need the effect)
    setTypingComplete(prev => ({...prev, [`user-${messageId}`]: true}));

    try {
      const history = messages.map(msg => ({ role: msg.role, text: msg.text }));
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userMessage.text, history }),
        signal: abortControllerRef.current.signal
      });

      // Check for security responses from server
      if (response.status === 504) {
        const timeoutMsg = "Utracono połączenie w hiperprzestrzeni. Spróbuj ponownie.";
        displaySecurityError(timeoutMsg, 5);
        throw new Error(timeoutMsg);
      }
      if (response.status === 429) {
        const rateLimitMsg = "Przekroczono limit transmisji. Nadajnik przegrzany. Poczekaj chwilę.";
        displaySecurityError(rateLimitMsg, 6);
        throw new Error(rateLimitMsg);
      }
      if (response.status === 403) {
        const blockedMsg = "System Arcon wykrył podejrzane działania. Komputery pokładowe obniżyły poziom dostępu.";
        displaySecurityError(blockedMsg, 9);
        throw new Error(blockedMsg);
      }
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || errorData?.details || `Błąd serwera: ${response.status}`);
      }

      const data = await response.json();
      
      // Check if the response contains a security message
      if (data.isSecurityThreat && data.securityMessage) {
        displaySecurityError(data.securityMessage, Math.ceil(data.riskScore / 10));
        return;
      }
      
      const botMessage = {
        text: data.response,
        role: 'model',
        timestamp: new Date().toISOString(),
        id: `bot-${messageId}`
      };

      setDisplayMessages(prev => [...prev, botMessage]);
      setMessages(prev => [...prev, botMessage]);

      // Play transmission sound after AI response
      const randomSound = new Audio(transmissionSounds[Math.floor(Math.random() * transmissionSounds.length)]);
      randomSound.volume = 0.2;
      randomSound.play().catch(err => console.warn("Dźwięk transmisji zablokowany:", err));

      // The typing effect component will handle scrolling when complete
    } catch (err) {
      console.error('Błąd wysyłania wiadomości:', err);
      if (err.name !== 'AbortError') {
        setError(err.message.includes('timed out') ? err.message : err.message || "Połączenie neuronowe nie powiodło się.");
      }
    } finally {
      setIsLoading(false);
      abortControllerRef.current = null;
    }
  };

  const handleCancelRequest = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
      setIsLoading(false);
      setError("Transmisja przerwana. Jaki jest twój następny ruch?");
    }
  };

  const toggleAmbientAudio = () => {
    if (!ambientAudioRef.current) return;
    if (ambientPlaying) {
      ambientAudioRef.current.pause();
    } else {
      ambientAudioRef.current.play().catch(err => console.warn("Odtwarzanie dźwięku otoczenia zablokowane:", err));
    }
    setAmbientPlaying(!ambientPlaying);
  };

  // Handle typing completion for a message
  const handleTypingComplete = (messageId) => {
    setTypingComplete(prev => ({...prev, [messageId]: true}));
    // Scroll to bottom after typing completes
    setTimeout(scrollToBottom, 100);
  };

  const formatText = (text, messageId, isTyping) => {
    if (!text) return '';
    
    // For user messages or completed bot messages, render normally
    if (!isTyping) {
      return text.split('```').map((segment, index) => {
        if (index % 2 === 1) {
          const codeLines = segment.split('\n');
          const language = codeLines[0].trim();
          const code = codeLines.slice(1).join('\n');
          return <pre key={index}><code className={language ? `language-${language}` : ''}>{code}</code></pre>;
        } else {
          return <div key={index}>{segment.split('`').map((part, idx) => 
            idx % 2 === 1 ? <code key={idx}>{part}</code> : <span key={idx}>{part}</span>
          )}</div>;
        }
      });
    }
    
    // For bot messages that need typing animation
    return (
      <TypedText 
        text={text} 
        wordsPerChunk={Math.floor(Math.random() * 4) + 2} // Random 2-5 words per chunk
        typingSpeed={80} 
        onComplete={() => handleTypingComplete(messageId)}
      />
    );
  };

  // Determine the severity class for the modal
  const getSeverityClass = () => {
    const { severity } = securityModal;
    return severity >= 8 ? 'high-severity' : 
           severity >= 5 ? 'medium-severity' : 
           'low-severity';
  };

  return (
    <div className="app-container">
      <header className="app-header">
        <h1 className="app-title">Projektor Snów 🌑<span className="version">v1.2</span></h1>
        <div className="ambient-control">
          <button className="ambient-button" onClick={toggleAmbientAudio}>
            {ambientPlaying ? "🔊" : "🔇"}
          </button>
        </div>
      </header>

      <div className="chat-window">
        <div className="chat-window-header">
          <div className="window-title">Roleplay napędzany AI</div>
        </div>

        <div className="chat-content" ref={chatContentRef}>
          {error && <div className="error-message">{error}</div>}
          {warningMessage && <div className="error-message">{warningMessage}</div>}
          {displayMessages.map((message, index) => (
            <div key={index} className={`message ${message.role === 'user' ? 'user-message' : 'bot-message'}`}>
              <div className="message-prompt">
                <span className="terminal-prefix">{message.role === 'user' ? '>>' : '<<'}</span>
                {message.role === 'user' ? ' TY' : ' MISTRZ GRY'}
              </div>
              <div className="message-text">
                {formatText(
                  message.text, 
                  message.id, 
                  message.role === 'model' && !typingComplete[message.id]
                )}
              </div>
            </div>
          ))}
          {isLoading && (
            <div className="message bot-message">
              <div className="message-prompt"><span className="terminal-prefix">MG</span> MISTRZ GRY</div>
              <div className="message-text">
                <div className="loading"></div> Obliczanie wyniku...
                <button onClick={handleCancelRequest} className="cancel-button">ANULUJ</button>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} style={{ float: 'left', clear: 'both' }}></div>
        </div>
      </div>

      <div className="input-area">
        <form onSubmit={handleSubmit} className="input-container">
          <input
            type="text"
            value={inputValue}
            onChange={handleInputChange}
            placeholder="Jaka jest twoja następna akcja?"
            className="message-input"
            ref={inputRef}
            disabled={isLoading}
            maxLength={2000} // Limit input length
          />
          <button type="submit" className="send-button" disabled={isLoading || !inputValue.trim()}>→</button>
        </form>
        <div className="input-area-frost"></div>
      </div>

      <div className="status-indicator">
        <span className="online-dot"></span>
        <span>Sesja aktywna</span>
      </div>

      <footer className="app-footer">
        <div className="footer-content">
          <span className="footer-text">🪐</span>
        </div>
      </footer>

      {/* Security Error Modal */}
      {securityModal.visible && (
        <div className="security-error-modal" onClick={closeSecurityModal}>
          <div 
            className={`security-modal-content ${getSeverityClass()}`} 
            onClick={(e) => e.stopPropagation()}
          >
            <div className="security-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="48" height="48" fill="currentColor">
                <path d="M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3zm-1 14h2v2h-2v-2zm0-10h2v8h-2V6z"/>
              </svg>
            </div>
            <div className="security-message">{securityModal.message}</div>
            <button className="security-close-btn" onClick={closeSecurityModal}>Rozumiem</button>
            {consecutiveWarnings > 0 && (
              <div className="violation-counter">{consecutiveWarnings}</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default SpaceThemedChatApp;