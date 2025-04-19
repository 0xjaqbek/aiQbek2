// In server/middleware/error-handler.js
import { getSecurityMessage } from '../client/src/security/utils.js';
import { enhancedLogSecurityEvent } from '../utils/logging.js';

export const errorHandler = (err, req, res, next) => {
  // Log the error
  console.error('Unhandled error:', err);
  
  // Get user ID for logging
  const ip = req.ip || req.socket.remoteAddress;
  const userId = req.headers['x-user-id'] || ip;
  
  // Log as server error
  enhancedLogSecurityEvent('serverError', null, {
    userId,
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method
  });
  
  // Handle timeout errors specifically
  if (err.code === 'ETIMEDOUT' || err.code === 'ECONNABORTED' || err.message.includes('timeout')) {
    return res.status(504).json({ 
      error: 'Request timeout', 
      details: getSecurityMessage('timeout', 5),
      isSecurityThreat: true,
      riskScore: 50
    });
  }
  
  // Default error response - updated to include security properties
  return res.status(500).json({ 
    error: 'Błąd serwera', 
    details: getSecurityMessage('serverError', 8),
    isSecurityThreat: true,
    riskScore: 80 // Higher risk score for server errors
  });
};