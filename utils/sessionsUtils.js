// Extract device information from request
export function extractDeviceInfo(req) {
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const ipAddress = req.ip || req.connection.remoteAddress || 'Unknown';
    
    // Parse user agent to get browser and OS info
    let browser = 'Unknown';
    let os = 'Unknown';
    let deviceType = 'Unknown';
    
    // Simple browser detection
    if (userAgent.includes('Chrome')) browser = 'Chrome';
    else if (userAgent.includes('Firefox')) browser = 'Firefox';
    else if (userAgent.includes('Safari')) browser = 'Safari';
    else if (userAgent.includes('Edge')) browser = 'Edge';
    
    // Simple OS detection
    if (userAgent.includes('Windows')) os = 'Windows';
    else if (userAgent.includes('Mac')) os = 'macOS';
    else if (userAgent.includes('Linux')) os = 'Linux';
    else if (userAgent.includes('Android')) os = 'Android';
    else if (userAgent.includes('iOS')) os = 'iOS';
    
    // Device type detection
    if (userAgent.includes('Mobile')) deviceType = 'Mobile';
    else if (userAgent.includes('Tablet')) deviceType = 'Tablet';
    else deviceType = 'Desktop';
    
    return {
      userAgent,
      ipAddress,
      browser,
      os,
      deviceType
    };
  }
  
  // Check if session is still active (within last 24 hours)
  export function isSessionActive(session) {
    if (!session) return false;
    const lastActivity = new Date(session.lastActivity);
    const now = new Date();
    const hoursDiff = (now - lastActivity) / (1000 * 60 * 60);
    return hoursDiff < 24; // Session expires after 24 hours of inactivity
  }
  