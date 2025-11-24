const fetch = require('node-fetch');

class ScanService {
  
  // Instant security checks
  instantCheck(url) {
    let score = 0;
    let flags = [];
    
    // 1. HTTPS check
    if (url.startsWith('https://')) {
      score += 20;
    } else {
      flags.push('Missing HTTPS encryption');
    }
    
    // 2. Suspicious TLD
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'];
    const hasSuspiciousTLD = suspiciousTLDs.some(tld => url.includes(tld));
    if (!hasSuspiciousTLD) {
      score += 20;
    } else {
      flags.push('Suspicious domain extension');
    }
    
    // 3. IP address check
    const hasIP = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url);
    if (!hasIP) {
      score += 15;
    } else {
      flags.push('Uses IP address instead of domain');
    }
    
    // 4. Phishing keywords
    const keywords = ['login', 'verify', 'account', 'secure', 'update', 'suspended'];
    const foundKeywords = keywords.filter(kw => url.toLowerCase().includes(kw));
    if (foundKeywords.length <= 1) {
      score += 15;
    } else {
      flags.push(`Suspicious keywords: ${foundKeywords.join(', ')}`);
    }
    
    // 5. URL length
    if (url.length <= 75) {
      score += 15;
    } else {
      flags.push('Unusually long URL');
    }
    
    // 6. Special characters
    const specialChars = (url.match(/[@\-_]/g) || []).length;
    if (specialChars <= 3) {
      score += 15;
    } else {
      flags.push('Too many special characters');
    }
    
    return { score, maxScore: 100, flags };
  }
  
  // Google Safe Browsing check
  async checkGoogleSafeBrowsing(url) {
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
    
    if (!apiKey) {
      console.log('⚠️  No Google API key - skipping check');
      return { safe: true, score: 0 };
    }
    
    try {
      const endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
      
      const response = await fetch(`${endpoint}?key=${apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: {
            clientId: 'phishing-guard',
            clientVersion: '1.0.0'
          },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: url }]
          }
        })
      });
      
      const data = await response.json();
      const matches = data.matches || [];
      
      if (matches.length > 0) {
        return { 
          safe: false, 
          score: 0,
          threat: matches[0].threatType 
        };
      }
      
      return { safe: true, score: 30 };
      
    } catch (error) {
      console.error('Google Safe Browsing error:', error);
      return { safe: true, score: 15 };
    }
  }
  
  // Main scan function
  async scanURL(url) {
    console.log(`🔍 Scanning: ${url}`);
    
    // Step 1: Instant checks
    const instant = this.instantCheck(url);
    
    // Step 2: Google Safe Browsing
    const google = await this.checkGoogleSafeBrowsing(url);
    
    // Calculate final score
    const finalScore = Math.round((instant.score * 0.6) + (google.score * 0.4));
    
    // Determine level
    let level, message;
    if (finalScore >= 80) {
      level = 'safe';
      message = 'This link appears safe to use';
    } else if (finalScore >= 50) {
      level = 'warning';
      message = 'Exercise caution with this link';
    } else {
      level = 'danger';
      message = 'High risk - avoid clicking this link';
    }
    
    // Combine flags
    const allFlags = [...instant.flags];
    if (!google.safe) {
      allFlags.push(`Flagged by Google Safe Browsing: ${google.threat}`);
    }
    
    return {
      url,
      finalScore,
      level,
      message,
      flags: allFlags,
      details: {
        instantScore: instant.score,
        googleScore: google.score
      }
    };
  }
}

module.exports = new ScanService();