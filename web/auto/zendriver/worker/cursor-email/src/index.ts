import PostalMime from 'postal-mime';

interface Env {
  CODES: KVNamespace;
}

interface VerificationCode {
  code: string;
  service: string;
  email: string;
  subject: string;
  timestamp: number;
  expiresAt: number;
}

// Patterns to extract verification codes from various services
const CODE_PATTERNS: { service: string; pattern: RegExp; expiryMinutes: number }[] = [
  // Cursor - "Your one-time code is: 706660"
  { service: 'cursor', pattern: /one-time code is[:\s]*(\d{6})/i, expiryMinutes: 10 },
  // Generic 6-digit OTP
  { service: 'generic', pattern: /(?:code|otp|verification)[:\s]*(\d{6})/i, expiryMinutes: 10 },
  // Generic 4-digit OTP
  { service: 'generic-4', pattern: /(?:code|otp|pin)[:\s]*(\d{4})/i, expiryMinutes: 10 },
];

function extractCode(text: string, subject: string): { code: string; service: string; expiryMinutes: number } | null {
  // Check subject first for service hints
  const lowerSubject = subject.toLowerCase();
  
  for (const { service, pattern, expiryMinutes } of CODE_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      return { code: match[1], service, expiryMinutes };
    }
  }
  
  // Fallback: find any standalone 6-digit number
  const fallbackMatch = text.match(/\b(\d{6})\b/);
  if (fallbackMatch) {
    return { code: fallbackMatch[1], service: 'unknown', expiryMinutes: 10 };
  }
  
  return null;
}

export default {
  // Handle incoming emails
  async email(message: EmailMessage, env: Env, ctx: ExecutionContext): Promise<void> {
    const parser = new PostalMime();
    const rawEmail = await new Response(message.raw).arrayBuffer();
    const parsed = await parser.parse(rawEmail);
    
    const text = parsed.text || parsed.html || '';
    const subject = parsed.subject || '';
    const to = message.to;
    const from = message.from;
    
    console.log(`📧 Email from: ${from} to: ${to}`);
    console.log(`📧 Subject: ${subject}`);
    
    const extracted = extractCode(text, subject);
    
    if (extracted) {
      const now = Date.now();
      const verificationCode: VerificationCode = {
        code: extracted.code,
        service: extracted.service,
        email: to,
        subject: subject,
        timestamp: now,
        expiresAt: now + (extracted.expiryMinutes * 60 * 1000),
      };
      
      // Store by email address (latest code)
      await env.CODES.put(`email:${to}`, JSON.stringify(verificationCode), {
        expirationTtl: extracted.expiryMinutes * 60,
      });
      
      // Also store by email:service for specific lookups
      await env.CODES.put(`${to}:${extracted.service}`, JSON.stringify(verificationCode), {
        expirationTtl: extracted.expiryMinutes * 60,
      });
      
      console.log(`✅ Stored code ${extracted.code} for ${to} (${extracted.service})`);
    } else {
      console.log(`⚠️ No verification code found in email`);
    }
  },

  // HTTP API to retrieve codes
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    
    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };
    
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }
    
    // GET /code?email=xxx@example.com
    if (path === '/code' && request.method === 'GET') {
      const email = url.searchParams.get('email');
      const service = url.searchParams.get('service');
      
      if (!email) {
        return new Response(JSON.stringify({ error: 'email parameter required' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }
      
      const key = service ? `${email}:${service}` : `email:${email}`;
      const stored = await env.CODES.get(key);
      
      if (!stored) {
        return new Response(JSON.stringify({ error: 'No code found', email, service }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }
      
      const data: VerificationCode = JSON.parse(stored);
      
      // Check if expired
      if (Date.now() > data.expiresAt) {
        await env.CODES.delete(key);
        return new Response(JSON.stringify({ error: 'Code expired' }), {
          status: 410,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }
      
      return new Response(JSON.stringify({
        code: data.code,
        service: data.service,
        email: data.email,
        expiresIn: Math.floor((data.expiresAt - Date.now()) / 1000),
      }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }
    
    // GET /health
    if (path === '/health') {
      return new Response(JSON.stringify({ status: 'ok', timestamp: Date.now() }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }
    
    // POST /code - manually add a code (for testing)
    if (path === '/code' && request.method === 'POST') {
      const body = await request.json() as { email: string; code: string; service?: string };
      
      if (!body.email || !body.code) {
        return new Response(JSON.stringify({ error: 'email and code required' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }
      
      const now = Date.now();
      const verificationCode: VerificationCode = {
        code: body.code,
        service: body.service || 'manual',
        email: body.email,
        subject: 'Manual entry',
        timestamp: now,
        expiresAt: now + (10 * 60 * 1000), // 10 minutes
      };
      
      await env.CODES.put(`email:${body.email}`, JSON.stringify(verificationCode), {
        expirationTtl: 600,
      });
      
      return new Response(JSON.stringify({ success: true, email: body.email }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }
    
    return new Response(JSON.stringify({
      endpoints: [
        'GET /code?email=xxx@example.com[&service=cursor]',
        'POST /code { email, code, service? }',
        'GET /health',
      ],
    }), {
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  },
};
