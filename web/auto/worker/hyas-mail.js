export default {
  async email(message, env, ctx) {
    const to = message.to;
    const from = message.from;
    const subject = message.headers.get("subject") || "";
    const rawEmail = await new Response(message.raw).text();
    const timestamp = new Date().toISOString();

    // Extract OTP - look for specific patterns like "code is 123456"
    // Try specific patterns first (most reliable)
    let otp = null;
    
    // Pattern 1: "code is 123456" or "code is: 123456"
    const codeIsMatch = rawEmail.match(/code\s+is[:\s]+(\d{6})/i);
    if (codeIsMatch) {
      otp = codeIsMatch[1];
    }
    
    // Pattern 2: "one-time code: 123456"
    if (!otp) {
      const otcMatch = rawEmail.match(/one-time\s+code[:\s]+(\d{6})/i);
      if (otcMatch) otp = otcMatch[1];
    }
    
    // Pattern 3: "verification code: 123456"
    if (!otp) {
      const vcMatch = rawEmail.match(/verification\s+code[:\s]+(\d{6})/i);
      if (vcMatch) otp = vcMatch[1];
    }
    
    // Fallback: first 6-digit number in body after headers
    if (!otp) {
      const bodyStart = rawEmail.indexOf('\n\n');
      const emailBody = bodyStart > 0 ? rawEmail.slice(bodyStart) : rawEmail;
      const fallbackMatch = emailBody.match(/\b\d{6}\b/);
      if (fallbackMatch) otp = fallbackMatch[0];
    }

    // Save OTP to KV (key = email address, expires in 10 minutes)
    if (otp && env.OTP_KV) {
      await env.OTP_KV.put(to, JSON.stringify({
        otp: otp,
        from: from,
        subject: subject,
        timestamp: timestamp
      }), { expirationTtl: 600 });

      console.log(`OTP saved to KV: ${to} -> ${otp}`);
    }

    // Save full email to D1
    if (env.EMAILS_DB) {
      try {
        await env.EMAILS_DB.prepare(
          "INSERT INTO emails (recipient, sender, subject, otp, raw_body, received_at) VALUES (?, ?, ?, ?, ?, ?)"
        ).bind(to, from, subject, otp, rawEmail, timestamp).run();

        console.log(`Email saved to D1: ${to}`);
      } catch (e) {
        console.error(`D1 error: ${e.message}`);
      }
    }

    console.log(JSON.stringify({ to, from, subject, otp, timestamp }));
    message.setReject(false);
  },

  // HTTP endpoint to retrieve OTP
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // GET /otp?email=xxx@hyas.site - retrieve OTP from D1 (more consistent than KV)
    if (path === "/otp" && request.method === "GET") {
      const email = url.searchParams.get("email");
      if (!email) {
        return new Response(JSON.stringify({ error: "email parameter required" }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }

      // Query D1 for the most recent OTP for this email (within last 10 minutes)
      const result = await env.EMAILS_DB.prepare(
        `SELECT otp, sender as "from", subject, received_at as timestamp 
         FROM emails 
         WHERE recipient = ? AND otp IS NOT NULL 
           AND received_at > datetime('now', '-10 minutes')
         ORDER BY id DESC LIMIT 1`
      ).bind(email).first();

      if (!result) {
        return new Response(JSON.stringify({ error: "no OTP found", email: email }), {
          status: 404,
          headers: { "Content-Type": "application/json" }
        });
      }

      return new Response(JSON.stringify(result), {
        headers: { "Content-Type": "application/json" }
      });
    }

    // GET /emails - list recent emails from D1
    if (path === "/emails" && request.method === "GET") {
      const limit = url.searchParams.get("limit") || "10";
      const recipient = url.searchParams.get("recipient");

      let sql = "SELECT id, recipient, sender, subject, otp, received_at FROM emails";
      let params = [];

      if (recipient) {
        sql += " WHERE recipient = ?";
        params.push(recipient);
      }

      sql += " ORDER BY id DESC LIMIT ?";
      params.push(parseInt(limit));

      const result = await env.EMAILS_DB.prepare(sql).bind(...params).all();

      return new Response(JSON.stringify(result.results), {
        headers: { "Content-Type": "application/json" }
      });
    }

    // GET /emails/:id - get single email with full body
    if (path.startsWith("/emails/") && request.method === "GET") {
      const id = path.split("/")[2];
      const result = await env.EMAILS_DB.prepare(
        "SELECT * FROM emails WHERE id = ?"
      ).bind(parseInt(id)).first();

      if (!result) {
        return new Response(JSON.stringify({ error: "email not found" }), {
          status: 404,
          headers: { "Content-Type": "application/json" }
        });
      }

      return new Response(JSON.stringify(result), {
        headers: { "Content-Type": "application/json" }
      });
    }

    // POST /send - send email via Cloudflare Email Routing
    if (path === "/send" && request.method === "POST") {
      try {
        const body = await request.json();
        const { from, to, subject, text, html } = body;

        if (!from || !to || !subject || (!text && !html)) {
          return new Response(JSON.stringify({ 
            error: "Missing required fields: from, to, subject, and text or html" 
          }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
          });
        }

        if (!env.SEND_EMAIL) {
          return new Response(JSON.stringify({ 
            error: "Email sending not configured. Add send_email binding to wrangler.toml" 
          }), {
            status: 500,
            headers: { "Content-Type": "application/json" }
          });
        }

        const contentType = html ? "text/html" : "text/plain";
        const content = html || text;
        
        const msg = new EmailMessage(from, to, 
          `Subject: ${subject}\r\nContent-Type: ${contentType}; charset=utf-8\r\n\r\n${content}`
        );
        
        await env.SEND_EMAIL.send(msg);
        
        return new Response(JSON.stringify({ success: true, message: "Email sent" }), {
          headers: { "Content-Type": "application/json" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }
    }

    return new Response(JSON.stringify({
      endpoints: [
        "GET /otp?email=xxx@hyas.site - get OTP for email",
        "GET /emails?limit=10&recipient=xxx - list emails",
        "GET /emails/:id - get single email",
        "POST /send - send email (json: from, to, subject, text/html)"
      ]
    }), {
      headers: { "Content-Type": "application/json" }
    });
  }
};
