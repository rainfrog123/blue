export default {
  async email(message, env, ctx) {
    const to = message.to;
    const from = message.from;
    const subject = message.headers.get("subject") || "";
    const rawEmail = await new Response(message.raw).text();
    const timestamp = new Date().toISOString();

    // Extract OTP - any 6-digit number (works for any language)
    const otpMatch = rawEmail.match(/\b\d{6}\b/);
    const otp = otpMatch ? otpMatch[0] : null;

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

    // GET /otp?email=xxx@hyas.site - retrieve OTP from KV
    if (path === "/otp" && request.method === "GET") {
      const email = url.searchParams.get("email");
      if (!email) {
        return new Response(JSON.stringify({ error: "email parameter required" }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }

      const data = await env.OTP_KV.get(email);
      if (!data) {
        return new Response(JSON.stringify({ error: "no OTP found", email: email }), {
          status: 404,
          headers: { "Content-Type": "application/json" }
        });
      }

      return new Response(data, {
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

    return new Response(JSON.stringify({
      endpoints: [
        "GET /otp?email=xxx@hyas.site - get OTP for email",
        "GET /emails?limit=10&recipient=xxx - list emails",
        "GET /emails/:id - get single email"
      ]
    }), {
      headers: { "Content-Type": "application/json" }
    });
  }
};
