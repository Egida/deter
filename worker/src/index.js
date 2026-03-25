export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    const zoneId = env.TARGET_ZONE_ID;
    const kvBinding = env.KV_NAMESPACE;

    if (!zoneId || !kvBinding) {
      console.error("Worker ERROR: TARGET_ZONE_ID or KV_NAMESPACE binding not configured");
      return fetch(request);
    }

    const kvKey = `attack_status_zone_${zoneId}`;
    let attackStatus = "inactive";

    try {
      const status = await kvBinding.get(kvKey);
      if (status === "active") {
        attackStatus = "active";
      }
    } catch (e) {
      console.error(`Worker ERROR: KV GET failed for key ${kvKey}: ${e}`);
      return fetch(request);
    }

    if (attackStatus !== "active") {
      return fetch(request);
    }

    const powCookie = parseCookie(request.headers.get("Cookie") || "", "deter_pow");
    if (powCookie && await verifyPowToken(powCookie, env.POW_SECRET || "deter-pow-secret")) {
      return fetch(request);
    }

    if (request.method === "POST" && url.pathname === "/__deter/verify") {
      return handleVerification(request, env);
    }

    const difficulty = parseInt(env.POW_DIFFICULTY || "4", 10);
    const nonce = crypto.randomUUID();
    const timestamp = Math.floor(Date.now() / 1000);
    const challengeData = `${nonce}:${timestamp}`;

    return new Response(generateChallengeHtml(challengeData, difficulty), {
      status: 403,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
      },
    });
  },
};

async function handleVerification(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response("Invalid request", { status: 400 });
  }

  const { challenge, counter, hash } = body;
  if (!challenge || counter === undefined || !hash) {
    return new Response("Missing fields", { status: 400 });
  }

  const parts = challenge.split(":");
  if (parts.length !== 2) {
    return new Response("Invalid challenge", { status: 400 });
  }

  const timestamp = parseInt(parts[1], 10);
  const now = Math.floor(Date.now() / 1000);
  if (now - timestamp > 300) {
    return new Response("Challenge expired", { status: 403 });
  }

  const difficulty = parseInt(env.POW_DIFFICULTY || "4", 10);
  const input = `${challenge}:${counter}`;
  const computed = await sha256Hex(input);

  if (computed !== hash) {
    return new Response("Hash mismatch", { status: 403 });
  }

  if (!computed.startsWith("0".repeat(difficulty))) {
    return new Response("Insufficient difficulty", { status: 403 });
  }

  const token = await createPowToken(env.POW_SECRET || "deter-pow-secret");

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": `deter_pow=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`,
    },
  });
}

async function sha256Hex(message) {
  const data = new TextEncoder().encode(message);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function createPowToken(secret) {
  const expires = Math.floor(Date.now() / 1000) + 3600;
  const payload = `pow:${expires}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  const sigHex = Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `${payload}:${sigHex}`;
}

async function verifyPowToken(token, secret) {
  const parts = token.split(":");
  if (parts.length !== 3) return false;

  const [prefix, expiresStr, sigHex] = parts;
  if (prefix !== "pow") return false;

  const expires = parseInt(expiresStr, 10);
  if (isNaN(expires) || Math.floor(Date.now() / 1000) > expires) return false;

  const payload = `${prefix}:${expiresStr}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const sigBuf = new Uint8Array(sigHex.match(/.{2}/g).map((b) => parseInt(b, 16)));
  return crypto.subtle.verify("HMAC", key, sigBuf, new TextEncoder().encode(payload));
}

function parseCookie(cookieHeader, name) {
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? match[1] : null;
}

function generateChallengeHtml(challenge, difficulty) {
  return `<!DOCTYPE html>
<html>
<head>
    <title>Verifying Connection</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
      * { margin: 0; padding: 0; box-sizing: border-box; }
      body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
             display: flex; align-items: center; justify-content: center;
             min-height: 100vh; background: #f5f5f5; color: #333; }
      .card { background: #fff; border-radius: 8px; padding: 2rem; max-width: 400px;
              width: 90%; box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }
      h1 { font-size: 1.25rem; margin-bottom: 1rem; }
      #status { color: #666; margin-bottom: 1rem; font-size: 0.9rem; }
      progress { width: 100%; height: 6px; border-radius: 3px; appearance: none; }
      progress::-webkit-progress-bar { background: #eee; border-radius: 3px; }
      progress::-webkit-progress-value { background: #4a90d9; border-radius: 3px; }
      .error { color: #c0392b; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Verifying your connection</h1>
        <p id="status">Starting security check...</p>
        <progress id="progress" max="100" value="0"></progress>
    </div>
    <script>
      const CHALLENGE = "${challenge}";
      const DIFFICULTY = ${difficulty};
      const TARGET = "0".repeat(DIFFICULTY);

      async function sha256(msg) {
        const buf = await crypto.subtle.digest("SHA-256",
          new TextEncoder().encode(msg));
        return Array.from(new Uint8Array(buf))
          .map(b => b.toString(16).padStart(2, "0")).join("");
      }

      async function solve() {
        const status = document.getElementById("status");
        const progress = document.getElementById("progress");
        status.textContent = "Computing proof of work...";

        let counter = 0;
        const batchSize = 500;
        const maxIterations = 50_000_000;

        while (counter < maxIterations) {
          for (let i = 0; i < batchSize; i++) {
            const input = CHALLENGE + ":" + counter;
            const hash = await sha256(input);
            if (hash.startsWith(TARGET)) {
              status.textContent = "Verified. Redirecting...";
              progress.value = 100;

              const res = await fetch("/__deter/verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ challenge: CHALLENGE, counter, hash }),
              });

              if (res.ok) {
                window.location.reload();
                return;
              }
              status.textContent = "Verification rejected. Please reload.";
              status.className = "error";
              return;
            }
            counter++;
          }
          progress.value = Math.min(95, (counter / 100000) * 100);
          await new Promise(r => setTimeout(r, 0));
        }

        status.textContent = "Verification timed out. Please reload.";
        status.className = "error";
      }

      solve();
    </script>
</body>
</html>`;
}
