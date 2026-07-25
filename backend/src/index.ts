// ==============================================================================
// Project Parewa — Email OTP Authentication Service
// Mock Signal endpoints for self-hosted registration via email verification
// ==============================================================================

import "dotenv/config";
import cors from "cors";
import Redis from "ioredis";
import nodemailer from "nodemailer";
import crypto from "node:crypto";
import http from "http";
import express, { Request, Response, NextFunction } from "express";

// ---- Configuration ----------------------------------------------------------

const PORT = parseInt(process.env.PORT ?? "8080", 10);
const REDIS_URL = process.env.REDIS_URL ?? "redis://localhost:6379";

const SMTP_HOST = process.env.SMTP_HOST ?? "smtp.example.com";
const SMTP_PORT = parseInt(process.env.SMTP_PORT ?? "587", 10);
const SMTP_USER = process.env.SMTP_USER ?? "";
const SMTP_PASS = process.env.SMTP_PASS ?? "";
const SMTP_FROM = process.env.SMTP_FROM ?? "noreply@parewa.local";

const OTP_TTL_SECONDS = 300;       // 5-minute code validity
const RATE_LIMIT_SECONDS = 60;     // 60s cooldown per email

// Redis key prefixes
const KEY_OTP = "parewa:otp:";           // parewa:otp:<email>  → OTP code
const KEY_RATE = "parewa:rate:otp:";     // parewa:rate:otp:<email>  → rate-limit flag

// ---- Redis Client -----------------------------------------------------------

const redis = new Redis(REDIS_URL, {
  maxRetriesPerRequest: 3,
  retryStrategy(times: number) {
    const delay = Math.min(times * 200, 5000);
    console.log(`[redis] Reconnecting in ${delay}ms (attempt ${times})`);
    return delay;
  },
});

redis.on("connect", () => console.log("[redis] Connected"));
redis.on("error", (err) => console.error("[redis] Error:", err.message));

// ---- SMTP Transporter -------------------------------------------------------

const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_PORT === 465,
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASS,
  },
});

// ---- Helpers ----------------------------------------------------------------

/** Generate a cryptographically random 6-digit OTP */
function generateOtp(): string {
  return crypto.randomInt(100_000, 999_999).toString();
}

/** Basic email format validation */
function isValidEmail(email: unknown): email is string {
  if (typeof email !== "string") return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ---- Express App ------------------------------------------------------------

const app = express();
const server = http.createServer(app);

app.use(cors());
app.use(express.json());

// ---- Health Check -----------------------------------------------------------

app.get("/health", (_req: Request, res: Response) => {
  const redisStatus = redis.status === "ready" ? "up" : "down";
  res.status(redisStatus === "up" ? 200 : 503).json({
    status: redisStatus === "up" ? "healthy" : "degraded",
    service: "parewa-auth",
    redis: redisStatus,
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// ==============================================================================
// POST /v1/accounts/sms/code
// Signal-compatible endpoint name — but we send OTP via email instead of SMS.
//
// Body: { "email": "user@example.com" }
//
// Flow:
//   1. Validate email format
//   2. Check 60s per-email rate limit
//   3. Generate 6-digit OTP
//   4. Store OTP in Redis with 300s TTL
//   5. Set rate-limit flag in Redis with 60s TTL
//   6. Send OTP via SMTP
//   7. Return 200 OK
// ==============================================================================

app.post("/v1/accounts/sms/code", async (req: Request, res: Response): Promise<void> => {
  try {
    // Guard: express.json() only parses when Content-Type is application/json.
    // If the header is missing, req.body is undefined → destructuring would fail.
    if (!req.body || typeof req.body !== "object") {
      console.warn("[otp] Empty or unparsed body. Content-Type:", req.headers["content-type"]);
      res.status(400).json({
        error: "Request body is empty. Ensure Content-Type is set to application/json.",
      });
      return;
    }

    const { email } = req.body;

    console.log("[otp] Received request — email:", email, "| Content-Type:", req.headers["content-type"]);

    // 1. Validate
    if (!isValidEmail(email)) {
      res.status(400).json({ error: "Invalid or missing email address" });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();

    // 2. Rate limit check (60s cooldown per email)
    const rateLimitKey = KEY_RATE + normalizedEmail;
    const isRateLimited = await redis.exists(rateLimitKey);

    if (isRateLimited) {
      const ttl = await redis.ttl(rateLimitKey);
      res.status(429).json({
        error: "Too many requests. Please wait before requesting a new code.",
        retryAfterSeconds: ttl > 0 ? ttl : RATE_LIMIT_SECONDS,
      });
      return;
    }

    // 3. Generate OTP
    const otp = generateOtp();

    // 4. Store OTP in Redis with 5-minute TTL
    const otpKey = KEY_OTP + normalizedEmail;
    await redis.set(otpKey, otp, "EX", OTP_TTL_SECONDS);

    // 5. Set rate-limit flag (60s TTL)
    await redis.set(rateLimitKey, "1", "EX", RATE_LIMIT_SECONDS);

    // 6. Send OTP via email
    try {
      await transporter.sendMail({
        from: SMTP_FROM,
        to: normalizedEmail,
        subject: "Project Parewa — Your Verification Code",
        text: [
          "Your verification code for Project Parewa is:",
          "",
          `    ${otp}`,
          "",
          `This code expires in ${OTP_TTL_SECONDS / 60} minutes.`,
          "If you did not request this code, please ignore this email.",
          "",
          "— Project Parewa",
        ].join("\n"),
        html: [
          '<div style="font-family: sans-serif; max-width: 480px; margin: auto; padding: 24px;">',
          '  <h2 style="color: #1a1a2e;">Project Parewa</h2>',
          "  <p>Your verification code is:</p>",
          `  <p style="font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #16213e; `,
          `     background: #f0f0f5; padding: 16px; border-radius: 8px; text-align: center;">`,
          `    ${otp}`,
          "  </p>",
          `  <p style="color: #666;">This code expires in ${OTP_TTL_SECONDS / 60} minutes.</p>`,
          '  <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;" />',
          '  <p style="font-size: 12px; color: #999;">',
          "    If you did not request this code, please ignore this email.",
          "  </p>",
          "</div>",
        ].join("\n"),
      });
    } catch (smtpErr) {
      // Log SMTP failure but don't leak details to client
      console.error("[smtp] Failed to send OTP email:", smtpErr);
      // Clean up the OTP since it wasn't delivered
      await redis.del(otpKey);
      await redis.del(rateLimitKey);
      res.status(502).json({ error: "Failed to send verification email. Please try again." });
      return;
    }

    console.log(`[otp] Code sent to ${normalizedEmail} (expires in ${OTP_TTL_SECONDS}s)`);

    res.status(200).json({
      message: "Verification code sent",
      expiresInSeconds: OTP_TTL_SECONDS,
    });
  } catch (err) {
    console.error("[otp] Unexpected error in /v1/accounts/sms/code:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ==============================================================================
// POST /v1/accounts/code
// Verify the OTP code submitted by the user.
//
// Body: { "email": "user@example.com", "code": "123456" }
//
// Flow:
//   1. Validate email and code format
//   2. Look up stored OTP in Redis
//   3. Compare codes (constant-time)
//   4. Delete OTP key on success
//   5. Return 200 OK or 403 Forbidden
// ==============================================================================

app.post("/v1/accounts/code", async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, code } = req.body;

    // 1. Validate inputs
    if (!isValidEmail(email)) {
      res.status(400).json({ error: "Invalid or missing email address" });
      return;
    }

    if (typeof code !== "string" || !/^\d{6}$/.test(code)) {
      res.status(400).json({ error: "Invalid code format. Expected a 6-digit number." });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const otpKey = KEY_OTP + normalizedEmail;

    // 2. Retrieve stored OTP
    const storedOtp = await redis.get(otpKey);

    if (!storedOtp) {
      res.status(403).json({
        error: "Verification code expired or not found. Please request a new code.",
      });
      return;
    }

    // 3. Constant-time comparison to prevent timing attacks
    const codeBuffer = Buffer.from(code);
    const storedBuffer = Buffer.from(storedOtp);
    const isValid =
      codeBuffer.length === storedBuffer.length &&
      crypto.timingSafeEqual(codeBuffer, storedBuffer);

    if (!isValid) {
      res.status(403).json({ error: "Invalid verification code" });
      return;
    }

    // 4. Delete OTP on successful verification (one-time use)
    await redis.del(otpKey);

    console.log(`[otp] Verified successfully for ${normalizedEmail}`);

    // 5. Return success — check if user already exists (PNI persistence)
    const phoneNumber = req.body.phone_number || null;
    let uuid = null;
    let pni = null;
    let isReRegistration = false;
    let existingUser: any = {};

    // Check by phone number FIRST (Primary Key enforcement)
    if (phoneNumber) {
      uuid = await redis.get(`parewa:phone:${phoneNumber}`);
      if (uuid) {
        console.log(`[otp] Found existing user by Phone Number ${phoneNumber} → UUID: ${uuid}`);
      }
    }
    
    // Fallback to email check if phone number lookup failed (Legacy or Email-only registration)
    if (!uuid) {
      uuid = await redis.get(`parewa:email:${normalizedEmail}`);
      if (uuid && phoneNumber) {
        console.log(`[otp] Upgrading legacy user found by Email ${normalizedEmail} to index new Phone Number ${phoneNumber}`);
      }
    }

    if (uuid) {
      // Returning user — reuse existing UUID and PNI
      const existingUserStr = await redis.get(`parewa:user:${uuid}`);
      if (existingUserStr) {
        existingUser = JSON.parse(existingUserStr);
        pni = existingUser.pni || crypto.randomUUID();
        isReRegistration = true;
        console.log(`[otp] Returning user restored: Phone/Email matched → UUID: ${uuid}, PNI: ${pni}`);
      } else {
        pni = crypto.randomUUID();
      }
    } else {
      // Brand new user — generate fresh UUID and PNI
      uuid = crypto.randomUUID();
      pni = crypto.randomUUID();
      console.log(`[otp] New user created: Phone ${phoneNumber}, Email ${normalizedEmail} → UUID: ${uuid}, PNI: ${pni}`);
    }

    // Preserve existing details, but update core identifiers
    const updatedUser = {
      ...existingUser,
      uuid,
      pni,
      email: normalizedEmail,
      phone_number: phoneNumber || existingUser.phone_number || normalizedEmail
    };
    
    // Store/update in all indexes
    await redis.set(`parewa:user:${uuid}`, JSON.stringify(updatedUser));
    await redis.set(`parewa:email:${normalizedEmail}`, uuid);
    
    // Index the phone number for contact discovery
    if (phoneNumber && phoneNumber !== normalizedEmail) {
      await redis.set(`parewa:phone:${phoneNumber}`, uuid);
      console.log(`[otp] Phone number indexed: ${phoneNumber} → ${uuid}`);
    }

    res.status(200).json({
      uuid: uuid,
      pni: pni,
      storageCapable: false,
      reRegistration: isReRegistration,
      number: phoneNumber || normalizedEmail
    });
  } catch (err) {
    console.error("[otp] Unexpected error in /v1/accounts/code:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ==============================================================================
// POST /v1/verification/session
// Mock endpoint to satisfy Signal client's session requests during PIN/registration flow.
// ==============================================================================

app.post("/v1/verification/session", (_req: Request, res: Response) => {
  console.log("[mock] Mock session created for /v1/verification/session");
  res.status(200).json({
    id: "parewa-mock-session-id",
    nextSms: null,
    nextCall: null,
    nextVerificationAttempt: null,
    allowedToRequestCode: true,
    requestedInformation: [],
    verified: false
  });
});

app.post("/v1/verification/session/:sessionId/code", (_req: Request, res: Response) => {
  console.log("[mock] Mock code request for session");
  res.status(200).json({
    id: "parewa-mock-session-id",
    nextSms: null,
    nextCall: null,
    nextVerificationAttempt: null,
    allowedToRequestCode: true,
    requestedInformation: [],
    verified: false
  });
});

// ==============================================================================
// POST /v1/registration
// Mock endpoint to satisfy Signal client's registration provisioning.
// ==============================================================================

app.post("/v1/registration", (_req: Request, res: Response) => {
  console.log("[mock] Mock account registration");
  res.status(200).json({
    uuid: "11111111-2222-3333-4444-555555555555",
    pni: "66666666-7777-8888-9999-aaaaaaaaaaaa",
    storageCapable: false,
    reregistration: false,
    number: "+1234567890"
  });
});

app.get("/v1/certificate/delivery", (_req: Request, res: Response) => {
  console.log("[mock] Mock certificate delivery");
  res.status(200).json({
    certificate: "mock_certificate"
  });
});

// ==============================================================================
// MOCK PHASE 2 ENDPOINTS (Post-Registration / Profiles / Directory)
// ==============================================================================

app.put("/v1/profile", (_req: Request, res: Response) => {
  console.log("[mock] PUT /v1/profile - Profile update received");
  res.status(200).json({ status: "SUCCESS" });
});

// Helper to get UUID from Basic Auth (or return a fallback for testing)
function getUuidFromAuth(req: Request): string {
  let authHeader = req.headers.authorization;
  if (Array.isArray(authHeader)) authHeader = authHeader[0];

  if (authHeader && authHeader.startsWith("Basic ")) {
    try {
      const b64auth = authHeader.split(" ")[1];
      const [uuid] = Buffer.from(b64auth, "base64").toString().split(":");
      return uuid;
    } catch (e) {
      console.warn("Failed to parse Basic Auth header");
    }
  }
  return "unknown-uuid";
}

app.put("/v2/keys", async (req: Request, res: Response) => {
  try {
    const uuid = getUuidFromAuth(req);
    const deviceId = 1; // Default single-device deployment
    const { identityKey, signedPreKey, preKeys } = req.body;

    console.log(`[keys] PUT /v2/keys - Storing keys for ${uuid} (Device ${deviceId})`);

    // Store main keys in a Redis Hash
    const hashKey = `parewa:keys:${uuid}:${deviceId}`;
    await redis.hset(hashKey, {
      identityKey: typeof identityKey === 'string' ? identityKey : JSON.stringify(identityKey),
      signedPreKey: JSON.stringify(signedPreKey),
      registrationId: req.body.registrationId || 0
    });

    // Store one-time preKeys in a Redis List
    const listKey = `parewa:prekeys:${uuid}:${deviceId}`;
    
    // Clear existing prekeys first
    await redis.del(listKey);
    
    if (Array.isArray(preKeys) && preKeys.length > 0) {
      const preKeyStrings = preKeys.map((pk: any) => JSON.stringify(pk));
      await redis.rpush(listKey, ...preKeyStrings);
      console.log(`[keys] Stored ${preKeys.length} one-time preKeys for ${uuid}`);
    }

    res.status(200).json({ status: "SUCCESS" });
  } catch (error) {
    console.error("[keys] Error storing keys:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/v2/keys/:identifier/:deviceId?", async (req: Request, res: Response) => {
  try {
    const identifier = req.params.identifier as string; // Target user's UUID
    const deviceId = (req.params.deviceId as string) || 1;
    
    console.log(`[keys] GET /v2/keys - Fetching keys for ${identifier} (Device ${deviceId})`);

    const hashKey = `parewa:keys:${identifier}:${deviceId}`;
    const mainKeys = await redis.hgetall(hashKey);

    if (!mainKeys || !mainKeys.identityKey) {
      console.log(`[keys] Keys not found for ${identifier}`);
      return res.status(404).json({ error: "Keys not found" });
    }

    const listKey = `parewa:prekeys:${identifier}:${deviceId}`;
    const preKeyString = await redis.lpop(listKey); // Pop one prekey from the pool
    const preKey = preKeyString ? JSON.parse(preKeyString) : null;

    if (!preKey) {
      console.warn(`[keys] WARNING: PreKey pool exhausted for ${identifier}!`);
    }

    const responsePayload = {
      identityKey: mainKeys.identityKey.startsWith('{') ? JSON.parse(mainKeys.identityKey) : mainKeys.identityKey,
      devices: [
        {
          deviceId: parseInt(deviceId.toString(), 10),
          registrationId: parseInt(mainKeys.registrationId || "0", 10),
          signedPreKey: JSON.parse(mainKeys.signedPreKey || "{}"),
          preKey: preKey
        }
      ]
    };

    res.status(200).json(responsePayload);
  } catch (error) {
    console.error("[keys] Error fetching keys:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.put("/v1/accounts/attributes", (_req: Request, res: Response) => {
  console.log("[mock] PUT /v1/accounts/attributes - Attributes updated");
  res.status(200).json({ status: "SUCCESS" });
});

app.post("/v1/directory/tokens", (_req: Request, res: Response) => {
  console.log("[mock] POST /v1/directory/tokens - Directory search mocked");
  res.status(200).json({ results: [] }); // Return empty matches for now
});

app.post("/v1/directory/parewa", async (req: Request, res: Response) => {
  console.log("[directory] POST /v1/directory/parewa");
  try {
    const numbers: string[] = req.body.numbers || [];
    const results: Record<string, any> = {};
    
    for (let num of numbers) {
      // Ensure we strip any whitespace just in case
      num = num.trim();
      let uuid = await redis.get(`parewa:phone:${num}`);
      
      // Fallback lookup if the number was stored without '+' or under email
      if (!uuid) {
        uuid = await redis.get(`parewa:email:${num}`);
      }
      if (!uuid && num.startsWith("+")) {
        uuid = await redis.get(`parewa:phone:${num.substring(1)}`);
      }
      
      if (uuid) {
        const userStr = await redis.get(`parewa:user:${uuid}`);
        if (userStr) {
          const user = JSON.parse(userStr);
          results[num] = {
            uuid: user.uuid,
            pni: user.pni || crypto.randomUUID() // fallback for old accounts
          };
          console.log(`[directory] Found match for ${num} -> UUID: ${user.uuid}`);
        }
      } else {
        console.log(`[directory] No match found for ${num}`);
      }
    }
    res.status(200).json({ results });
  } catch (error) {
    console.error("[directory] Error processing bulk lookup:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/v1/accounts/username/:username", async (req: Request, res: Response) => {
  try {
    // Decode URI component to perfectly handle URL-encoded emails (e.g. test%40example.com -> test@example.com)
    const username = decodeURIComponent(req.params.username as string).toLowerCase();
    console.log(`[directory] GET /v1/accounts/username/${username}`);
    
    const uuid = await redis.get(`parewa:email:${username}`) || await redis.get(`parewa:phone:${username}`);
    if (uuid) {
      const userStr = await redis.get(`parewa:user:${uuid}`);
      if (userStr) {
        const user = JSON.parse(userStr);
        res.status(200).json({
          uuid: user.uuid,
          pni: user.pni,
          number: user.phone_number,
          email: user.email
        });
        return;
      }
    }
    res.status(404).json({ error: "User not found" });
  } catch (err) {
    console.error("[directory] Error fetching username:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/v1/accounts/number/:number", async (req: Request, res: Response) => {
  try {
    const number = decodeURIComponent(req.params.number as string);
    console.log(`[directory] GET /v1/accounts/number/${number}`);
    
    const uuid = await redis.get(`parewa:phone:${number}`) || await redis.get(`parewa:email:${number}`);
    if (uuid) {
      const userStr = await redis.get(`parewa:user:${uuid}`);
      if (userStr) {
        const user = JSON.parse(userStr);
        res.status(200).json({
          uuid: user.uuid,
          pni: user.pni,
          number: user.phone_number,
          email: user.email
        });
        return;
      }
    }
    res.status(404).json({ error: "User not found" });
  } catch (err) {
    console.error("[directory] Error fetching number:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/v1/profiles/:identifier", (req: Request, res: Response) => {
  const identifier = req.params.identifier as string;
  console.log(`[mock] GET /v1/profiles/${identifier}`);
  res.status(200).json({
    identityKey: "mock_identity_key",
    version: "1"
  });
});

app.put("/v1/messages/:destination", async (req: Request, res: Response) => {
  try {
    const destination = req.params.destination as string; // UUID of recipient
    const senderUuid = getUuidFromAuth(req);
    console.log(`[messages] PUT /v1/messages/${destination} - Routing message from ${senderUuid} via HTTP fallback...`);

    const body = req.body || {};
    const messages = body.messages || [];
    const timestamp = body.timestamp || Date.now();
    const urgent = body.urgent || false;

    for (const msg of messages) {
      // Map OutgoingPushMessage to Envelope format expected by Android client
      const envelope = {
        type: msg.type,
        sourceServiceId: senderUuid,
        sourceDeviceId: 1, // Defaulting to 1 for MVP
        destinationServiceId: destination,
        clientTimestamp: timestamp,
        serverTimestamp: Date.now(),
        ephemeral: false,
        urgent: urgent,
        content: msg.content
      };

      // Offline: push to Redis queue
      await redis.rpush(`parewa:messages:${destination}`, JSON.stringify(envelope));
    }

    console.log(`[messages] Stored ${messages.length} offline envelope(s) for ${destination}`);

    res.status(200).json({ needsSync: false, status: "SUCCESS" });
  } catch (error) {
    console.error("[messages] Error routing message:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/v1/messages", async (req: Request, res: Response) => {
  try {
    const uuid = getUuidFromAuth(req);
    console.log(`[messages] GET /v1/messages - Fetching offline messages for ${uuid}`);

    const offlineMessages = await redis.lrange(`parewa:messages:${uuid}`, 0, -1);
    if (offlineMessages.length > 0) {
      await redis.del(`parewa:messages:${uuid}`);
      // Parse them back to JSON array
      const parsedMessages = offlineMessages.map(msg => JSON.parse(msg));
      res.status(200).json({ messages: parsedMessages });
    } else {
      res.status(200).json({ messages: [] });
    }
  } catch (error) {
    console.error("[messages] Error fetching messages:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ---- Dummy Endpoints (to prevent client 404 spam) ---------------------------

app.get("/v2/config", (_req: Request, res: Response) => {
  res.status(200).json({});
});

app.get("/v1/storage/auth", (_req: Request, res: Response) => {
  res.status(200).json({});
});

// ---- 404 Catch-All ----------------------------------------------------------

app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: "Not found" });
});

// ---- Global Error Handler ---------------------------------------------------

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error("[server] Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// Start Express Server
const port = process.env.PORT || 8080;
server.listen(port, () => {
  console.log(`============================================`);
  console.log(`  Project Parewa — Auth Service`);
  console.log(`  Listening on http://0.0.0.0:${port}`);
  console.log(`  Redis: redis://${process.env.REDIS_HOST}:6379`);
  console.log(`  SMTP:  ${process.env.SMTP_HOST}:${process.env.SMTP_PORT}`);
  console.log(`============================================`);
});
