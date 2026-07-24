// ==============================================================================
// Project Parewa — Email OTP Authentication Service
// Mock Signal endpoints for self-hosted registration via email verification
// ==============================================================================

import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import Redis from "ioredis";
import nodemailer from "nodemailer";
import crypto from "node:crypto";

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

    // 5. Return success and generate authoritative ACI/PNI
    const uuid = crypto.randomUUID();
    const pni = crypto.randomUUID();

    res.status(200).json({
      uuid: uuid,
      pni: pni,
      storageCapable: false,
      reRegistration: false,
      number: normalizedEmail
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

// ---- 404 Catch-All ----------------------------------------------------------

app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: "Not found" });
});

// ---- Global Error Handler ---------------------------------------------------

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error("[server] Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// ---- Start Server -----------------------------------------------------------

app.listen(PORT, "0.0.0.0", () => {
  console.log("============================================");
  console.log("  Project Parewa — Auth Service");
  console.log(`  Listening on http://0.0.0.0:${PORT}`);
  console.log(`  Redis: ${REDIS_URL}`);
  console.log(`  SMTP:  ${SMTP_HOST}:${SMTP_PORT}`);
  console.log("============================================");
});
