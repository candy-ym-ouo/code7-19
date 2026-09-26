import { randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import {
  forgotPasswordSchema,
  loginSchema,
  registerSchema,
  resetPasswordSchema,
  verifyEmailSchema
} from "@map/shared/contracts";
import { hashPassword, normalizeEmail, randomToken, sha256, verifyPassword } from "@map/shared/server";
import { config } from "../config";
import { query, transaction } from "../db";
import { AppError } from "../errors";
import { loadUser, requireAuth, signAccessToken, type AuthUser } from "../auth";
import { queueOutbox } from "../audit";
import { enqueueOutbox } from "../queue";

function isUniqueViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "23505";
}

const REFRESH_COOKIE = "map_refresh";
const CSRF_COOKIE = "map_csrf";

export function clearSessionCookies(reply: FastifyReply) {
  reply.clearCookie(REFRESH_COOKIE, { path: "/api/v1/auth" });
  reply.clearCookie(CSRF_COOKIE, { path: "/" });
}

export function revokeSessions(userId: string): Promise<unknown> {
  return query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL", [userId]);
}

function userResponse(user: AuthUser) {
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    role: user.role,
    status: user.status,
    emailVerified: user.emailVerified
  };
}

async function issueSession(user: AuthUser, reply: FastifyReply) {
  const refreshToken = randomToken();
  const csrfToken = randomToken(24);
  const expiresAt = new Date(Date.now() + config.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000);

  await query(
    `INSERT INTO sessions(user_id, refresh_token_hash, csrf_token_hash, expires_at)
     VALUES ($1, $2, $3, $4)`,
    [user.id, sha256(refreshToken), sha256(csrfToken), expiresAt]
  );

  reply.setCookie(REFRESH_COOKIE, refreshToken, {
    path: "/api/v1/auth",
    httpOnly: true,
    sameSite: "lax",
    secure: config.COOKIE_SECURE,
    expires: expiresAt
  });
  reply.setCookie(CSRF_COOKIE, csrfToken, {
    path: "/",
    httpOnly: false,
    sameSite: "lax",
    secure: config.COOKIE_SECURE,
    expires: expiresAt
  });

  return {
    accessToken: signAccessToken(user),
    csrfToken,
    user: userResponse(user)
  };
}

function verificationEmail(token: string) {
  const link = `${config.APP_ORIGIN}/verify-email?token=${encodeURIComponent(token)}`;
  return {
    subject: "验证你的公共空间细节地图账号",
    text: `请在 24 小时内打开以下链接完成验证：${link}`,
    html: `<p>请在 24 小时内打开以下链接完成验证：</p><p><a href="${link}">${link}</a></p>`
  };
}

function resetEmail(token: string) {
  const link = `${config.APP_ORIGIN}/reset-password?token=${encodeURIComponent(token)}`;
  return {
    subject: "重置公共空间细节地图密码",
    text: `请在 30 分钟内打开以下链接重置密码：${link}`,
    html: `<p>请在 30 分钟内打开以下链接重置密码：</p><p><a href="${link}">${link}</a></p>`
  };
}

export async function authRoutes(app: FastifyInstance) {
  app.post("/auth/register", { config: { rateLimit: { max: 8, timeWindow: "1 hour" } } }, async (request, reply) => {
    const input = registerSchema.parse(request.body);
    const email = input.email.trim();
    const normalized = normalizeEmail(email);
    const passwordHash = await hashPassword(input.password);
    const token = randomToken();
    const tokenId = randomUUID();

    const outboxId = await transaction(async (client) => {
      const existing = await client.query("SELECT id FROM users WHERE email_normalized = $1", [normalized]);
      if (existing.rowCount) throw new AppError(409, "CONFLICT", "Email is already registered");

      let inserted;
      try {
        inserted = await client.query<{ id: string }>(
          `INSERT INTO users(email, email_normalized, password_hash, display_name)
           VALUES ($1, $2, $3, $4)
           RETURNING id`,
          [email, normalized, passwordHash, input.displayName]
        );
      } catch (error) {
        if (isUniqueViolation(error)) throw new AppError(409, "CONFLICT", "Email is already registered");
        throw error;
      }
      const userId = inserted.rows[0]!.id;
      await client.query(
        `INSERT INTO auth_tokens(id, user_id, type, token_hash, expires_at)
         VALUES ($1, $2, 'email_verification', $3, now() + interval '24 hours')`,
        [tokenId, userId, sha256(token)]
      );
      return queueOutbox(client, {
        eventType: "email.verification",
        aggregateType: "user",
        aggregateId: userId,
        payload: { to: email, ...verificationEmail(token) }
      });
    });

    await enqueueOutbox(outboxId);
    return reply.code(201).send({ status: "verification_sent" });
  });

  app.post("/auth/verify-email", async (request) => {
    const input = verifyEmailSchema.parse(request.body);
    return transaction(async (client) => {
      const result = await client.query<{ id: string; user_id: string }>(
        `SELECT at.id, at.user_id
         FROM auth_tokens at
         JOIN users u ON u.id = at.user_id
         WHERE at.type = 'email_verification'
           AND at.token_hash = $1
           AND at.used_at IS NULL
           AND at.expires_at > now()
           AND u.status = 'pending_verification'
           AND u.deleted_at IS NULL
         FOR UPDATE OF at`,
        [sha256(input.token)]
      );
      const tokenRow = result.rows[0];
      if (!tokenRow) throw new AppError(400, "VALIDATION_FAILED", "Verification link is invalid or expired");
      await client.query("UPDATE auth_tokens SET used_at = now() WHERE id = $1", [tokenRow.id]);
      await client.query(
        `UPDATE users
         SET status = 'active', email_verified_at = now(), updated_at = now()
         WHERE id = $1 AND status = 'pending_verification' AND deleted_at IS NULL`,
        [tokenRow.user_id]
      );
      return { status: "verified" };
    });
  });

  app.post("/auth/login", { config: { rateLimit: { max: 20, timeWindow: "15 minutes" } } }, async (request, reply) => {
    const input = loginSchema.parse(request.body);
    const result = await query<{
      id: string;
      email: string;
      display_name: string;
      password_hash: string;
      role: AuthUser["role"];
      status: AuthUser["status"];
      email_verified_at: Date | null;
      suspended: boolean;
    }>(
      `SELECT id, email, display_name, password_hash, role, status, email_verified_at
       FROM users WHERE email_normalized = $1 AND deleted_at IS NULL`,
      [normalizeEmail(input.email)]
    );
    const row = result.rows[0];
    if (!row || !(await verifyPassword(input.password, row.password_hash))) {
      throw new AppError(401, "AUTH_REQUIRED", "Invalid email or password");
    }
    if (row.status === "suspended") throw new AppError(403, "FORBIDDEN", "Account is suspended");

    await query("UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1", [row.id]);
    const user: AuthUser = {
      id: row.id,
      email: row.email,
      displayName: row.display_name,
      role: row.role,
      status: row.status,
      emailVerified: Boolean(row.email_verified_at)
    };
    return issueSession(user, reply);
  });

  app.post("/auth/refresh", async (request, reply) => {
    const refreshToken = request.cookies[REFRESH_COOKIE];
    const csrfHeader = request.headers["x-csrf-token"];
    const csrfCookie = request.cookies[CSRF_COOKIE];
    if (!refreshToken || !csrfCookie || typeof csrfHeader !== "string" || csrfHeader !== csrfCookie) {
      clearSessionCookies(reply);
      throw new AppError(401, "AUTH_REQUIRED", "Invalid refresh session");
    }

    try {
      const user = await transaction(async (client) => {
        const sessionResult = await client.query<{ id: string; user_id: string; csrf_token_hash: string }>(
          `SELECT id, user_id, csrf_token_hash
           FROM sessions
           WHERE refresh_token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
           FOR UPDATE`,
          [sha256(refreshToken)]
        );
        const session = sessionResult.rows[0];
        if (!session || session.csrf_token_hash !== sha256(csrfHeader)) {
          throw new AppError(401, "AUTH_REQUIRED", "Invalid refresh session");
        }

        const loadedUser = await loadUser(session.user_id);
        if (!loadedUser || loadedUser.status === "suspended") {
          throw new AppError(401, "AUTH_REQUIRED", "Account is unavailable");
        }

        await client.query("UPDATE sessions SET revoked_at = now() WHERE id = $1", [session.id]);
        return loadedUser;
      });
      return issueSession(user, reply);
    } catch (error) {
      // A concurrent refresh can rotate the token first. Keep the winning response's
      // Set-Cookie intact instead of letting the losing response clear it.
      if (!(error instanceof AppError && error.message === "Invalid refresh session")) {
        clearSessionCookies(reply);
      }
      throw error;
    }
  });

  app.post("/auth/logout", async (request, reply) => {
    const refreshToken = request.cookies[REFRESH_COOKIE];
    if (refreshToken) {
      await query("UPDATE sessions SET revoked_at = now() WHERE refresh_token_hash = $1", [sha256(refreshToken)]);
    }
    clearSessionCookies(reply);
    return { status: "logged_out" };
  });

  app.post("/auth/password/forgot", { config: { rateLimit: { max: 8, timeWindow: "1 hour" } } }, async (request) => {
    const input = forgotPasswordSchema.parse(request.body);
    const result = await query<{ id: string; email: string }>(
      "SELECT id, email FROM users WHERE email_normalized = $1 AND deleted_at IS NULL",
      [normalizeEmail(input.email)]
    );
    const user = result.rows[0];
    if (user) {
      const token = randomToken();
      const outboxId = await transaction(async (client) => {
        await client.query(
          `UPDATE auth_tokens SET used_at = now()
           WHERE user_id = $1 AND type = 'password_reset' AND used_at IS NULL`,
          [user.id]
        );
        await client.query(
          `INSERT INTO auth_tokens(user_id, type, token_hash, expires_at)
           VALUES ($1, 'password_reset', $2, now() + interval '30 minutes')`,
          [user.id, sha256(token)]
        );
        return queueOutbox(client, {
          eventType: "email.password_reset",
          aggregateType: "user",
          aggregateId: user.id,
          payload: { to: user.email, ...resetEmail(token) }
        });
      });
      await enqueueOutbox(outboxId);
    }
    return { status: "accepted" };
  });

  app.post("/auth/password/reset", async (request) => {
    const input = resetPasswordSchema.parse(request.body);
    const passwordHash = await hashPassword(input.password);
    return transaction(async (client) => {
      const result = await client.query<{ id: string; user_id: string }>(
        `SELECT at.id, at.user_id
         FROM auth_tokens at
         JOIN users u ON u.id = at.user_id
         WHERE at.type = 'password_reset'
           AND at.token_hash = $1
           AND at.used_at IS NULL
           AND at.expires_at > now()
           AND u.deleted_at IS NULL
         FOR UPDATE OF at`,
        [sha256(input.token)]
      );
      const tokenRow = result.rows[0];
      if (!tokenRow) throw new AppError(400, "VALIDATION_FAILED", "Reset link is invalid or expired");
      await client.query(
        `UPDATE auth_tokens SET used_at = now()
         WHERE user_id = $1 AND type = 'password_reset' AND used_at IS NULL`,
        [tokenRow.user_id]
      );
      await client.query("UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1", [tokenRow.user_id, passwordHash]);
      await client.query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1", [tokenRow.user_id]);
      return { status: "password_reset" };
    });
  });

  app.get("/me", { preHandler: requireAuth }, async (request) => userResponse(request.user!));

  app.patch("/me", { preHandler: requireAuth }, async (request) => {
    const input = z.object({ displayName: z.string().trim().min(2).max(40) }).parse(request.body);
    await query("UPDATE users SET display_name = $2, updated_at = now() WHERE id = $1", [request.user!.id, input.displayName]);
    const user = await loadUser(request.user!.id);
    if (!user) throw new AppError(404, "NOT_FOUND", "Account not found");
    return userResponse(user);
  });
}
