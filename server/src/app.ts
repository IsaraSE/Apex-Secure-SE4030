// [SECURITY][V5] VULNERABLE: express pulls in outdated qs/body-parser with DoS bugs. A06:2021

import express from "express";
import cors from "cors";
import helmet from "helmet";

import { errorHandler } from "./middleware/errorHandler";
import authRoutes from "./routes/auth.routes";
import memberRoutes from "./routes/member.routes";
import inventoryRoutes from "./routes/inventory.routes";
import sessionRoutes from "./routes/session.routes";
import paymentRoutes from "./routes/payment.routes";
import notificationRoutes from "./routes/notification.routes";

const normalizeOrigin = (value: string | undefined): string | undefined => {
  const rawValue = value?.trim();

  if (!rawValue) {
    return undefined;
  }

  const absoluteValue = /^https?:\/\//i.test(rawValue) ? rawValue : `https://${rawValue}`;

  try {
    return new URL(absoluteValue).origin;
  } catch {
    return rawValue;
  }
};

const allowedOrigins = new Set<string>([
  normalizeOrigin(process.env.CLIENT_URL),
  "http://localhost:3000",
  "http://127.0.0.1:3000",
].filter((origin): origin is string => Boolean(origin)));

const isAllowedCorsOrigin = (origin: string | undefined): boolean => {
  if (!origin) {
    return false;
  }

  if (allowedOrigins.has(origin)) {
    return true;
  }

  try {
    const parsedOrigin = new URL(origin);
    return parsedOrigin.protocol === "https:" && parsedOrigin.hostname.endsWith(".vercel.app");
  } catch {
    return false;
  }
};

const app = express();

app.use(helmet());
app.use(
  cors({
    origin: (origin, callback) => {
      if (isAllowedCorsOrigin(origin)) {
        callback(null, true);
        return;
      }

      callback(new Error(`CORS blocked for origin: ${origin ?? "unknown"}`));
    },
    credentials: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use("/api/auth", authRoutes);
app.use("/api/members", memberRoutes);
app.use("/api/inventory", inventoryRoutes);
app.use("/api/sessions", sessionRoutes);
app.use("/api/payments", paymentRoutes);
app.use("/api/notifications", notificationRoutes);

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

app.use(errorHandler);

export default app;