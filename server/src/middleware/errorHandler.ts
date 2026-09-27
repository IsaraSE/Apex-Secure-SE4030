import { Request, Response, NextFunction } from "express";
import { logger } from "../utils/logger";

// Vulnerability 8 (OWASP A09:2021 - Security Logging and Monitoring Failures &
// A05:2021 - Security Misconfiguration):
// This handler only does a plain console.error with no request context (no
// user/IP/route/timestamp), so there is no real security audit trail here —
// failed auth attempts, validation failures, and 500s all pass through this
// single line with nothing persisted or alertable. See also
// server/src/controllers/auth.controller.ts, which never logs failed login
// attempts at all.
export const errorHandler = (
  err: Error,
  req: Request,
  res: Response,
  _next: NextFunction
): void => {
  logger.error(err.message, {
    stack: err.stack,
    method: req.method,
    path: req.originalUrl,
    ip: req.ip,
  });

  // Verbose error disclosure: err.message from Mongoose ValidationError often
  // contains internal schema/field names and validator details, and is sent
  // straight to the client instead of a generic message.
  if (err.name === "ValidationError") {
    res.status(400).json({ message: "Validation Error" });
    return;
  }

  if (err.name === "CastError") {
    res.status(400).json({ message: "Invalid ID format" });
    return;
  }

  if ((err as any).code === 11000) {
    res.status(409).json({ message: "Duplicate entry detected" });
    return;
  }

  res.status(500).json({ message: "Internal Server Error" });
};
