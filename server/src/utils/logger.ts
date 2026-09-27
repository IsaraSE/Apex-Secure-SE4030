import path from "node:path";
import { Request, Response } from "express";
import winston from "winston";

const logsDir = path.join(process.cwd(), "logs");

export const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
    }),
    new winston.transports.File({ filename: path.join(logsDir, "error.log"), level: "error" }),
    new winston.transports.File({
      filename: path.join(logsDir, "security.log"),
      level: "warn",
      format: winston.format.combine(
        winston.format((info) => (info.level === "warn" ? info : false))(),
        winston.format.timestamp(),
        winston.format.json()
      ),
    }),
  ],
});

export const logSecurityEvent = (
  event: string,
  req: Request,
  meta: Record<string, unknown> = {}
): void => {
  logger.warn(event, {
    event,
    ip: req.ip,
    method: req.method,
    path: req.originalUrl,
    ...meta,
  });
};

interface RespondWithServerErrorOptions {
  status?: number;
  clientMessage?: string;
  level?: "error" | "warn";
}

export const respondWithServerError = (
  req: Request,
  res: Response,
  logMessage: string,
  error: unknown,
  options: RespondWithServerErrorOptions = {}
): void => {
  const { status = 500, clientMessage = logMessage, level = "error" } = options;

  logger[level](logMessage, {
    stack: error instanceof Error ? error.stack : undefined,
    method: req.method,
    path: req.originalUrl,
    ip: req.ip,
  });

  res.status(status).json({ message: clientMessage });
};
