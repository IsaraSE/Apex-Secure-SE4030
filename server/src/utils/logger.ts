import path from "path";
import { Request } from "express";
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
