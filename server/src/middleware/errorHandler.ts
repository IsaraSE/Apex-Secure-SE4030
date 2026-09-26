import { Request, Response, NextFunction } from "express";
import { logger } from "../utils/logger";

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
