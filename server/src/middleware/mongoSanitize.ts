import { Request, Response, NextFunction } from "express";
import { stripMongoOperators } from "../utils/sanitize";

/**
 * [SECURITY][V6] Global middleware that removes MongoDB operators ($ne, $gt, $where, ...)
 * from req.body, req.query and req.params before any controller uses them.
 */
const cleanInPlace = (target: Record<string, unknown> | undefined): void => {
  if (!target || typeof target !== "object") return;
  const cleaned = stripMongoOperators(target) as Record<string, unknown>;
  for (const key of Object.keys(target)) delete target[key];
  Object.assign(target, cleaned);
};

export const mongoSanitize = (req: Request, _res: Response, next: NextFunction): void => {
  cleanInPlace(req.body);
  cleanInPlace(req.query as Record<string, unknown>);
  cleanInPlace(req.params);
  next();
};