import { Request, Response, NextFunction } from "express";
import { ZodSchema } from "zod";

export const validate = (schema: ZodSchema) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      // [V3: FIX] - Mass Assignment (Validation Middleware Bypass)
      // Reassign the validated/stripped output back to req.body.
      // This ensures that unauthorized fields (like "status") dropped by Zod
      // are permanently removed before the payload reaches the controller.
      req.body = schema.parse(req.body);
      next();
    } catch (error: any) {
      res.status(400).json({
        message: "Validation failed",
        errors: error.errors?.map((e: any) => ({
          field: e.path.join("."),
          message: e.message,
        })),
      });
    }
  };
};
