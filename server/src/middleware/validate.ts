import { Request, Response, NextFunction } from "express";
import { ZodSchema } from "zod";

export const validate = (schema: ZodSchema) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      // [V3: VULNERABLE CODE] - Mass Assignment (Validation Middleware Bypass)
      // schema.parse() validates the data, but the parsed result is discarded here.
      // Because the output isn't assigned back to req.body, unallowed injected
      // fields (like "status") remain in the original request body.
      schema.parse(req.body);
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
