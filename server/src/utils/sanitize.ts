import mongoose from "mongoose";

/**
 * [SECURITY][V6] NoSQL Injection protection helpers.
 * Query-string values can arrive as objects (e.g. ?status[$ne]=x becomes { $ne: "x" }).
 * These helpers make sure only plain, expected values reach Mongoose queries.
 */

// Returns the value only if it is a plain string. Objects/arrays are rejected.
export const toSafeString = (value: unknown): string | undefined =>
  typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;

// Returns the value only if it is a valid MongoDB ObjectId string.
export const toSafeObjectId = (value: unknown): string | undefined =>
  typeof value === "string" && mongoose.isValidObjectId(value) ? value : undefined;

// Recursively removes keys that start with "$" or contain "." (MongoDB operators / dotted paths).
export const stripMongoOperators = (input: unknown): unknown => {
  if (Array.isArray(input)) {
    return input.map(stripMongoOperators);
  }

  if (input !== null && typeof input === "object") {
    const clean: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
      if (key.startsWith("$") || key.includes(".")) {
        continue; // drop dangerous key
      }
      clean[key] = stripMongoOperators(value);
    }
    return clean;
  }

  return input;
};