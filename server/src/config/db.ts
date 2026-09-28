// [SECURITY][V5] VULNERABLE: mongoose 8.0.0-8.24.0 has prototype pollution (GHSA-664h-wqgq-64gw). A06:2021

import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

let connectionPromise: Promise<typeof mongoose> | null = null;

const connectDB = async (): Promise<void> => {
  const uri = process.env.MONGODB_URI;

  if (!uri) {
    throw new Error("MONGODB_URI is not defined in environment variables");
  }

  if (mongoose.connection.readyState === 1) {
    return;
  }

  connectionPromise ??= mongoose.connect(uri);

  try {
    await connectionPromise;
  } catch (error) {
    connectionPromise = null;
    throw error;
  }
};

export default connectDB;
