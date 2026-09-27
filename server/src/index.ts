import dns from "node:dns";
dns.setServers(["8.8.8.8", "1.1.1.1"]); // LOCAL ONLY - fixes Atlas SRV lookup on my Wi-Fi

import dotenv from "dotenv";
import connectDB from "./config/db";
import app from "./app";
import { autoCompleteOverdueSessions } from "./controllers/session.controller";

dotenv.config();

const PORT = process.env.PORT || 5000;

// Start server
const start = async () => {
  await connectDB();

  setInterval(() => {
    void autoCompleteOverdueSessions();
  }, 5 * 60 * 1000);

  app.listen(PORT, () => {
    console.log(`🚀 Apex Server running on port ${PORT}`);
  });
};

void start();

export default app;
