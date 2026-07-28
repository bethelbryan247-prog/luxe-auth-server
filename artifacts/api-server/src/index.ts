import https from "https";
import app from "./app";
import { logger } from "./lib/logger";

const rawPort = process.env["PORT"];

if (!rawPort) {
  throw new Error(
    "PORT environment variable is required but was not provided.",
  );
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

app.listen(port, (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");

  // Keep-alive ping every 4 minutes
  const devDomain = process.env.REPLIT_DEV_DOMAIN;
  if (devDomain) {
    setInterval(() => {
      https.get(`https://${devDomain}/api/healthz`, (res) => {
        logger.info({ statusCode: res.statusCode }, "Keep-alive ping");
      }).on("error", (err) => {
        logger.warn({ err }, "Keep-alive ping failed");
      });
    }, 240000);
  }
});
