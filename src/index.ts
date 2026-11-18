import 'dotenv/config';
import fs from "fs";
import path from "path";
import { EmailVerificationBot } from "./bot/EmailVerificationBot";
import { startAuthServer } from "./server";
import { AuthService } from "./auth/AuthService";
import { VerificationStore } from "./db/VerificationStore";

async function main() {
  const asciiArt = fs.readFileSync(
    path.join(__dirname, "ascii", "koguma"),
    "utf8"
  );

  console.log(asciiArt);
  console.log("Koguma will handle this !!!");
  console.log("Lets verify them all (≧▽≦)");

  const store = new VerificationStore();
  await store.init();
  console.log("✅ MySQL connected, schema ready");

  const imported = await store.importLegacyCsv(path.join(process.cwd(), "verified_emails.csv"));
  if (imported > 0) console.log(`📥 Imported ${imported} users from legacy verified_emails.csv`);

  const baseUrl = process.env.APP_BASE_URL || "http://localhost:8000";
  const port = Number(process.env.PORT || 8000);
  const authService = new AuthService(baseUrl);
  startAuthServer(port, baseUrl, authService);

  const bot = new EmailVerificationBot(authService, store);
  bot.start();
}

main().catch((error) => {
  console.error("❌ Fatal startup error", error);
  process.exit(1);
});
