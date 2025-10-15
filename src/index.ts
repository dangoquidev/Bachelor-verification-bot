import 'dotenv/config';
import fs from "fs";
import path from "path";
import { EmailVerificationBot } from "./bot/EmailVerificationBot";
import { startAuthServer } from "./server";
import { AuthService } from "./auth/AuthService";

const asciiArt = fs.readFileSync(
  path.join(__dirname, "ascii", "koguma"),
  "utf8"
);

console.log(asciiArt);
console.log("Koguma will handle this !!!");
console.log("Lets verify them all (≧▽≦)");

const baseUrl = process.env.APP_BASE_URL || "http://localhost:8000";
const port = Number(process.env.PORT || 8000);
const authService = new AuthService(baseUrl);
startAuthServer(port, baseUrl, authService);

const bot = new EmailVerificationBot(authService);
bot.start();

export default EmailVerificationBot;
