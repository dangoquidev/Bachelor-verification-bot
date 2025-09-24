import fs from "fs";
import path from "path";
import { EmailVerificationBot } from "./bot/EmailVerificationBot";

const asciiArt = fs.readFileSync(
  path.join(__dirname, "ascii", "koguma"),
  "utf8"
);

console.log(asciiArt);
console.log("Koguma will handle this !!!");
console.log("Lets verify them all (≧▽≦)");

const bot = new EmailVerificationBot();
bot.start();

export default EmailVerificationBot;
