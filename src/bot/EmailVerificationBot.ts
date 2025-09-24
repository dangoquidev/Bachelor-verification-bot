import { Client, GatewayIntentBits, SlashCommandBuilder, ChatInputCommandInteraction, GuildMember, MessageFlags } from 'discord.js';
import nodemailer from 'nodemailer';
import { config } from 'dotenv';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { VerificationData, RateLimitData } from '../types/interfaces';

config();

export class EmailVerificationBot {
    private client: Client;
    private pendingVerifications: Map<string, VerificationData>;
    private rateLimits: Map<string, RateLimitData>;
    private emailTransporter!: nodemailer.Transporter;
    private readonly RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
    private readonly MAX_ATTEMPTS_PER_WINDOW = 3;
    private readonly MAX_VERIFICATION_ATTEMPTS = 5;
    private readonly CSV_FILE_PATH = path.join(process.cwd(), 'verified_emails.csv');

    constructor() {
        this.client = new Client({
            intents: [
                GatewayIntentBits.Guilds,
                GatewayIntentBits.GuildMessages,
                GatewayIntentBits.MessageContent
            ]
        });

        this.pendingVerifications = new Map();
        this.rateLimits = new Map();
        this.initializeCsvFile();
        this.setupEmailTransporter();
        this.setupEventListeners();
    }

    private initializeCsvFile() {
        if (!fs.existsSync(this.CSV_FILE_PATH)) {
            fs.writeFileSync(this.CSV_FILE_PATH, 'email,discord\n');
            console.log('📄 Created verified_emails.csv file');
        }
    }

    private isEmailAlreadyVerified(email: string): boolean {
        try {
            const csvContent = fs.readFileSync(this.CSV_FILE_PATH, 'utf-8');
            const lines = csvContent.split('\n').slice(1);
            
            for (const line of lines) {
                if (line.trim()) {
                    const [csvEmail] = line.split(',');
                    if (csvEmail.toLowerCase() === email.toLowerCase()) {
                        return true;
                    }
                }
            }
            return false;
        } catch (error) {
            console.error('❌ Error reading CSV file:', error);
            return false;
        }
    }

    private addEmailToVerifiedList(email: string, discordUsername: string) {
        try {
            const csvLine = `${email},${discordUsername}\n`;
            fs.appendFileSync(this.CSV_FILE_PATH, csvLine);
        } catch (error) {
            console.error('❌ Error writing to CSV file:', error);
        }
    }

    private setupEmailTransporter() {
        this.emailTransporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });
    }

    private setupEventListeners() {
        this.client.once('ready', () => {
            this.registerSlashCommands();
        });

        this.client.on('interactionCreate', async (interaction) => {
            if (!interaction.isChatInputCommand()) return;

            if (interaction.commandName === 'verify') {
                await this.handleVerifyCommand(interaction);
            }
        });

        this.client.on('messageCreate', async (message) => {
            if (message.author.bot) return;
            
            const verification = this.pendingVerifications.get(message.author.id);
            if (verification && verification.channelId === message.channel.id) {
                await this.handleVerificationCode(message, verification);
            }
        });
    }

    private async registerSlashCommands() {
        const verifyCommand = new SlashCommandBuilder()
            .setName('verify')
            .setDescription('Vérifiez votre adresse email epitech')
            .addStringOption(option =>
                option.setName('email')
                    .setDescription('Votre adresse email epitech')
                    .setRequired(true)
            );

        try {
            await this.client.application?.commands.create(verifyCommand);
        } catch (error) {
            console.error('❌ Error registering slash command:', error);
        }
    }

    private async handleVerifyCommand(interaction: ChatInputCommandInteraction) {
        const email = interaction.options.get('email')?.value as string;
        const userId = interaction.user.id;

        const member = interaction.member as GuildMember;
        const roleName = process.env.VERIFIED_ROLE_NAME || 'Verified';
        const verifiedRole = member.guild.roles.cache.find(r => r.name === roleName);
        
        if (verifiedRole && member.roles.cache.has(verifiedRole.id)) {
            await interaction.reply({
                content: '✅ Vous êtes déjà vérifié !',
                flags: MessageFlags.Ephemeral
            });
            return;
        }

        if (!this.checkRateLimit(userId)) {
            await interaction.reply({
                content: '⏰ Vous avez fait trop de tentatives de vérification. Veuillez attendre 15 minutes avant de réessayer.',
                flags: MessageFlags.Ephemeral
            });
            return;
        }

        const existingVerification = this.pendingVerifications.get(userId);
        if (existingVerification) {
            const timeLeft = Math.ceil((existingVerification.timestamp + 10 * 60 * 1000 - Date.now()) / 1000 / 60);
            await interaction.reply({
                content: `⏳ Vous avez déjà une vérification en cours. Veuillez attendre ${timeLeft} minutes ou vérifiez votre email pour le code existant.`,
                flags: MessageFlags.Ephemeral
            });
            return;
        }

        if (!this.isValidEmail(email)) {
            await interaction.reply({
                content: '❌ Veuillez fournir une adresse email epitech valide.',
                flags: MessageFlags.Ephemeral
            });
            return;
        }

        if (!email.toLowerCase().endsWith('@epitech.eu')) {
            await interaction.reply({
                content: '❌ Seules les adresses email `@epitech.eu` sont autorisées pour la vérification.',
                flags: MessageFlags.Ephemeral
            });
            return;
        }
        if (this.isEmailAlreadyVerified(email)) {
            await interaction.reply({
                content: '❌ Cette adresse email a déjà été utilisée pour la vérification. Vous ne pouvez pas vérifier avec la même adresse email deux fois. Veuillez contacter un APE si vous avez besoin d\'aide.',
                flags: MessageFlags.Ephemeral
            });
            return;
        }

        await interaction.deferReply({ flags: MessageFlags.Ephemeral });

        const verificationCode = this.generateVerificationCode();
        
        try {
            await this.sendVerificationEmail(email, verificationCode, interaction.user.username);

            this.pendingVerifications.set(userId, {
                userId,
                email,
                code: verificationCode,
                timestamp: Date.now(),
                channelId: interaction.channel?.id || '',
                attempts: 0
            });

            await interaction.editReply({
                content: `📧 Un code de vérification a été envoyé à \`${email}\`.\nVeuillez vérifier votre email et saisir le code dans ce channel.\n\n⏰ Le code expirera dans 10 minutes.`
            });

            setTimeout(() => {
                this.pendingVerifications.delete(userId);
            }, 10 * 60 * 1000);

        } catch (error) {
            console.error('❌ Error sending email:', error);
            await interaction.editReply({
                content: '❌ Échec de l\'envoi de l\'email de vérification. Veuillez réessayer plus tard.'
            });
        }
    }

    private checkRateLimit(userId: string): boolean {
        const now = Date.now();
        const userRateLimit = this.rateLimits.get(userId);

        if (!userRateLimit) {
            this.rateLimits.set(userId, { attempts: 1, lastAttempt: now });
            return true;
        }

        if (now - userRateLimit.lastAttempt > this.RATE_LIMIT_WINDOW) {
            this.rateLimits.set(userId, { attempts: 1, lastAttempt: now });
            return true;
        }

        if (userRateLimit.attempts < this.MAX_ATTEMPTS_PER_WINDOW) {
            userRateLimit.attempts++;
            userRateLimit.lastAttempt = now;
            return true;
        }

        return false;
    }

    private async handleVerificationCode(message: any, verification: VerificationData) {
        const inputCode = message.content.trim();
        
        if (inputCode === verification.code) {
            await this.grantVerifiedRole(message.member);
            
            this.addEmailToVerifiedList(verification.email, message.author.username);
            
            this.pendingVerifications.delete(verification.userId);
            await message.delete().catch(() => {});
        } else {
            verification.attempts++;
            
            if (verification.attempts >= this.MAX_VERIFICATION_ATTEMPTS) {
                await message.react('🚫');
                await message.reply('❌ Trop de tentatives échouées. Veuillez demander un nouveau code de vérification.');
                this.pendingVerifications.delete(verification.userId);
            } else {
                await message.react('❌');
                const remainingAttempts = this.MAX_VERIFICATION_ATTEMPTS - verification.attempts;
                await message.reply(`❌ Code de vérification invalide. ${remainingAttempts} tentatives restantes.`);
            }
        }
    }

    private async grantVerifiedRole(member: GuildMember) {
        try {
            const roleName = process.env.VERIFIED_ROLE_NAME || 'Verified';
            const role = member.guild.roles.cache.find(r => r.name === roleName);
            
            if (role) {
                await member.roles.add(role);
            } else {
                console.log(`❌ Role "${roleName}" not found in guild`);
            }
        } catch (error) {
            console.error('❌ Error granting role:', error);
        }
    }

    private async sendVerificationEmail(email: string, code: string, username: string) {
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Vérification Email Serveur Discord',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #5865F2;">Vérification Email Discord</h2>
                    <p>Bonjour <strong>${username}</strong>,</p>
                    <p>Votre code de vérification est :</p>
                    <div style="background-color: #f0f0f0; padding: 20px; text-align: center; margin: 20px 0;">
                        <h1 style="color: #5865F2; font-size: 32px; margin: 0; letter-spacing: 5px;">${code}</h1>
                    </div>
                    <p>Veuillez entrer ce code dans le canal Discord pour compléter votre vérification.</p>
                    <p><strong>Note :</strong> Ce code expirera dans 10 minutes.</p>
                    <hr>
                    <p style="color: #666; font-size: 12px;">Si vous n'avez pas demandé cette vérification, veuillez ignorer cet email.</p>
                </div>
            `
        };

        await this.emailTransporter!.sendMail(mailOptions);
    }

    private generateVerificationCode(): string {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        let result = '';
        for (let i = 0; i < 6; i++) {
            const randomIndex = crypto.randomInt(0, chars.length);
            result += chars[randomIndex];
        }
        return result;
    }

    private isValidEmail(email: string): boolean {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    public start() {
        this.client.login(process.env.DISCORD_TOKEN);
    }
}
