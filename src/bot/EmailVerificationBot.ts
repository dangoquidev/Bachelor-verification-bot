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
    private readonly MAIL_DEBUG: boolean = ((process.env.MAIL_DEBUG || '').toLowerCase() === 'true' || process.env.MAIL_DEBUG === '1');
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

    private log(message: string, details?: Record<string, unknown>) {
        const ts = new Date().toISOString();
        if (details) {
            console.log(`[${ts}] ${message}`, details);
        } else {
            console.log(`[${ts}] ${message}`);
        }
    }

    private warn(message: string, details?: Record<string, unknown>) {
        const ts = new Date().toISOString();
        if (details) {
            console.warn(`[${ts}] ⚠️ ${message}`, details);
        } else {
            console.warn(`[${ts}] ⚠️ ${message}`);
        }
    }

    private error(message: string, details?: unknown) {
        const ts = new Date().toISOString();
        if (details) {
            console.error(`[${ts}] ❌ ${message}`, details);
        } else {
            console.error(`[${ts}] ❌ ${message}`);
        }
    }

    private initializeCsvFile() {
        if (!fs.existsSync(this.CSV_FILE_PATH)) {
            fs.writeFileSync(this.CSV_FILE_PATH, 'email,discord\n');
            this.log('📄 Created verified_emails.csv file', { path: this.CSV_FILE_PATH });
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
            this.error('Error reading CSV file', error);
            return false;
        }
    }

    private addEmailToVerifiedList(email: string, discordUsername: string) {
        try {
            const csvLine = `${email},${discordUsername}\n`;
            fs.appendFileSync(this.CSV_FILE_PATH, csvLine);
        } catch (error) {
            this.error('Error writing to CSV file', error);
        }
    }

    private setupEmailTransporter() {
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
            this.warn('EMAIL_USER or EMAIL_PASS not configured');
        }

        const transportOptions: any = {
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            },
            logger: this.MAIL_DEBUG,
            debug: this.MAIL_DEBUG
        };

        this.emailTransporter = nodemailer.createTransport(transportOptions);

        // Verify SMTP connection early to surface auth/connectivity issues
        this.emailTransporter.verify()
            .then(() => this.log('✅ SMTP transporter verified'))
            .catch((err) => this.error('SMTP transporter verification failed', {
                message: (err as any)?.message,
                code: (err as any)?.code
            }));
    }

    private setupEventListeners() {
        this.client.once('clientReady', () => {
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
        this.log('Received /verify command', { userId, email });

        const member = interaction.member as GuildMember;
        const roleName = process.env.VERIFIED_ROLE_NAME || 'Verified';
        const verifiedRole = member.guild.roles.cache.find(r => r.name === roleName);
        
        if (verifiedRole && member.roles.cache.has(verifiedRole.id)) {
            await interaction.reply({
                content: '✅ Vous êtes déjà vérifié !',
                flags: MessageFlags.Ephemeral
            });
            this.log('User already verified', { userId });
            return;
        }

        if (!this.checkRateLimit(userId)) {
            await interaction.reply({
                content: '⏰ Vous avez fait trop de tentatives de vérification. Veuillez attendre 15 minutes avant de réessayer.',
                flags: MessageFlags.Ephemeral
            });
            this.warn('Rate limit reached for user', { userId });
            return;
        }

        const existingVerification = this.pendingVerifications.get(userId);
        if (existingVerification) {
            const timeLeft = Math.ceil((existingVerification.timestamp + 10 * 60 * 1000 - Date.now()) / 1000 / 60);
            await interaction.reply({
                content: `⏳ Vous avez déjà une vérification en cours. Veuillez attendre ${timeLeft} minutes ou vérifiez votre email pour le code existant.`,
                flags: MessageFlags.Ephemeral
            });
            this.log('Existing verification in progress', { userId, timeLeftMinutes: timeLeft });
            return;
        }

        if (!this.isValidEmail(email)) {
            await interaction.reply({
                content: '❌ Veuillez fournir une adresse email epitech valide.',
                flags: MessageFlags.Ephemeral
            });
            this.warn('Invalid email format', { userId, email });
            return;
        }

        if (!email.toLowerCase().endsWith('@epitech.eu')) {
            await interaction.reply({
                content: '❌ Seules les adresses email `@epitech.eu` sont autorisées pour la vérification.',
                flags: MessageFlags.Ephemeral
            });
            this.warn('Email domain not allowed', { userId, email });
            return;
        }
        if (this.isEmailAlreadyVerified(email)) {
            await interaction.reply({
                content: '❌ Cette adresse email a déjà été utilisée pour la vérification. Vous ne pouvez pas vérifier avec la même adresse email deux fois. Veuillez contacter un APE si vous avez besoin d\'aide.',
                flags: MessageFlags.Ephemeral
            });
            this.warn('Email already verified', { userId, email });
            return;
        }

        await interaction.deferReply({ flags: MessageFlags.Ephemeral });

        const verificationCode = this.generateVerificationCode();
        this.log('Generated verification code', { userId, email });
        
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
            this.log('Pending verification stored', { userId, email });

            await interaction.editReply({
                content: `📧 Un code de vérification a été envoyé à \`${email}\`.\nVeuillez vérifier votre email et saisir le code dans ce channel.\n\n⏰ Le code expirera dans 10 minutes.`
            });

            setTimeout(() => {
                this.pendingVerifications.delete(userId);
                this.log('Verification expired and cleared', { userId, email });
            }, 10 * 60 * 1000);

        } catch (error) {
            this.error('Error sending verification email', error);
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

    private renameUserToRealName(member: GuildMember, mail: string) {
        try {
            const localPart = mail.split('@')[0] || '';
            const [rawFirstName, rawLastName] = localPart.split('.') as [string | undefined, string | undefined];
            if (!rawFirstName || !rawLastName) return;

            const cleanedFirst = rawFirstName.replace(/\d+/g, '');
            const cleanedLast = rawLastName.replace(/\d+/g, '');
            if (!cleanedFirst || !cleanedLast) return;

            const firstName = cleanedFirst
                .split('-')
                .filter(Boolean)
                .map(part => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
                .join(' ');

            const lastName = cleanedLast
                .split('-')
                .filter(Boolean)
                .join(' ')
                .toUpperCase();

            const nickname = `${firstName} ${lastName}`;

            member.setNickname(nickname).catch(() => {});
        } catch (error) {
            this.error('Error renaming user', error);
        }
    }

    private async handleVerificationCode(message: any, verification: VerificationData) {
        const inputCode = message.content.trim();
        this.log('Received verification code input', { userId: verification.userId, attempts: verification.attempts + 1 });
        
        if (inputCode === verification.code) {
            await this.grantVerifiedRole(message.member);
            
            this.addEmailToVerifiedList(verification.email, message.author.username);

            this.renameUserToRealName(message.member, verification.email);
        
            this.pendingVerifications.delete(verification.userId);
            await message.delete().catch(() => {});
            this.log('Verification successful', { userId: verification.userId, email: verification.email });
        } else {
            verification.attempts++;
            
            if (verification.attempts >= this.MAX_VERIFICATION_ATTEMPTS) {
                await message.react('🚫');
                await message.reply('❌ Trop de tentatives échouées. Veuillez demander un nouveau code de vérification.');
                this.pendingVerifications.delete(verification.userId);
                this.warn('Verification failed: too many attempts', { userId: verification.userId });
            } else {
                await message.react('❌');
                const remainingAttempts = this.MAX_VERIFICATION_ATTEMPTS - verification.attempts;
                await message.reply(`❌ Code de vérification invalide. ${remainingAttempts} tentatives restantes.`);
                this.warn('Verification code mismatch', { userId: verification.userId, remainingAttempts });
            }
        }
    }

    private async grantVerifiedRole(member: GuildMember) {
        try {
            const roleName = process.env.VERIFIED_ROLE_NAME || 'Verified';
            const role = member.guild.roles.cache.find(r => r.name === roleName);
            
            if (role) {
                await member.roles.add(role);
                this.log('Granted verified role', { roleName });
            } else {
                this.warn('Role not found in guild', { roleName });
            }
        } catch (error) {
            this.error('Error granting role', error);
        }
    }

    private async sendVerificationEmail(email: string, code: string, username: string) {
        let index = fs.readFileSync(path.join(__dirname, '../utils/index.html'), 'utf8');
        index = index.replace('{{verificationCode}}', String(code));
        index = index.replace('{{user}}', username);
    
        const mailOptions = {
            from: `"Bachelor Verification Bot" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Vérification Email Serveur Discord',
            text: `Voilà ton code de vérification: ${code}\nSi tu n'as pas demandé de code de vérification, la demande vient de l'utilisateur: ${username}.`,
            html: index
        };

        this.log('Sending verification email', { to: email, from: process.env.EMAIL_USER });
        const info = await this.emailTransporter!.sendMail(mailOptions);
        this.log('Email sent via SMTP', {
            messageId: (info as any)?.messageId,
            accepted: (info as any)?.accepted,
            rejected: (info as any)?.rejected,
            response: (info as any)?.response
        });

        if ((info as any)?.rejected && (info as any).rejected.length > 0) {
            this.warn('SMTP reported rejected recipients', { rejected: (info as any).rejected });
        }
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
