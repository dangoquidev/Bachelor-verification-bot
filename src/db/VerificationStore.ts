import fs from 'fs';
import mysql, { Pool, ResultSetHeader, RowDataPacket } from 'mysql2/promise';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS verified_users (
    id               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email            VARCHAR(255) NOT NULL,
    discord_id       VARCHAR(32)  NULL,
    discord_username VARCHAR(100) NOT NULL,
    verified_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_verified_users_email (email),
    KEY idx_verified_users_discord_id (discord_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`;

export interface VerifiedUser {
    email: string;
    discordId: string | null;
    discordUsername: string;
}

/**
 * MySQL persistence for verified students.
 * The UNIQUE constraint on `email` is the source of truth: one school address
 * can only ever verify one Discord account, even under concurrent requests.
 */
export class VerificationStore {
    private pool: Pool;

    constructor() {
        this.pool = mysql.createPool({
            host: process.env.MYSQL_HOST || 'localhost',
            port: Number(process.env.MYSQL_PORT || 3306),
            user: process.env.MYSQL_USER,
            password: process.env.MYSQL_PASSWORD,
            database: process.env.MYSQL_DATABASE,
            connectionLimit: 5,
            waitForConnections: true
        });
    }

    /** Waits for MySQL to accept connections, then creates the schema. */
    async init(retries = 10, delayMs = 3000): Promise<void> {
        for (let attempt = 1; ; attempt++) {
            try {
                await this.pool.query('SELECT 1');
                break;
            } catch (error) {
                if (attempt >= retries) throw error;
                console.warn(`MySQL not ready (attempt ${attempt}/${retries}), retrying in ${delayMs}ms`);
                await new Promise(resolve => setTimeout(resolve, delayMs));
            }
        }
        await this.pool.query(SCHEMA);
    }

    async isEmailVerified(email: string): Promise<boolean> {
        const [rows] = await this.pool.execute<RowDataPacket[]>(
            'SELECT 1 FROM verified_users WHERE email = ? LIMIT 1',
            [email.toLowerCase()]
        );
        return rows.length > 0;
    }

    /** Returns false if the email was already used (duplicate key). */
    async addVerifiedUser(user: VerifiedUser): Promise<boolean> {
        try {
            await this.pool.execute<ResultSetHeader>(
                'INSERT INTO verified_users (email, discord_id, discord_username) VALUES (?, ?, ?)',
                [user.email.toLowerCase(), user.discordId, user.discordUsername]
            );
            return true;
        } catch (error: any) {
            if (error?.code === 'ER_DUP_ENTRY') return false;
            throw error;
        }
    }

    /** One-off migration from the legacy `email,discord` CSV file. Returns the number of imported rows. */
    async importLegacyCsv(csvPath: string): Promise<number> {
        if (!fs.existsSync(csvPath)) return 0;
        const lines = fs.readFileSync(csvPath, 'utf-8').split('\n').slice(1);
        let imported = 0;
        for (const line of lines) {
            const [email, discordUsername] = line.trim().split(',');
            if (!email || !discordUsername) continue;
            const [result] = await this.pool.execute<ResultSetHeader>(
                'INSERT IGNORE INTO verified_users (email, discord_username) VALUES (?, ?)',
                [email.toLowerCase(), discordUsername]
            );
            imported += result.affectedRows;
        }
        return imported;
    }

    async close(): Promise<void> {
        await this.pool.end();
    }
}
