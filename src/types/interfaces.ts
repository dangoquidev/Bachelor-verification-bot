export interface VerificationData {
    userId: string;
    email: string;
    code: string;
    timestamp: number;
    channelId: string;
    attempts: number;
}

export interface RateLimitData {
    attempts: number;
    lastAttempt: number;
}
