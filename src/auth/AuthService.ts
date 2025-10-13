import { Configuration, LogLevel, ConfidentialClientApplication, AuthorizationUrlRequest, AuthorizationCodeRequest, AccountInfo } from "@azure/msal-node";

export class AuthService {
	private msalApp: ConfidentialClientApplication;
	private account: AccountInfo | null = null;
	private readonly redirectUri: string;
	private readonly baseUrl: string;
	private readonly scopes: string[] = [
		"https://graph.microsoft.com/Mail.Send",
		"offline_access",
		"openid",
		"profile"
	];

	constructor(baseUrl: string) {
		const clientId = process.env.AZURE_CLIENT_ID;
		const tenantId = process.env.AZURE_TENANT_ID;
		const clientSecret = process.env.AZURE_CLIENT_SECRET;

		if (!clientId || !tenantId || !clientSecret) {
			throw new Error("Missing AZURE_CLIENT_ID, AZURE_TENANT_ID or AZURE_CLIENT_SECRET env vars");
		}

		this.baseUrl = baseUrl;
		this.redirectUri = process.env.MSAL_REDIRECT_URI || `${this.baseUrl}/get_token`;

		const msalConfig: Configuration = {
			auth: {
				clientId,
				authority: `https://login.microsoftonline.com/${tenantId}`,
				clientSecret
			},
			system: { loggerOptions: { loggerCallback: () => {}, logLevel: LogLevel.Warning } }
		};

		this.msalApp = new ConfidentialClientApplication(msalConfig);
	}

	public getLoginUrl = async (): Promise<string> => {
		const authCodeUrlParams: AuthorizationUrlRequest = {
			scopes: this.scopes,
			redirectUri: this.redirectUri
		};
		return await this.msalApp.getAuthCodeUrl(authCodeUrlParams);
	};

	public handleAuthCode = async (authCode: string): Promise<void> => {
		const tokenRequest: AuthorizationCodeRequest = {
			code: authCode,
			scopes: this.scopes,
			redirectUri: this.redirectUri
		};
		const response = await this.msalApp.acquireTokenByCode(tokenRequest);
		this.account = response.account ?? null;
	};

	public isLoggedIn = (): boolean => {
		return this.account != null;
	};

	public getAccessToken = async (): Promise<string | null> => {
		if (!this.account) return null;
		try {
			const response = await this.msalApp.acquireTokenSilent({
				account: this.account,
				scopes: this.scopes
			});
			return response.accessToken || null;
		} catch {
			return null;
		}
	};

	public logout = () => {
		this.account = null;
	};
}


