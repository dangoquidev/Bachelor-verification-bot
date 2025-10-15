import express from 'express';
import path from 'path';
import { AuthService } from './auth/AuthService';

export function startAuthServer(port: number, baseUrl: string, auth: AuthService) {
	const app = express();

	app.get('/', async (_req, res) => {
		if (auth.isLoggedIn()) {
			res.send('<h2>Logged in ✅</h2><a href="/logout">Logout</a>');
		} else {
			res.send('<h2>Not logged in</h2><a href="/login">Login with Microsoft</a>');
		}
	});

	app.get('/login', async (_req, res) => {
		try {
			const url = await auth.getLoginUrl();
			res.redirect(url);
		} catch (e) {
			res.status(500).send('Failed to start login');
		}
	});

	app.get('/get_token', async (req, res) => {
		const code = req.query.code as string | undefined;
		if (!code) return res.status(400).send('Missing code');
		try {
			await auth.handleAuthCode(code);
			res.redirect('/dashboard');
		} catch (e) {
			res.status(500).send('Failed to acquire token');
		}
	});

	app.get('/dashboard', async (_req, res) => {
		if (!auth.isLoggedIn()) return res.redirect('/');
		res.send('<h2>Ready to send emails from Discord bot.</h2><a href="/">Home</a>');
	});

	app.get('/logout', (_req, res) => {
		auth.logout();
		res.redirect('/');
	});

	app.listen(port, () => {
		console.log(`Auth server listening on ${baseUrl}`);
	});
}


