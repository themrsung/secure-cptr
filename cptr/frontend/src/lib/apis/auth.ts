/**
 * Auth API: login, setup, session, logout.
 */
import { fetchHandler, fetchJSON, jsonBody } from '$lib/apis';

interface SessionResponse {
	authenticated: boolean;
	user_id?: string;
	username?: string;
	display_name?: string | null;
	role?: string;
	profile_image_url?: string | null;
	exp?: number;
	/** What this account may reach: 'terminal' | 'machine' | 'external'. */
	capabilities?: string[];
	/** Whether a terminal elevation window is currently open. */
	elevated?: boolean;
	/** When that window lapses, in ms since epoch. */
	elevation_expires_at?: number | null;
}

/**
 * A password is never enough on its own. `/login` answers with one of these
 * instead of a session, and the second step exchanges the ticket for one.
 */
export interface TotpChallenge {
	/** First sign-in, or after `cptr recovery reset`: enrol a new secret. */
	totp_enrollment?: true;
	/** Steady state: the client just collects six digits. */
	totp_required?: true;
	ticket: string;
	/** Enrolment only — shown once and never again. */
	secret?: string;
	uri?: string;
	qr_svg?: string;
}

interface ConfigResponse {
	auth_mode: string;
	needs_setup: boolean;
	signup_enabled: boolean;
	version: string;
}

export const getSession = () => fetchJSON<SessionResponse>('/api/auth');

export const getConfig = () => fetchJSON<ConfigResponse>('/api/config');

export const login = (username: string, password: string) =>
	fetchJSON<TotpChallenge>('/api/auth/login', jsonBody({ username, password }));

export const setup = (username: string, password: string, token: string) =>
	fetchJSON<TotpChallenge>('/api/auth/setup', jsonBody({ username, password, token }));

/** Second step of login: trade the ticket plus six digits for a session. */
export const loginTotp = (ticket: string, code: string) =>
	fetchJSON<{ ok: boolean; username: string; enrolled: boolean }>(
		'/api/auth/login/totp',
		jsonBody({ ticket, code })
	);

/** Re-enter a code to open a terminal elevation window. */
export const elevate = (code: string) =>
	fetchJSON<{ ok: boolean; expires_at: number }>('/api/auth/elevate', jsonBody({ code }));

/** Whether an elevation window is currently open, and until when. */
export const elevationStatus = () =>
	fetchJSON<{ elevated: boolean; expires_at: number | null; capabilities: string[] }>(
		'/api/auth/elevation'
	);

export const signup = (username: string, password: string) =>
	fetchJSON<{ ok?: boolean; pending?: boolean }>(
		'/api/auth/signup',
		jsonBody({ username, password })
	);

export const logout = () => fetchHandler('/api/auth/logout', { method: 'POST' }).catch(() => {});

export const updatePassword = (currentPassword: string, newPassword: string) =>
	fetchJSON(
		'/api/auth/password',
		jsonBody({
			current_password: currentPassword,
			new_password: newPassword
		})
	);

/** Upload avatar (resized client-side). Returns { ok, profile_image_url }. */
export const uploadAvatar = async (
	blob: Blob
): Promise<{ ok: boolean; profile_image_url: string }> => {
	const form = new FormData();
	form.append('file', blob, 'avatar.png');
	return fetchJSON('/api/auth/avatar', { method: 'PUT', body: form });
};

/** Delete avatar. */
export const deleteAvatar = () => fetchJSON('/api/auth/avatar', { method: 'DELETE' });

/** Update display name. */
export const updateProfile = (display_name: string | null) =>
	fetchJSON('/api/auth/profile', { ...jsonBody({ display_name }), method: 'PUT' });
