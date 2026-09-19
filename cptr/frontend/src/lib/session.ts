/**
 * Session management: user state + 401 handling.
 *
 * No client-side expiry timers; the server is the source of truth.
 * If any API call returns 401, we clear the session and reload.
 */

import { derived, writable } from 'svelte/store';

export interface Session {
	user_id: string;
	username: string;
	display_name?: string | null;
	role: string;
	profile_image_url?: string | null;
	/** Capability grants: 'terminal' | 'machine' | 'external'. */
	capabilities?: string[];
	/** Whether a terminal elevation window is open right now. */
	elevated?: boolean;
	/** When that window lapses, in ms since epoch. */
	elevation_expires_at?: number | null;
}

export const session = writable<Session | null>(null);

/**
 * Set session after successful auth check.
 */
export function setSession(s: Session | null) {
	session.set(s);
}

/**
 * Whether the signed-in account holds a capability.
 *
 * Presentation only — every one of these is re-checked server-side on the
 * request itself. Hiding a control the server would refuse is a courtesy,
 * not the boundary.
 */
export function hasCapability(s: Session | null, capability: string): boolean {
	return !!s?.capabilities?.includes(capability);
}

export const canUseTerminal = derived(session, ($s) => hasCapability($s, 'terminal'));
export const canUseMachine = derived(session, ($s) => hasCapability($s, 'machine'));

/** Reflects the live elevation window so the UI can show a lock state. */
export const isElevated = writable(false);

export function setElevated(value: boolean) {
	isElevated.set(value);
}

/**
 * Clear session: delete cookie, reload to login screen.
 */
export function clearSession() {
	session.set(null);
	fetch('/api/auth/logout', { method: 'POST', credentials: 'include' }).catch(() => {});
	window.location.reload();
}
