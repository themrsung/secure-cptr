/**
 * i18n setup using i18next (framework-agnostic, industry standard).
 *
 * Exports reactive `t` and `locale` Svelte stores for use in components.
 *
 * The locale is pinned to en-US. Browser and OS language settings are ignored
 * on purpose: this build is English-only, so detection could only ever pick a
 * language with no bundle behind it and fall back anyway. The other locale
 * files are kept in the tree so translations are not lost, but nothing loads
 * them.
 */

import i18next, { type TFunction } from 'i18next';
import { writable, derived } from 'svelte/store';
import en from './locales/en.json';

/** The one locale this build ships. */
export const LOCALE = 'en-US';

export const supportedLocales = [{ code: LOCALE, label: 'English (US)' }] as const;

// Registered under both tags so `en-US` is an exact hit and a bare `en`
// lookup still resolves rather than falling through to a key name.
const resources: Record<string, { translation: Record<string, string> }> = {
	'en-US': { translation: en },
	en: { translation: en }
};

i18next.init({
	resources,
	lng: LOCALE,
	fallbackLng: 'en',
	supportedLngs: [LOCALE, 'en'],
	interpolation: {
		escapeValue: false // Svelte handles escaping
	}
});

// ── Svelte store wrapper ────────────────────────────────────────

/** Writable store tracking the current locale code. */
export const locale = writable<string>(LOCALE);

/**
 * Internal ticker that increments on every language change.
 * Forces the derived `t` store to re-evaluate.
 */
const _tick = writable(0);

i18next.on('languageChanged', (lng: string) => {
	locale.set(lng);
	_tick.update((n) => n + 1);
});

/** Reactive translation function: use as `$t('key')` or `$t('key', { count: 3 })` in templates. */
export const t = derived(_tick, () => i18next.t.bind(i18next) as TFunction);

/**
 * No-op: the locale is pinned to en-US.
 *
 * Kept as a function so stored preferences and cross-tab broadcasts from older
 * builds stay harmless instead of throwing.
 */
export function changeLocale(_lng?: string): void {
	/* intentionally empty */
}

/**
 * Register a new locale bundle at runtime.
 * Useful for dynamically loaded translations.
 */
export function addLocale(lng: string, translations: Record<string, string>): void {
	i18next.addResourceBundle(lng, 'translation', translations, true, true);
}

export { i18next };
