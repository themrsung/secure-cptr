<script lang="ts">
	/**
	 * Second step of sign-in.
	 *
	 * Two shapes, one component: on a first sign-in it shows the QR code and
	 * secret once and asks for a code to prove the authenticator took it; after
	 * that it just asks for the code. The same form also backs terminal
	 * elevation, where there is never an enrolment to show.
	 */
	import { toast } from 'svelte-sonner';
	import { ApiError } from '$lib/apis';
	import { t } from '$lib/i18n';
	import Spinner from '$lib/components/common/Spinner.svelte';

	interface Props {
		/** Enrolment payload, present only on a first sign-in. */
		enrollment?: { secret: string; uri: string; qr_svg: string } | null;
		/** Called with the six digits; throws to report a bad code. */
		onsubmit: (code: string) => Promise<void>;
		oncancel?: () => void;
		title?: string;
		description?: string;
		cancelLabel?: string;
	}

	let { enrollment = null, onsubmit, oncancel, title, description, cancelLabel }: Props = $props();

	let code = $state('');
	let loading = $state(false);
	let showSecret = $state(false);
	let input = $state<HTMLInputElement | null>(null);

	$effect(() => {
		input?.focus();
	});

	const digits = $derived(code.replace(/\D/g, '').slice(0, 6));

	async function submit() {
		if (digits.length !== 6) {
			toast.error($t('auth.totpSixDigits'));
			return;
		}
		loading = true;
		try {
			await onsubmit(digits);
		} catch (e) {
			toast.error(e instanceof ApiError ? e.message : $t('auth.connectionFailed'));
			code = '';
			input?.focus();
		} finally {
			loading = false;
		}
	}

	function handleSubmit(e: SubmitEvent) {
		e.preventDefault();
		submit();
	}

	/** Auto-submit as soon as six digits are in — nobody wants to press enter. */
	function onInput() {
		if (code.replace(/\D/g, '').length === 6 && !loading) submit();
	}

	async function copySecret() {
		if (!enrollment) return;
		try {
			await navigator.clipboard.writeText(enrollment.secret);
			toast.success($t('auth.totpSecretCopied'));
		} catch {
			toast.error($t('auth.totpCopyFailed'));
		}
	}
</script>

<form onsubmit={handleSubmit} class="w-full max-w-sm flex flex-col gap-5">
	<div class="flex flex-col gap-1.5 text-center">
		<h1 class="text-lg font-semibold tracking-tight text-gray-900 dark:text-white m-0">
			{title ?? (enrollment ? $t('auth.totpEnrollTitle') : $t('auth.totpTitle'))}
		</h1>
		<p class="text-[0.8125rem] text-gray-500 dark:text-gray-400 m-0">
			{description ?? (enrollment ? $t('auth.totpEnrollHint') : $t('auth.totpHint'))}
		</p>
	</div>

	{#if enrollment}
		<div class="flex flex-col items-center gap-3">
			<!-- currentColor keeps the QR legible in both themes; the white
			     backing plate is what scanners actually need for contrast. -->
			<div
				class="p-3 rounded-xl bg-white text-black border border-gray-200 dark:border-gray-700 [&>svg]:block [&>svg]:w-44 [&>svg]:h-44"
			>
				<!-- eslint-disable-next-line svelte/no-at-html-tags -->
				{@html enrollment.qr_svg}
			</div>

			<button
				type="button"
				class="text-xs text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 transition-colors"
				onclick={() => (showSecret = !showSecret)}
			>
				{showSecret ? $t('auth.totpHideSecret') : $t('auth.totpCantScan')}
			</button>

			{#if showSecret}
				<button
					type="button"
					onclick={copySecret}
					title={$t('auth.totpCopySecret')}
					class="w-full px-3 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 font-mono text-[0.6875rem] tracking-[0.12em] break-all text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
				>
					{enrollment.secret}
				</button>
			{/if}

			<p
				class="text-[0.6875rem] leading-relaxed text-amber-700 dark:text-amber-500 text-center m-0"
			>
				{$t('auth.totpEnrollWarning')}
			</p>
		</div>
	{/if}

	<input
		bind:this={input}
		bind:value={code}
		oninput={onInput}
		type="text"
		inputmode="numeric"
		autocomplete="one-time-code"
		pattern="[0-9]*"
		maxlength="6"
		placeholder="000000"
		disabled={loading}
		aria-label={$t('auth.totpCode')}
		class="w-full px-4 py-3 rounded-lg bg-transparent border border-gray-200 dark:border-gray-700 text-center text-2xl font-mono tracking-[0.4em] text-gray-900 dark:text-white placeholder:text-gray-300 dark:placeholder:text-gray-600 outline-none focus:border-gray-400 dark:focus:border-gray-500 transition-colors disabled:opacity-50"
	/>

	<div class="flex flex-col gap-2">
		<button
			type="submit"
			disabled={loading || digits.length !== 6}
			class="w-full h-10 rounded-lg bg-gray-900 dark:bg-white text-white dark:text-gray-900 text-sm font-medium transition-opacity hover:opacity-90 disabled:opacity-40 disabled:pointer-events-none flex items-center justify-center"
		>
			{#if loading}
				<Spinner />
			{:else}
				{enrollment ? $t('auth.totpEnrollBtn') : $t('auth.totpVerifyBtn')}
			{/if}
		</button>

		{#if oncancel}
			<button
				type="button"
				onclick={oncancel}
				class="text-xs text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 transition-colors"
			>
				{cancelLabel ?? $t('auth.totpBack')}
			</button>
		{/if}
	</div>
</form>
