<script lang="ts">
	import { toast } from 'svelte-sonner';
	import { login, loginTotp, setup, signup, type TotpChallenge } from '$lib/apis/auth';
	import { ApiError } from '$lib/apis';
	import { t } from '$lib/i18n';
	import Spinner from '$lib/components/common/Spinner.svelte';
	import TotpStep from '$lib/components/TotpStep.svelte';

	interface Props {
		mode: 'password' | 'pam';
		needsSetup?: boolean;
		signupEnabled?: boolean;
		token?: string;
		onauth: () => void;
	}

	let { mode, needsSetup, signupEnabled = false, token = '', onauth }: Props = $props();

	let username = $state('');
	let password = $state('');
	let loading = $state(false);
	let isSignup = $state(false);
	/** Set once the password step passes; the session arrives only after TOTP. */
	let challenge = $state<TotpChallenge | null>(null);

	const isSetup = mode === 'password' && needsSetup;

	async function submit() {
		if (isSetup && password.length < 6) {
			toast.error($t('auth.minChars'));
			return;
		}
		if (!username.trim()) {
			toast.error($t('auth.usernameRequired'));
			return;
		}
		if (!password) {
			toast.error($t('auth.passwordRequired'));
			return;
		}

		loading = true;
		try {
			if (isSetup) {
				challenge = await setup(username.trim(), password, token);
				password = '';
			} else if (isSignup) {
				const data = await signup(username.trim(), password);
				if (data.pending) {
					toast.success($t('auth.accountPending'));
					isSignup = false;
					username = '';
					password = '';
				} else {
					onauth();
				}
			} else {
				challenge = await login(username.trim(), password);
				password = '';
			}
		} catch (e) {
			const msg = e instanceof ApiError ? e.message : $t('auth.connectionFailed');
			toast.error(msg);
			password = '';
		} finally {
			loading = false;
		}
	}

	function handleSubmit(e: SubmitEvent) {
		e.preventDefault();
		submit();
	}

	async function submitCode(code: string) {
		await loginTotp(challenge!.ticket, code);
		challenge = null;
		onauth();
	}

	/** Abandoning the second step throws the half-finished login away. */
	function cancelChallenge() {
		challenge = null;
		password = '';
	}
</script>

<div
	class="app-theme flex items-center justify-center h-dvh bg-white dark:bg-black p-6"
	style="background: var(--app-bg); color: var(--app-fg);"
>
	<div class="w-full max-w-md">
		<h1 class="text-lg font-semibold tracking-tight text-gray-900 dark:text-white mb-3">
			Computer
		</h1>

		{#if challenge}
			<!-- Password accepted, but no session yet: the second factor decides. -->
			<div class="flex justify-center pt-2">
				<TotpStep
					enrollment={challenge.totp_enrollment
						? {
								secret: challenge.secret!,
								uri: challenge.uri!,
								qr_svg: challenge.qr_svg!
							}
						: null}
					onsubmit={submitCode}
					oncancel={cancelChallenge}
				/>
			</div>
		{:else}
			{#if isSetup}
				<p class="text-xs text-gray-400 dark:text-gray-600 -mt-2 mb-3">
					{$t('auth.createAccountHint')}
				</p>
			{:else if mode === 'pam'}
				<p class="text-xs text-gray-400 dark:text-gray-600 -mt-2 mb-3">
					{$t('auth.signInSystemHint')}
				</p>
			{/if}

			<form onsubmit={handleSubmit} action="javascript:void(0)">
				<h2 class="text-xs text-gray-400 dark:text-gray-600 mb-1">
					{isSetup ? $t('auth.setup') : isSignup ? $t('auth.signUp') : $t('auth.signIn')}
				</h2>
				<input
					type="text"
					placeholder={$t('auth.username')}
					bind:value={username}
					autofocus
					autocomplete="username"
					spellcheck="false"
					class="block w-full bg-transparent text-[0.8125rem] text-gray-700 dark:text-gray-300 placeholder:text-gray-300 dark:placeholder:text-gray-700 outline-none py-1"
				/>
				<input
					type="password"
					placeholder={$t('auth.password')}
					bind:value={password}
					autocomplete={isSetup ? 'new-password' : 'current-password'}
					class="block w-full bg-transparent text-[0.8125rem] text-gray-700 dark:text-gray-300 placeholder:text-gray-300 dark:placeholder:text-gray-700 outline-none py-1"
				/>

				<button
					type="submit"
					disabled={loading || !password || !username.trim()}
					class="flex items-center gap-2 text-[0.8125rem] text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors duration-100
					disabled:opacity-30 disabled:pointer-events-none mt-2"
				>
					{#if loading}
						<Spinner size={14} />
					{:else}
						{isSetup
							? $t('auth.createAccountBtn')
							: isSignup
								? $t('auth.signUpBtn')
								: $t('auth.signInBtn')}
					{/if}
				</button>
			</form>

			{#if !isSetup && signupEnabled && mode === 'password'}
				<p class="text-[0.6875rem] text-gray-400 dark:text-gray-600 mt-4">
					{#if isSignup}
						{$t('auth.alreadyHaveAccount')}
						<button
							type="button"
							class="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
							onclick={() => {
								isSignup = false;
								password = '';
							}}>{$t('auth.signInLink')}</button
						>
					{:else}
						{$t('auth.dontHaveAccount')}
						<button
							type="button"
							class="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
							onclick={() => {
								isSignup = true;
								password = '';
							}}>{$t('auth.signUpLink')}</button
						>
					{/if}
				</p>
			{/if}
		{/if}
	</div>
</div>
