<script lang="ts">
	import { toast } from 'svelte-sonner';
	import Modal from '../Modal.svelte';
	import {
		updateRole,
		updateCapabilities,
		updateUserProfile,
		resetPassword,
		updateUsername,
		deleteUser as apiDeleteUser
	} from '$lib/apis/admin';
	import { ApiError } from '$lib/apis';
	import { t } from '$lib/i18n';

	interface User {
		user_id: string;
		username: string;
		display_name: string | null;
		profile_image_url: string | null;
		role: string;
		created_at: number;
		capabilities?: { terminal: boolean; machine: boolean; external: boolean };
		totp_enabled?: boolean;
		totp_reset_required?: boolean;
	}

	interface Props {
		user: User;
		adminCount: number;
		currentUserId: string;
		/** Role of the signed-in admin; only a superadmin may touch admin status. */
		currentUserRole?: string;
		onclose: () => void;
		onchanged: () => void;
	}

	const CAPABILITIES = [
		{ key: 'terminal', label: 'admin.capTerminal', hint: 'admin.capTerminalHint' },
		{ key: 'machine', label: 'admin.capMachine', hint: 'admin.capMachineHint' },
		{ key: 'external', label: 'admin.capExternal', hint: 'admin.capExternalHint' }
	] as const;

	let {
		user,
		adminCount,
		currentUserId,
		currentUserRole = 'admin',
		onclose,
		onchanged
	}: Props = $props();

	let isSelf = $derived(user.user_id === currentUserId);
	let isSuperadmin = $derived(currentUserRole === 'superadmin');
	/** Admin tiers hold every capability implicitly, so the toggles are moot. */
	let targetIsAdmin = $derived(role === 'admin' || role === 'superadmin');

	/**
	 * Which roles this admin may assign. Granting or removing admin is reserved
	 * to superadmins; the server enforces the same rule.
	 */
	let roles = $derived(
		isSuperadmin ? ['superadmin', 'admin', 'user', 'pending'] : ['user', 'pending']
	);

	let username = $state(user.username);
	let displayName = $state(user.display_name ?? '');
	let newPassword = $state('');
	let role = $state(user.role);
	let caps = $state({
		...(user.capabilities ?? { terminal: false, machine: false, external: false })
	});
	let saving = $state(false);

	async function save() {
		saving = true;
		try {
			const trimmedUsername = username.trim();
			if (!trimmedUsername) {
				toast.error($t('admin.usernameRequired'));
				saving = false;
				return;
			}
			if (newPassword && newPassword.length < 6) {
				toast.error($t('admin.minCharsPassword'));
				saving = false;
				return;
			}

			if (trimmedUsername !== user.username) {
				await updateUsername(user.user_id, trimmedUsername);
			}
			const trimmedDisplay = displayName.trim() || null;
			if (trimmedDisplay !== user.display_name) {
				await updateUserProfile(user.user_id, trimmedDisplay);
			}
			if (role !== user.role) {
				await updateRole(user.user_id, role);
			}
			// Only meaningful for non-admins; the server rejects it otherwise.
			if (!targetIsAdmin) {
				const before = user.capabilities ?? { terminal: false, machine: false, external: false };
				const changed = Object.fromEntries(
					Object.entries(caps).filter(([k, v]) => v !== before[k as keyof typeof before])
				);
				if (Object.keys(changed).length) {
					await updateCapabilities(user.user_id, changed);
				}
			}
			if (newPassword) {
				await resetPassword(user.user_id, newPassword);
			}
			toast.success($t('admin.userUpdated'));
			onchanged();
		} catch (e) {
			toast.error(e instanceof ApiError ? e.message : $t('auth.connectionFailed'));
		} finally {
			saving = false;
		}
	}

	async function deleteUser() {
		try {
			await apiDeleteUser(user.user_id);
			toast.success($t('admin.userDeleted', { username: user.username }));
			onchanged();
		} catch (e) {
			toast.error(e instanceof ApiError ? e.message : $t('auth.connectionFailed'));
		}
	}
</script>

<Modal {onclose} class="w-full max-w-sm mx-4">
	<div class="p-4">
		<h2 class="text-sm font-medium text-gray-900 dark:text-white mb-2">{$t('admin.editUser')}</h2>
		<label class="text-[0.625rem] text-gray-400 dark:text-gray-600 mt-1"
			>{$t('admin.username')}</label
		>
		<input
			type="text"
			placeholder={$t('admin.username')}
			bind:value={username}
			class="block w-full bg-transparent text-[0.8125rem] text-gray-700 dark:text-gray-300 placeholder:text-gray-300 dark:placeholder:text-gray-700 outline-none py-0.5"
		/>
		<label class="text-[0.625rem] text-gray-400 dark:text-gray-600 mt-1"
			>{$t('admin.displayName')}</label
		>
		<input
			type="text"
			placeholder={$t('admin.optional')}
			bind:value={displayName}
			class="block w-full bg-transparent text-[0.8125rem] text-gray-700 dark:text-gray-300 placeholder:text-gray-300 dark:placeholder:text-gray-700 outline-none py-0.5"
		/>
		<label class="text-[0.625rem] text-gray-400 dark:text-gray-600 mt-1"
			>{$t('admin.newPasswordLabel')}</label
		>
		<input
			type="password"
			placeholder={$t('admin.leaveBlank')}
			bind:value={newPassword}
			autocomplete="new-password"
			class="block w-full bg-transparent text-[0.8125rem] text-gray-700 dark:text-gray-300 placeholder:text-gray-300 dark:placeholder:text-gray-700 outline-none py-0.5"
		/>
		<label class="text-[0.625rem] text-gray-400 dark:text-gray-600 mt-1">{$t('admin.role')}</label>
		<select
			bind:value={role}
			disabled={isSelf}
			class="block w-full bg-transparent text-[0.8125rem] text-gray-700 dark:text-gray-300 outline-none py-0.5 cursor-pointer disabled:opacity-50"
		>
			{#each roles as r}<option value={r}>{r}</option>{/each}
		</select>
		<label class="text-[0.625rem] text-gray-400 dark:text-gray-600 mt-3"
			>{$t('admin.capabilities')}</label
		>
		{#if targetIsAdmin}
			<p class="text-[0.6875rem] text-gray-400 dark:text-gray-600 m-0 py-0.5">
				{$t('admin.capAdminImplicit')}
			</p>
		{:else}
			<div class="flex flex-col gap-1.5 py-0.5">
				{#each CAPABILITIES as cap}
					<label class="flex items-start gap-2 cursor-pointer group">
						<input
							type="checkbox"
							checked={caps[cap.key]}
							onchange={(e) => (caps = { ...caps, [cap.key]: e.currentTarget.checked })}
							class="mt-[0.1875rem] accent-gray-900 dark:accent-white cursor-pointer"
						/>
						<span class="flex flex-col leading-tight">
							<span class="text-[0.8125rem] text-gray-700 dark:text-gray-300">{$t(cap.label)}</span>
							<span class="text-[0.625rem] text-gray-400 dark:text-gray-600">{$t(cap.hint)}</span>
						</span>
					</label>
				{/each}
			</div>
		{/if}

		<div class="flex items-center justify-between mt-3">
			{#if !isSelf && (!['admin', 'superadmin'].includes(user.role) ? true : isSuperadmin && adminCount > 1)}
				<button
					class="text-[0.8125rem] text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors duration-100"
					onclick={deleteUser}>{$t('admin.delete')}</button
				>
			{:else}
				<span></span>
			{/if}
			<button
				disabled={saving}
				onclick={save}
				class="text-[0.8125rem] text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors duration-100 disabled:opacity-30 disabled:pointer-events-none"
			>
				{#if saving}{$t('settings.saving')}{:else}{$t('settings.save')}{/if}
			</button>
		</div>
	</div>
</Modal>
