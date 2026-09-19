<script lang="ts">
	/**
	 * Terminal unlock prompt.
	 *
	 * Holding the `terminal` capability is not enough to reach a shell: it also
	 * takes a fresh TOTP code, which opens a 30-minute idle window shared by
	 * every terminal this account has open. Any traffic in either direction
	 * refreshes it, so a long build never gets locked out mid-run.
	 *
	 * Render this conditionally — it draws its own overlay.
	 */
	import { toast } from 'svelte-sonner';
	import { elevate } from '$lib/apis/auth';
	import { setElevated } from '$lib/session';
	import { t } from '$lib/i18n';
	import Modal from '$lib/components/Modal.svelte';
	import TotpStep from '$lib/components/TotpStep.svelte';

	interface Props {
		/** Set when re-prompting after an idle expiry, to explain why. */
		expired?: boolean;
		onclose: () => void;
		onelevated?: () => void;
	}

	let { expired = false, onclose, onelevated }: Props = $props();

	async function submit(code: string) {
		await elevate(code);
		setElevated(true);
		toast.success($t('terminal.elevated'));
		onelevated?.();
	}
</script>

<Modal {onclose} class="w-full max-w-md mx-4">
	<div class="p-6 flex justify-center">
		<TotpStep
			onsubmit={submit}
			oncancel={onclose}
			title={$t('terminal.elevateTitle')}
			description={expired ? $t('terminal.elevationExpired') : $t('terminal.elevateHint')}
		/>
	</div>
</Modal>
