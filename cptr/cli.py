import asyncio

import click
import uvicorn


@click.group()
def cli():
    """Your computer, from anywhere."""
    pass


@cli.command()
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="Host to bind to. Use 0.0.0.0 to allow access from other devices.",
)
@click.option("--port", default=8000, type=int, help="Port to bind to.")
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload.")
@click.option("--headless", is_flag=True, default=False, help="Don't open browser.")
@click.option(
    "--no-tls",
    is_flag=True,
    default=False,
    help="Serve plain HTTP. Only safe on a loopback bind; credentials and "
    "terminal traffic would otherwise cross the network in the clear.",
)
@click.option(
    "--cert-host",
    "cert_hosts",
    multiple=True,
    help="Extra hostname or IP to include in the TLS certificate. Repeatable.",
)
def run(host: str, port: int, reload: bool, headless: bool, no_tls: bool, cert_hosts: tuple):
    """Start the cptr server."""
    import os
    import secrets

    display_host = "localhost" if host == "0.0.0.0" else host

    token = secrets.token_hex(32)
    os.environ["CPTR_STARTUP_TOKEN"] = token
    os.environ["CPTR_PORT"] = str(port)

    ssl_args: dict = {}
    scheme = "http"
    if no_tls:
        if host not in ("127.0.0.1", "localhost", "::1"):
            click.secho(
                f"  !  --no-tls with --host {host} sends passwords, session cookies and\n"
                f"     terminal output across the network in plain text.",
                fg="red",
            )
    else:
        from cptr.utils.tls import ensure_certificate, is_locally_trusted

        cert, key = ensure_certificate(list(cert_hosts))
        ssl_args = {"ssl_certfile": str(cert), "ssl_keyfile": str(key)}
        scheme = "https"
        os.environ["CPTR_TLS"] = "1"
        if not is_locally_trusted():
            click.secho(
                "  i  Using a self-signed certificate — your browser will warn once.\n"
                "     Install mkcert and restart for a locally-trusted certificate.",
                fg="yellow",
            )

    url = f"{scheme}://{display_host}:{port}/?token={token}"
    print(f"\n  ➜  {url}\n")
    if not headless:
        import threading
        import webbrowser

        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    uvicorn.run(
        "cptr.app:application",
        host=host,
        port=port,
        reload=reload,
        **ssl_args,
    )


# ── Recovery ─────────────────────────────────────────────────


@cli.group()
def recovery():
    """Recover access when a second factor is lost.

    These commands read and write the local cptr database directly, so shell
    access to this machine is itself the authorisation — there is no password
    prompt. Anyone who can run them can already read ~/.cptr/app.db.
    """


async def _with_db(coro):
    from cptr.utils.db import init_db

    await init_db()
    return await coro


def _run(coro):
    return asyncio.run(_with_db(coro))


@recovery.command("list")
def recovery_list():
    """List accounts with their role and second-factor status."""
    from cptr.models import User

    users = _run(User.list_all())
    if not users:
        click.echo("No accounts yet.")
        return

    width = max([len("USERNAME")] + [len(u["username"] or "") for u in users])
    click.echo(f"{'USERNAME'.ljust(width)}  {'ROLE'.ljust(10)}  2FA       CAPABILITIES")
    for u in users:
        if u["totp_reset_required"]:
            status = "reset"
        elif u["totp_enabled"]:
            status = "enrolled"
        else:
            status = "pending"
        caps = ",".join(sorted(c for c, on in u["capabilities"].items() if on)) or "-"
        click.echo(
            f"{(u['username'] or '').ljust(width)}  {u['role'].ljust(10)}  {status.ljust(8)}  {caps}"
        )


@recovery.command("reset")
@click.argument("username")
@click.option("--yes", is_flag=True, default=False, help="Skip the confirmation prompt.")
def recovery_reset(username: str, yes: bool):
    """Clear USERNAME's second factor so the next login re-enrols it.

    The account keeps its password. At the next successful sign-in it is shown
    a fresh secret and QR code, exactly like a first sign-in.
    """
    from cptr.models import Auth

    auth = _run(Auth.get_by_username(username))
    if auth is None:
        raise click.ClickException(f"no account named {username!r}")

    if not yes:
        click.confirm(
            f"Clear the second factor for {username!r}? "
            "They will re-enrol at their next sign-in.",
            abort=True,
        )

    if not _run(Auth.reset_totp(auth.user_id)):
        raise click.ClickException("could not update the account")

    from cptr.utils.elevation import revoke

    revoke(auth.user_id)
    click.secho(f"✓ {username} will re-enrol a second factor at the next sign-in.", fg="green")


@recovery.command("promote")
@click.argument("username")
@click.option("--yes", is_flag=True, default=False, help="Skip the confirmation prompt.")
def recovery_promote(username: str, yes: bool):
    """Make USERNAME a superadmin.

    Break-glass for the case where no superadmin can sign in any more.
    """
    from cptr.models import Auth, User
    from cptr.utils.permissions import ROLE_SUPERADMIN

    auth = _run(Auth.get_by_username(username))
    if auth is None:
        raise click.ClickException(f"no account named {username!r}")

    if not yes:
        click.confirm(f"Make {username!r} a superadmin?", abort=True)

    if not _run(User.update_role(auth.user_id, ROLE_SUPERADMIN)):
        raise click.ClickException("could not update the account")
    click.secho(f"✓ {username} is now a superadmin.", fg="green")


@recovery.command("capabilities")
@click.argument("username")
@click.option("--grant", "grants", multiple=True, help="Capability to grant. Repeatable.")
@click.option("--revoke", "revokes", multiple=True, help="Capability to revoke. Repeatable.")
def recovery_capabilities(username: str, grants: tuple, revokes: tuple):
    """Grant or revoke capabilities for USERNAME.

    Valid capabilities: terminal, machine, external.
    """
    from cptr.models import Auth, User
    from cptr.utils.elevation import revoke as revoke_elevation
    from cptr.utils.permissions import ALL_CAPABILITIES, CAP_TERMINAL

    unknown = (set(grants) | set(revokes)) - set(ALL_CAPABILITIES)
    if unknown:
        raise click.ClickException(
            f"unknown capability: {', '.join(sorted(unknown))}. "
            f"Valid: {', '.join(ALL_CAPABILITIES)}"
        )
    if not grants and not revokes:
        raise click.ClickException("nothing to do — pass --grant or --revoke")

    auth = _run(Auth.get_by_username(username))
    if auth is None:
        raise click.ClickException(f"no account named {username!r}")

    changes = {cap: True for cap in grants}
    changes.update({cap: False for cap in revokes})
    if not _run(User.update_capabilities(auth.user_id, changes)):
        raise click.ClickException("could not update the account")

    if changes.get(CAP_TERMINAL) is False:
        revoke_elevation(auth.user_id)

    click.secho(
        "✓ "
        + ", ".join(f"{'+' if on else '-'}{cap}" for cap, on in sorted(changes.items()))
        + f" for {username}",
        fg="green",
    )


def main():
    cli()


if __name__ == "__main__":
    main()
