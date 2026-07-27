import click
import utilities_common.cli as clicommon
from sonic_py_common import multi_asic
from swsscommon.swsscommon import ConfigDBConnector
from utilities_common.constants import DEFAULT_NAMESPACE
from utilities_common.db import Db

#
# 'macsec' group ('config macsec ...')
#
@click.group(cls=clicommon.AbbreviationGroup, name='macsec')
# TODO add "hidden=True if this is a single ASIC platform, once we have click 7.0 in all branches.
@click.option('-n', '--namespace', help='Namespace name',
             required=True if multi_asic.is_multi_asic() else False, type=click.Choice(multi_asic.get_namespace_list()))
@click.pass_context
def macsec(ctx, namespace):
    """MACsec-related configuration tasks"""
    if not ctx.obj or isinstance(ctx.obj, Db):
        # Set namespace to default_namespace if it is None.
        if namespace is None:
            namespace = DEFAULT_NAMESPACE
        config_db = ConfigDBConnector(use_unix_socket_path=True, namespace=str(namespace))
        config_db.connect()
        ctx.obj = config_db


#
# 'port' group ('config macsec port ...')
#
@macsec.group(cls=clicommon.AbbreviationGroup, name='port')
def macsec_port():
    """Enable MACsec or disable MACsec on the specified port"""
    pass

#
# 'add' command ('config macsec port add ...')
#
@macsec_port.command('add')
@click.argument('port', metavar='<port_name>', required=True)
@click.argument('profile', metavar='<profile_name>', required=True)
def add_port(port, profile):
    """
    Add MACsec port
    """
    ctx = click.get_current_context()
    config_db = ctx.obj

    if clicommon.get_interface_naming_mode() == "alias":
        port = interface_alias_to_name(config_db, port)
        if port is None:
            ctx.fail("cannot find port name for alias {}".format(port))

    profile_entry = config_db.get_entry('MACSEC_PROFILE', profile)
    if len(profile_entry) == 0:
        ctx.fail("profile {} doesn't exist".format(profile))

    port_entry = config_db.get_entry('PORT', port)
    if len(port_entry) == 0:
        ctx.fail("port {} doesn't exist".format(port))

    port_entry['macsec'] = profile

    config_db.set_entry("PORT", port, port_entry)


#
# 'del' command ('config macsec port del ...')
#
@macsec_port.command('del')
@click.argument('port', metavar='<port_name>', required=True)
def del_port(port):
    """
    Delete MACsec port
    """
    ctx = click.get_current_context()
    config_db = ctx.obj

    if clicommon.get_interface_naming_mode() == "alias":
        port = interface_alias_to_name(config_db, port)
        if port is None:
            ctx.fail("cannot find port name for alias {}".format(port))

    port_entry = config_db.get_entry('PORT', port)
    if len(port_entry) == 0:
        ctx.fail("port {} doesn't exist".format(port))

    if 'macsec' in port_entry:
        del port_entry['macsec']
        config_db.set_entry("PORT", port, port_entry)
    else:
        click.echo("port {} has no configured macsec profile".format(port))

#
# 'profile' group ('config macsec profile ...')
#
@macsec.group(cls=clicommon.AbbreviationGroup, name='profile')
def macsec_profile():
    pass


def is_hexstring(hexstring: str):
    try:
        int(hexstring, 16)
        return True
    except ValueError:
        return False


def check_cak_length(ctx, cipher_suite, cak, field_name):
    """Validate that a CAK hex string has the length required by the cipher suite."""
    if "128" in cipher_suite:
        if len(cak) != 66:
            ctx.fail("Expect the length of {} is 66, but got {}".format(field_name, len(cak)))
    elif "256" in cipher_suite:
        if len(cak) != 130:
            ctx.fail("Expect the length of {} is 130, but got {}".format(field_name, len(cak)))
    if not is_hexstring(cak):
        ctx.fail("Expect the {} is valid hex string".format(field_name))


#
# 'add' command ('config macsec profile add ...')
#
@macsec_profile.command('add')
@click.argument('profile', metavar='<profile_name>', required=True)
@click.option('--priority', metavar='<priority>', required=False, default=255, show_default=True, type=click.IntRange(0, 255), help="For Key server election. In 0-255 range with 0 being the highest priority.")
@click.option('--cipher_suite', metavar='<cipher_suite>', required=False, default="GCM-AES-128", show_default=True, type=click.Choice(["GCM-AES-128", "GCM-AES-256", "GCM-AES-XPN-128", "GCM-AES-XPN-256"]), help="The cipher suite for MACsec.")
@click.option('--primary_cak', metavar='<primary_cak>', required=True, type=str, help="Primary Connectivity Association Key.")
@click.option('--primary_ckn', metavar='<primary_cak>', required=True, type=str, help="Primary CAK Name.")
@click.option('--fallback_cak', metavar='<fallback_cak>', required=False, default=None, type=str, help="Fallback Connectivity Association Key, used as a standby CA. Must be provided together with --fallback_ckn.")
@click.option('--fallback_ckn', metavar='<fallback_ckn>', required=False, default=None, type=str, help="Fallback CAK Name. Must differ from --primary_ckn and be provided together with --fallback_cak.")
@click.option('--policy', metavar='<policy>', required=False, default="security", show_default=True, type=click.Choice(["integrity_only", "security"]), help="MACsec policy. INTEGRITY_ONLY: All traffic, except EAPOL, will be converted to MACsec packets without encryption.  SECURITY: All traffic, except EAPOL, will be encrypted by SecY.")
@click.option('--enable_replay_protect/--disable_replay_protect', metavar='<replay_protect>', required=False, default=False, show_default=True, is_flag=True, help="Whether enable replay protect.")
@click.option('--replay_window', metavar='<enable_replay_protect>', required=False, default=0, show_default=True, type=click.IntRange(0, 2**32), help="Replay window size that is the number of packets that could be out of order. This field works only if ENABLE_REPLAY_PROTECT is true.")
@click.option('--send_sci/--no_send_sci', metavar='<send_sci>', required=False, default=True, show_default=True, is_flag=True, help="Send SCI in SecTAG field of MACsec header.")
@click.option('--rekey_period', metavar='<rekey_period>', required=False, default=0, show_default=True, type=click.IntRange(min=0), help="The period of proactively refresh (Unit second).")
def add_profile(profile, priority, cipher_suite, primary_cak, primary_ckn, fallback_cak, fallback_ckn, policy, enable_replay_protect, replay_window, send_sci, rekey_period):
    """
    Add MACsec profile
    """
    ctx = click.get_current_context()
    config_db = ctx.obj

    profile_entry = config_db.get_entry('MACSEC_PROFILE', profile)
    if not len(profile_entry) == 0:
        ctx.fail("{} already exists".format(profile))

    profile_table = {}

    profile_table["priority"] = priority

    profile_table["cipher_suite"] = cipher_suite

    check_cak_length(ctx, cipher_suite, primary_cak, "primary_cak")
    if not is_hexstring(primary_ckn):
        ctx.fail("Expect the primary_ckn is valid hex string")
    profile_table["primary_cak"] = primary_cak
    profile_table["primary_ckn"] = primary_ckn

    # Fallback CA is optional. When supplied, both the key and its name are
    # required together, the key must match the cipher suite, and the fallback
    # CKN must differ from the primary CKN.
    if (fallback_cak is None) != (fallback_ckn is None):
        ctx.fail("--fallback_cak and --fallback_ckn must be provided together")
    if fallback_cak is not None:
        check_cak_length(ctx, cipher_suite, fallback_cak, "fallback_cak")
        if not is_hexstring(fallback_ckn):
            ctx.fail("Expect the fallback_ckn is valid hex string")
        if fallback_ckn == primary_ckn:
            ctx.fail("fallback_ckn must be different from primary_ckn")
        profile_table["fallback_cak"] = fallback_cak
        profile_table["fallback_ckn"] = fallback_ckn

    profile_table["policy"] = policy

    if enable_replay_protect and replay_window > 0:
        profile_table["enable_replay_protect"] = enable_replay_protect
        profile_table["replay_window"] = replay_window

    profile_table["send_sci"] = send_sci

    if rekey_period > 0:
        profile_table["rekey_period"] = rekey_period

    for k, v in profile_table.items():
        if isinstance(v, bool):
            if v:
                profile_table[k] = "true"
            else:
                profile_table[k] = "false"
        else:
            profile_table[k] = str(v)
    config_db.set_entry("MACSEC_PROFILE", profile, profile_table)


#
# 'update' command ('config macsec profile update ...')
#
@macsec_profile.command('update')
@click.argument('profile', metavar='<profile_name>', required=True)
@click.option('--primary_cak', metavar='<primary_cak>', required=False, default=None, type=str, help="New primary Connectivity Association Key. Must be provided together with --primary_ckn to rotate the primary CA.")
@click.option('--primary_ckn', metavar='<primary_ckn>', required=False, default=None, type=str, help="New primary CAK Name. Must be provided together with --primary_cak.")
@click.option('--fallback_cak', metavar='<fallback_cak>', required=False, default=None, type=str, help="New fallback Connectivity Association Key. Must be provided together with --fallback_ckn.")
@click.option('--fallback_ckn', metavar='<fallback_ckn>', required=False, default=None, type=str, help="New fallback CAK Name. Must be provided together with --fallback_cak and differ from the primary CKN.")
@click.option('--remove_fallback', is_flag=True, default=False, help="Remove the fallback CA from the profile. Mutually exclusive with --fallback_cak/--fallback_ckn.")
def update_profile(profile, primary_cak, primary_ckn, fallback_cak, fallback_ckn, remove_fallback):
    """
    Update the key material of an existing MACsec profile.

    Rotate the primary CA and/or change the fallback CA in place, without
    tearing MACsec down. This is the supported way to rotate keys; editing
    CONFIG_DB directly is not.

    A primary rotation is only hitless when a fallback CA is already
    established to carry traffic while the old primary is retired and the new
    one negotiates. Rotating the primary is therefore refused unless the
    profile already has a fallback configured, or the new primary CKN is the
    current fallback being promoted. A fallback added in the same command does
    not count: it is not live yet.
    """
    ctx = click.get_current_context()
    config_db = ctx.obj

    profile_entry = config_db.get_entry('MACSEC_PROFILE', profile)
    if len(profile_entry) == 0:
        ctx.fail("{} doesn't exist".format(profile))

    if (primary_cak is None) != (primary_ckn is None):
        ctx.fail("--primary_cak and --primary_ckn must be provided together")
    if (fallback_cak is None) != (fallback_ckn is None):
        ctx.fail("--fallback_cak and --fallback_ckn must be provided together")
    if remove_fallback and (fallback_cak is not None or fallback_ckn is not None):
        ctx.fail("--remove_fallback cannot be combined with --fallback_cak/--fallback_ckn")
    if primary_cak is None and fallback_cak is None and not remove_fallback:
        ctx.fail("nothing to update: provide --primary_cak/--primary_ckn, "
                 "--fallback_cak/--fallback_ckn, or --remove_fallback")

    cipher_suite = profile_entry.get("cipher_suite", "GCM-AES-128")
    old_primary_ckn = profile_entry.get("primary_ckn", "")
    old_fallback_ckn = profile_entry.get("fallback_ckn", "")

    # set_entry replaces the whole record, so work on a copy of the existing
    # entry to keep unrelated fields (priority, policy, ...) intact.
    updated = dict(profile_entry)

    new_primary_ckn = primary_ckn if primary_ckn is not None else old_primary_ckn

    if primary_cak is not None:
        check_cak_length(ctx, cipher_suite, primary_cak, "primary_cak")
        if not is_hexstring(primary_ckn):
            ctx.fail("Expect the primary_ckn is valid hex string")
        updated["primary_cak"] = primary_cak
        updated["primary_ckn"] = primary_ckn

    if remove_fallback:
        updated.pop("fallback_cak", None)
        updated.pop("fallback_ckn", None)
    elif fallback_cak is not None:
        check_cak_length(ctx, cipher_suite, fallback_cak, "fallback_cak")
        if not is_hexstring(fallback_ckn):
            ctx.fail("Expect the fallback_ckn is valid hex string")
        if fallback_ckn == new_primary_ckn:
            ctx.fail("fallback_ckn must be different from primary_ckn")
        updated["fallback_cak"] = fallback_cak
        updated["fallback_ckn"] = fallback_ckn

    # Command-time guard mirroring macsecmgr: a primary rotation is only hitless
    # if a fallback CA is already established to carry traffic during the swap.
    if new_primary_ckn != old_primary_ckn:
        promoting_fallback = bool(old_fallback_ckn) and new_primary_ckn == old_fallback_ckn
        if not promoting_fallback and not old_fallback_ckn:
            ctx.fail(
                "cannot rotate the primary CAK of profile '{0}': no fallback CA "
                "is established to carry traffic during the rotation. Configure a "
                "fallback CAK first (config macsec profile update {0} "
                "--fallback_cak ... --fallback_ckn ...) and let it converge "
                "before rotating the primary.".format(profile))

    # A promoted fallback must not remain configured as the fallback too, or the
    # primary and fallback CKNs would collide.
    if updated.get("fallback_ckn") and updated.get("fallback_ckn") == updated.get("primary_ckn"):
        ctx.fail(
            "fallback_ckn would equal primary_ckn; when promoting the fallback to "
            "primary, also set a new fallback (--fallback_cak/--fallback_ckn) or "
            "remove it (--remove_fallback)")

    config_db.set_entry("MACSEC_PROFILE", profile, updated)


#
# 'del' command ('config macsec profile del ...')
#
@macsec_profile.command('del')
@click.argument('profile', metavar='<profile_name>', required=True)
def del_profile( profile):
    """
    Delete MACsec profile
    """
    ctx = click.get_current_context()
    config_db = ctx.obj

    profile_entry = config_db.get_entry('MACSEC_PROFILE', profile)
    if len(profile_entry) == 0:
        ctx.fail("{} doesn't exist".format(profile))

    # Check if the profile is being used by any port
    for port in config_db.get_keys('PORT'):
        attr = config_db.get_entry('PORT', port)
        if 'macsec' in attr and attr['macsec'] == profile:
            ctx.fail("{} is being used by port {}, Please remove the MACsec from the port firstly".format(profile, port))

    config_db.set_entry("MACSEC_PROFILE", profile, None)


def register(cli):
    cli.add_command(macsec)


if __name__ == '__main__':
    macsec()
