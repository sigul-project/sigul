# Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use, modify,
# copy, or redistribute it subject to the terms and conditions of the GNU
# General Public License v.2.  This program is distributed in the hope that it
# will be useful, but WITHOUT ANY WARRANTY expressed or implied, including the
# implied warranties of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.  You should have
# received a copy of the GNU General Public License along with this program; if
# not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
# Floor, Boston, MA 02110-1301, USA.  Any Red Hat trademarks that are
# incorporated in the source code or documentation are not subject to the GNU
# General Public License and may only be used or replicated with the express
# permission of Red Hat, Inc.
#
# Red Hat Author: Patrick Uiterwijk <puiterwijk@redhat.com>

from getpass import getpass
import logging
import subprocess

# Binding to a TPM1.2
tpm_srk = None


def tpm_bind(value, pcrs=None):
    """This function seals data with a TPM1.2 using trousers.

    Extra arguments are optionally a list of PCRs (comma seperated) to which
    the data is to be bound and the SRK secret.
    If srk=None, the well known secret will be used.

    This assumes that the SRK secret is set to TSS_WELL_KNOWN.
    """
    global tpm_srk
    cmd = ['tpm_sealdata']
    if tpm_srk:
        value = tpm_srk + '\n' + value
    else:
        cmd.append('--well-known')

    if pcrs:
        for pcr in pcrs.split(','):
            cmd.extend(['--pcr', pcr])
    proc = subprocess.Popen(cmd,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    (stdout, stderr) = proc.communicate(value)
    if proc.returncode != 0:
        logging.error(
            'Unable to seal with TPM. RC: {0:d}, stdout: {1!s}, stderr: {2!s}'.
            format(proc.returncode, stdout, stderr))
        return None, None
    return stdout, None


def tpm_unbind(value):
    """This function unseals data with a TPM1.2 using trousers.

    This assumes that the SRK secret is set to TSS_WELL_KNOWN.
    """
    global tpm_srk
    cmd = ['tpm_unsealdata', '--infile', '/dev/stdin']
    if tpm_srk:
        value = tpm_srk + '\n' + value
    else:
        cmd.append('--srk-well-known')
    proc = subprocess.Popen(cmd,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    (stdout, stderr) = proc.communicate(value)
    if proc.returncode != 0:
        logging.error('Unable to unseal with TPM. RC: %i, stdout: %s, '
                      'stderr: %s'
                      % (proc.returncode, stdout, stderr))
        return None
    return stdout


def tpm(**config):
    global tpm_srk
    if 'srk' in config:
        tpm_srk = config['srk']
    elif 'nosrk' in config and config['nosrk']:
        tpm_srk = None
    else:
        tpm_srk = getpass('Enter TPM SRK: ')
    return (tpm_bind, tpm_unbind)


# Binding to PKCS11 token with openssl engine_pkcs11
pkcs11_config = {}


def pkcs11_bind(value, token):
    """This function binds data with a PKCS11 token using engine_pkcs11.

    Argument required is the token, which needs to have been configured in the
    config file.
    """
    global pkcs11_config

    if token not in pkcs11_config['tokens']:
        logging.error(
            'Binding attempted with unknown pkcs11 token {0!s}'.format(token))
        return None, None

    pubkey = pkcs11_config['{0!s}_pubkey'.format(token)]

    cmd = ['openssl', 'smime', '-encrypt', '-aes-256-cbc', pubkey]
    proc = subprocess.Popen(cmd,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    (stdout, stderr) = proc.communicate(value)
    if proc.returncode != 0:
        logging.error('Unable to bind with PKCS11 token %s. RC: %i, stdout: %s'
                      ', stderr: %s'
                      % (token, proc.returncode, stdout, stderr))
        return None, None
    return stdout, {'token': token}


def pkcs11_unbind(value, token):
    """This function unbinds data with engine_pkcs11.

    This requires that the token identified is configured.
    """
    global pkcs11_config

    if token not in pkcs11_config['tokens']:
        logging.error(
            'Unbinding attempted with unknown pkcs11 token {0!s}'.format(
                token))
        return None

    if ('{0!s}_privkey'.format(token)) not in pkcs11_config:
        logging.info(
            'Unbinding attempted with pubonly token {0!s}'.format(token))
        return None

    privkey = pkcs11_config['{0!s}_privkey'.format(token)]
    pin = pkcs11_config['{0!s}_pin'.format(token)]

    value = pin + '\n' + value

    cmd = ['openssl', 'smime', '-decrypt', '-keyform', 'engine', '-passin',
           'stdin', '-engine', 'pkcs11', '-inkey', privkey]
    proc = subprocess.Popen(cmd,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    (stdout, stderr) = proc.communicate(value)
    if proc.returncode != 0:
        logging.error('Unable to unbind with PKCS11 token %s. RC: %i, stdout: '
                      '%s, stderr: %s'
                      % (token, proc.returncode, stdout, stderr))
        return None
    return stdout


def pkcs11(tokens, **config):
    # Check config
    tokens = list(map(str.strip, tokens.split(',')))
    for token in tokens:
        # This is a lazy way of checking: it will just throw KeyError
        config['{0!s}_pubkey'.format(token)]
        assert 'pkcs11:' not in config['{0!s}_pubkey'.format(token)]

        if ('{0!s}_privkey'.format(token)) in config:
            assert 'pkcs11:' in config['{0!s}_privkey'.format(token)]

            if ('{0!s}_pin'.format(token)) not in config:
                config['{0!s}_pin'.format(token)] = getpass(
                    'PIN code for token "{0!s}": '.format(token))
            config['{0!s}_pin'.format(token)]

    global pkcs11_config
    # We primarily do the split here so that we fail early if required
    # arguments are not provided
    config['tokens'] = tokens
    pkcs11_config = config
    return (pkcs11_bind, pkcs11_unbind)


# Test binding method
def test_bind(passphrase, may_unbind):
    return passphrase, {'may_unbind': may_unbind}


def test_unbind(bound, may_unbind):
    if may_unbind != '1':
        return None
    return bound


def test():
    return (test_bind, test_unbind)
