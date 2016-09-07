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

import logging
import subprocess

# Binding to a TPM1.2
def tpm_bind(value, pcrs=None):
    """This function seals data with a TPM1.2 using trousers.

    Extra arguments are optionally a list of PCRs (comma seperated) to which
    the data is to be bound and the SRK secret.
    If srk=None, the well known secret will be used.

    This assumes that the SRK secret is set to TSS_WELL_KNOWN.
    """
    cmd = ['tpm_sealdata', '--well-known']
    if pcrs:
        for pcr in pcrs.split(','):
            cmd.extend(['--pcr', pcr])
    proc = subprocess.Popen(cmd,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    (stdout, stderr) = proc.communicate(value)
    if proc.returncode != 0:
        logging.error('Unable to seal with TPM. RC: %i, stdout: %s, stderr: %s'
                      % (proc.returncode, stdout, stderr))
        return None, None
    return stdout, None

def tpm_unbind(value):
    """This function unseals data with a TPM1.2 using trousers.

    This assumes that the SRK secret is set to TSS_WELL_KNOWN.
    """
    cmd = ['tpm_unsealdata', '--srk-well-known', '--infile', '/dev/stdin']
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

def tpm(config):
    return (tpm_bind, tpm_unbind)


# Test binding method
def test_bind(passphrase, may_unbind):
    return passphrase, {'may_unbind': may_unbind}

def test_unbind(bound, may_unbind):
    if may_unbind != '1':
        return None
    return bound

def test(config):
    return (test_bind, test_unbind)
