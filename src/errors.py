# Copyright (C) 2008 Red Hat, Inc.  All rights reserved.
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
# Red Hat Author: Miloslav Trmac <mitr@redhat.com>

OK = 0
UNKNOWN_VERSION = 1
UNKNOWN_OP = 2
AUTHENTICATION_FAILED = 3
ALREADY_EXISTS = 4
USER_NOT_FOUND = 5
USER_HAS_KEY_ACCESSES = 6
KEY_USER_NOT_FOUND = 7
KEY_NOT_FOUND = 8
UNKNOWN_ERROR = 9
ONLY_ONE_KEY_USER = 10
CORRUPT_RPM = 11
UNAUTHENTICATED_RPM = 12
INVALID_IMPORT = 13
IMPORT_PASSPHRASE_ERROR = 14
DECRYPT_FAILED = 15
UNSUPPORTED_KEYTYPE = 16

_messages = {
    OK: 'No error',
    UNKNOWN_VERSION: 'Unknown protocol version',
    UNKNOWN_OP: 'Unknown operation',
    AUTHENTICATION_FAILED: 'Authentication failed',
    ALREADY_EXISTS: 'The specified object already exists',
    USER_NOT_FOUND: 'The specified user was not found',
    USER_HAS_KEY_ACCESSES: 'The specified user can access one or more keys',
    KEY_USER_NOT_FOUND: 'The specified user can not access this key',
    KEY_NOT_FOUND: 'The specified key was not found',
    UNKNOWN_ERROR: 'Unknown error',
    ONLY_ONE_KEY_USER: 'This is the only user with access to this key',
    CORRUPT_RPM: 'The RPM file is corrupt',
    UNAUTHENTICATED_RPM: 'Missing RPM file authentication by client',
    INVALID_IMPORT: 'Invalid import file',
    IMPORT_PASSPHRASE_ERROR: 'Import passphrase does not match',
    DECRYPT_FAILED: 'Decryption failed',
    UNSUPPORTED_KEYTYPE: 'Unsupported keytype for operation',
}


def message(error_code):
    '''Return an error message for error_code.'''
    if error_code in _messages:
        return _messages[error_code]
    return 'Error {0:d}'.format(error_code)
