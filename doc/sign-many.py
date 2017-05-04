#! /usr/bin/env python
import errno
import getpass
import os
import subprocess
import sys

def sign_rpm(list_file, args, passphrase):
    for rpm_id in open(list_file):
        rpm_id = rpm_id.rstrip('\n')
        child = subprocess.Popen(['sigul', '-v', '-v', '--batch', 'sign-rpm',
                                  '-o', '{0!s}.signed'.format(rpm_id)] + args + [rpm_id],
                                 stdin=subprocess.PIPE)
        child.stdin.write(passphrase + '\0')
        ret = child.wait()
        if ret != 0:
            sys.exit('Exit status {0:d}'.format(ret))
        print '{0!s} done'.format(rpm_id)

def sign_rpms(list_file, args, passphrase):
    rpms = [line.rstrip('\n') for line in open(list_file)]
    try:
        os.mkdir('signed')
    except OSError, e:
        if e.errno != errno.EEXIST:
            raise
    child = subprocess.Popen(['sigul', '-v', '-v', '--batch', 'sign-rpms',
                              '-o', 'signed'] + args + rpms,
                             stdin=subprocess.PIPE)
    child.stdin.write(passphrase + '\0')
    ret = child.wait()
    if ret != 0:
        sys.exit('Exit status {0:d}'.format(ret))
    print 'All done'

def main():
    if len(sys.argv) < 2:
        sys.exit('Usage: sign-many.py rpm_list other_sign-rpm_arguments\n'
                 'The other arguments should end with key name')
    passphrase = getpass.getpass('Key passphrase: ')
    if False:
        sign_rpm(sys.argv[1], sys.argv[2:], passphrase)
    else:
        sign_rpms(sys.argv[1], sys.argv[2:], passphrase)

if __name__ == '__main__':
    main()
