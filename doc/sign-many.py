#! /usr/bin/env python
import getpass
import subprocess
import sys

def main():
    if len(sys.argv) < 2:
        sys.exit('Usage: sign-many.py rpm_list other_sign-rpm_arguments\n'
                 'The other arguments should end with key name')
    passphrase = getpass.getpass('Key passphrase: ')
    for rpm_id in open(sys.argv[1]):
        rpm_id = rpm_id.rstrip('\n')
        child = subprocess.Popen(['sigul', '-v', '-v', '--batch', 'sign-rpm',
                                  '-o', '%s.signed' % rpm_id]
                                 + sys.argv[2:] + [rpm_id],
                                 stdin=subprocess.PIPE)
        child.stdin.write(passphrase + '\0')
        ret = child.wait()
        if ret != 0:
            sys.exit('Exit status %d' % ret)
        print '%s done' % (rpm_id,)

if __name__ == '__main__':
    main()
