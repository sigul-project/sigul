#!/usr/bin/python -tt

"""
    Initialize our database with some sample data
"""

import sys
import gpgme

from turbogears import update_config
update_config(configfile='dev.cfg', modulename='signserv.config')
from turbogears.database import PackageHub
hub = __connection__ = PackageHub("bodhi")
from signserv.model import Key, User, Group

keys = {
    '4F2A6FD2': {
        'name'        : 'fedora-gold',
        'description' : 'Fedora Project',
        'email'       : 'fedora@redhat.com'
    },

    '30C9ECF8': {
        'name'        : 'fedora-test',
        'description' : 'Fedora Project (Test Software)',
        'email'       : 'rawhide@redhat.com'
    },

    '1CDDBCA9': {
        'name'        : 'fedora-rawhide',
        'description' : 'Fedora Project automated build signing key',
        'email'       : 'rawhide@redhat.com'
    },

    'F5B783C4': {
        'name'        : 'signserv-test',
        'description' : 'Signing Server (Test key)',
        'email'       : 'nobody@fedoraproject.org',
        'passphrase'  : 'abcdefg'
    }
}

hub.begin()
print "Populating database with keys"
for key, value in keys.items():
    print Key(key_id=key, **value)


# import the keys locally
sec = open('signserv.sec', 'rb')
ctx = gpgme.Context()
result = ctx.import_(sec)
if result.imported:
    print "Successfully imported key"
else:
    print "Unable to import key"

if '--dev' in sys.argv:
    print "Initializing a guest releng user"
    releng = Group(group_name='releng', display_name='releng')
    guest = User(user_name='guest', display_name='guest',
                 email_address='foo@bar.com', password='guest')
    guest.addGroup(releng)
    print guest

hub.commit()
