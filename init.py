#!/usr/bin/python -tt

"""
    Initialize our database with some sample data
"""

from turbogears import update_config
update_config(configfile='dev.cfg', modulename='signserv.config')
from turbogears.database import PackageHub
hub = __connection__ = PackageHub("bodhi")
from signserv.model import Key

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
hub.commit()


# import the keys locally
import gpgme
sec = open('signserv.sec', 'rb')
ctx = gpgme.Context()
result = ctx.import_(sec)
if result.imported:
    print "Successfully imported key"
else:
    print "Unable to import key"
