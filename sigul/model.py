# This copyrighted material is made available to anyone wishing to use, modify,
# copy, or redistribute it subject to the terms and conditions of the GNU
# General Public License v.2.  This program is distributed in the hope that it
# will be useful, but WITHOUT ANY WARRANTY expressed or implied, including the
# implied warranties of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.  You should have
# received a copy of the GNU General Public License along with this program;
# if not, write to the Free Software Foundation, Inc., 51 Franklin Street,
# Fifth Floor, Boston, MA 02110-1301, USA. Any Red Hat trademarks that are
# incorporated in the source code or documentation are not subject to the GNU
# General Public License and may only be used or replicated with the express
# permission of Red Hat, Inc.
#
# Copyright (C) 2007  Red Hat, Inc. All rights reserved.
# Author: Luke Macken <lmacken@redhat.com>

import logging

from datetime import datetime
from sqlobject import *
from turbogears import identity
from turbogears.database import PackageHub

log = logging.getLogger(__name__)
hub = PackageHub("sigul")
__connection__ = hub

class KeyNotFound(Exception):
    pass

class Key(SQLObject):
    name        = UnicodeCol(alternateID=True, notNone=True)
    key_id      = UnicodeCol(notNone=True)
    email       = UnicodeCol(notNone=True)
    passphrase  = UnicodeCol(default="")
    description = UnicodeCol()

    @staticmethod
    def fetch(id):
        """ Fetch a Key by name, id, or email """
        keys = Key.select(
                OR(Key.q.name == id,
                   Key.q.key_id == id,
                   Key.q.email == id))
        if not keys.count():
            raise KeyNotFound("No key id/name/email matches '%s'" % id)
        return keys[0]

    def __str__(self):
        return u"[%s] %s : %s <%s>" % (self.key_id, self.name,
                                       self.description, self.email)

class Visit(SQLObject):
    """ A visit to your site """
    visit_key = StringCol(length=40, alternateID=True,
                          alternateMethodName='by_visit_key')
    created = DateTimeCol(default=datetime.now)
    expiry = DateTimeCol()

    def lookup_visit(cls, visit_key):
        try:
            return cls.by_visit_key(visit_key)
        except SQLObjectNotFound:
            return None
    lookup_visit = classmethod(lookup_visit)


class VisitIdentity(SQLObject):
    """ A Visit that is link to a User object """
    visit_key = StringCol(length=40, alternateID=True,
                          alternateMethodName='by_visit_key')
    user_id = IntCol()


class Group(SQLObject):
    """
    An ultra-simple group definition.
    """
    # names like "Group", "Order" and "User" are reserved words in SQL
    # so we set the name to something safe for SQL
    class sqlmeta:
        table = 'tg_group'

    group_name = UnicodeCol(length=16, alternateID=True,
                            alternateMethodName='by_group_name')
    display_name = UnicodeCol(length=255)
    created = DateTimeCol(default=datetime.now)

    # collection of all users belonging to this group
    users = RelatedJoin('User', intermediateTable='user_group',
                        joinColumn='group_id', otherColumn='user_id')

    # collection of all permissions for this group
    permissions = RelatedJoin('Permission', joinColumn='group_id',
                              intermediateTable='group_permission',
                              otherColumn='permission_id')


class User(SQLObject):
    """
    Reasonably basic User definition.
    Probably would want additional attributes.
    """
    # names like "Group", "Order" and "User" are reserved words in SQL
    # so we set the name to something safe for SQL
    class sqlmeta:
        table = 'tg_user'

    user_name = UnicodeCol(length=16, alternateID=True,
                           alternateMethodName='by_user_name')
    email_address = UnicodeCol(length=255, alternateID=True,
                               alternateMethodName='by_email_address')
    display_name = UnicodeCol(length=255)
    password = UnicodeCol(length=40)
    created = DateTimeCol(default=datetime.now)

    # groups this user belongs to
    groups = RelatedJoin('Group', intermediateTable='user_group',
                         joinColumn='user_id', otherColumn='group_id')

    def _get_permissions(self):
        perms = set()
        for g in self.groups:
            perms = perms | set(g.permissions)
        return perms

    def _set_password(self, cleartext_password):
        "Runs cleartext_password through the hash algorithm before saving."
        password_hash = identity.encrypt_password(cleartext_password)
        self._SO_set_password(password_hash)

    def set_password_raw(self, password):
        "Saves the password as-is to the database."
        self._SO_set_password(password)


class Permission(SQLObject):
    """
    A relationship that determines what each Group can do
    """
    permission_name = UnicodeCol(length=16, alternateID=True,
                                 alternateMethodName='by_permission_name')
    description = UnicodeCol(length=255)

    groups = RelatedJoin('Group',
                         intermediateTable='group_permission',
                         joinColumn='permission_id',
                         otherColumn='group_id')
