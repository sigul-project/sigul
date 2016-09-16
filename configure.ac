dnl Process this file with autoconf to produce a configure script.
AC_INIT([sigul], [0.201], [puiterwijk@redhat.com], ,
        [https://pagure.io/sigul/])
AC_COPYRIGHT(
[Copyright (C) 2009-2016 Red Hat, Inc.  All rights reserved.

This copyrighted material is made available to anyone wishing to use, modify,
copy, or redistribute it subject to the terms and conditions of the GNU General
Public License v.2.  This program is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY expressed or implied, including the implied
warranties of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.  You should have received a copy of
the GNU General Public License along with this program; if not, write to the
Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301, USA.  Any Red Hat trademarks that are incorporated in the source
code or documentation are not subject to the GNU General Public License and may
only be used or replicated with the express permission of Red Hat, Inc.

Red Hat Author: Miloslav Trmac <mitr@redhat.com>
Red Hat Author: Patrick Uiterwijk <puiterwijk@redhat.com>])
AC_PREREQ([2.63b])
AC_CONFIG_SRCDIR([src/server.py])
AC_CONFIG_AUX_DIR([admin])
AC_CONFIG_TESTDIR([.], [src])
AM_INIT_AUTOMAKE([dist-bzip2 no-define -Wall])

dnl Checks for programs.
AM_PATH_PYTHON([2.4])
dnl Not gpg2, it cannot receive passphrases from gpgme
AC_PATH_PROG([GPG], [gpg])
AC_ARG_VAR([GPG])
# This interface seems to be undocumented, but bison uses it ;-)
AM_MISSING_PROG([AUTOM4TE], [autom4te])

dnl For the OSTree helper
AC_PROG_CC
PKG_CHECK_MODULES([libostree], [ostree-1])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
