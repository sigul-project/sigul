# Copyright (C) 2008, 2009 Red Hat, Inc.  All rights reserved.
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

## Process this file with automake to produce Makefile.in

## Settings
configdir = $(sysconfdir)/sigul
logdir = $(localstatedir)/log
piddir = $(localstatedir)/run
pythondir = $(pkgdatadir)
serverdatadir = $(localstatedir)/lib/sigul
AUTOMAKE_OPTIONS = subdir-objects

## Targets
bin_PROGRAMS = sigul-ostree-helper
sigul_ostree_helper_SOURCES = src/sigul-ostree-helper.c
sigul_ostree_helper_CFLAGS = $(libostree_CFLAGS)
sigul_ostree_helper_LDFLAGS = $(libostree_LIBS)
bin_SCRIPTS = src/sigul
dist_bin_SCRIPTS = src/sigul_setup_client
sbin_SCRIPTS = src/sigul_bridge src/sigul_server src/sigul_server_add_admin \
	src/sigul_server_create_db
dist_config_DATA = config/bridge.conf config/client.conf config/server.conf
man_MANS = doc/sigul.1 doc/sigul_bridge.8 doc/sigul_server.8 \
	doc/sigul_server_add_admin.8 doc/sigul_server_create_db.8
dist_man_MANS = doc/sigul_setup_client.1
python_PYTHON = src/bridge.py \
	src/client.py \
	src/double_tls.py \
	src/errors.py \
	src/server.py src/server_add_admin.py src/server_common.py \
	src/server_create_db.py \
	src/utils.py
nodist_python_PYTHON = src/settings.py

## Rules
CLEANFILES = $(bin_SCRIPTS) $(sbin_SCRIPTS) $(man_MANS) $(nodist_python_PYTHON)
DISTCLEANFILES = atconfig
EXTRA_DIST = doc/data-design.txt doc/protocol-design.txt \
	doc/sigul.1.in doc/sigul_bridge.8.in doc/sigul_server.8.in \
	doc/sigul_server_add_admin.8.in doc/sigul_server_create_db.8.in \
	doc/sign-many.py \
	src/script.in src/settings.py.in \
	tests/testsuite tests/package.m4 tests/testsuite.at $(TESTFILES) \
	tests/imported-public-key.asc tests/imported-secret-key.asc \
	tests/new-key-substitute.asc tests/testrpm.spec
TESTFILES = tests/basic.at

doc/sigul.1: doc/sigul.1.in Makefile
	$(MKDIR_P) doc
	sed -e 's|@''configdir''@|$(configdir)|g' \
		< $(srcdir)/doc/sigul.1.in > $@

doc/sigul_bridge.8: doc/sigul_bridge.8.in Makefile
	$(MKDIR_P) doc
	sed -e 's|@''configdir''@|$(configdir)|g' \
		-e 's|@''piddir''@|$(piddir)|g' \
		< $(srcdir)/doc/sigul_bridge.8.in > $@

doc/sigul_server.8: doc/sigul_server.8.in Makefile
	$(MKDIR_P) doc
	sed -e 's|@''configdir''@|$(configdir)|g' \
		-e 's|@''piddir''@|$(piddir)|g' \
		< $(srcdir)/doc/sigul_server.8.in > $@

doc/sigul_server_add_admin.8: doc/sigul_server_add_admin.8.in Makefile
	$(MKDIR_P) doc
	sed -e 's|@''configdir''@|$(configdir)|g' \
		< $(srcdir)/doc/sigul_server_add_admin.8.in > $@

doc/sigul_server_create_db.8: doc/sigul_server_create_db.8.in Makefile
	$(MKDIR_P) doc
	sed -e 's|@''configdir''@|$(configdir)|g' \
		< $(srcdir)/doc/sigul_server_create_db.8.in > $@

src/settings.py: src/settings.py.in Makefile
	$(MKDIR_P) src
	sed -e 's|@''GPG''@|$(GPG)|g' \
		-e 's|@''PACKAGE_VERSION''@|$(PACKAGE_VERSION)|g' \
		-e 's|@''configdir''@|$(configdir)|g' \
		-e 's|@''logdir''@|$(logdir)|g' \
		-e 's|@''piddir''@|$(piddir)|g' \
		-e 's|@''serverdatadir''@|$(serverdatadir)|g' \
		< $(srcdir)/src/settings.py.in > $@

src/sigul: src/script.in Makefile
	$(MKDIR_P) src
	sed -e 's|@''PYTHON''@|$(PYTHON)|g' \
		-e 's|@''pkgdatadir''@|$(pkgdatadir)|g' \
		-e 's|@''program''@|client|g' \
		< $(srcdir)/src/script.in > $@
	chmod a+x $@

src/sigul_bridge: src/script.in Makefile
	$(MKDIR_P) src
	sed -e 's|@''PYTHON''@|$(PYTHON)|g' \
		-e 's|@''pkgdatadir''@|$(pkgdatadir)|g' \
		-e 's|@''program''@|bridge|g' \
		< $(srcdir)/src/script.in > $@
	chmod a+x $@

src/sigul_server: src/script.in Makefile
	$(MKDIR_P) src
	sed -e 's|@''PYTHON''@|$(PYTHON)|g' \
		-e 's|@''pkgdatadir''@|$(pkgdatadir)|g' \
		-e 's|@''program''@|server|g' \
		< $(srcdir)/src/script.in > $@
	chmod a+x $@

src/sigul_server_add_admin: src/script.in Makefile
	$(MKDIR_P) src
	sed -e 's|@''PYTHON''@|$(PYTHON)|g' \
		-e 's|@''pkgdatadir''@|$(pkgdatadir)|g' \
		-e 's|@''program''@|server_add_admin|g' \
		< $(srcdir)/src/script.in > $@
	chmod a+x $@

src/sigul_server_create_db: src/script.in Makefile
	$(MKDIR_P) src
	sed -e 's|@''PYTHON''@|$(PYTHON)|g' \
		-e 's|@''pkgdatadir''@|$(pkgdatadir)|g' \
		-e 's|@''program''@|server_create_db|g' \
		< $(srcdir)/src/script.in > $@
	chmod a+x $@

clean-local:
	$(SHELL) $(top_srcdir)/tests/testsuite --clean

installcheck-local: atconfig $(top_srcdir)/tests/testsuite
	$(SHELL) $(top_srcdir)/tests/testsuite \
		AUTOTEST_PATH=$(bindir):$(sbindir)

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(logdir) $(DESTDIR)$(piddir) \
		$(DESTDIR)$(serverdatadir)/gnupg
	chmod 0700 $(DESTDIR)$(serverdatadir) $(DESTDIR)$(serverdatadir)/gnupg

$(top_srcdir)/tests/package.m4: $(top_srcdir)/configure.ac
	{								   \
	  echo '# Signature of the current package.';			   \
	  echo 'm4_define([AT_PACKAGE_NAME],      [@PACKAGE_NAME@])';	   \
	  echo 'm4_define([AT_PACKAGE_TARNAME],   [@PACKAGE_TARNAME@])';   \
	  echo 'm4_define([AT_PACKAGE_VERSION],   [@PACKAGE_VERSION@])';   \
	  echo 'm4_define([AT_PACKAGE_STRING],    [@PACKAGE_STRING@])';	   \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [@PACKAGE_BUGREPORT@])'; \
	  echo 'm4_define([AT_PACKAGE_URL],       [@PACKAGE_URL@])';	   \
	} >$(top_srcdir)/tests/package.m4

$(top_srcdir)/tests/testsuite: tests/package.m4 tests/testsuite.at $(TESTFILES)
	$(AUTOM4TE) --language=autotest -I $(top_srcdir)/tests \
		$(top_srcdir)/tests/testsuite.at -o $@.tmp
	mv $@.tmp $@

atconfig: $(top_builddir)/config.status
	cd $(top_builddir) && $(SHELL) ./config.status ./atconfig
