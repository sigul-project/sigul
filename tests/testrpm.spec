Name: testrpm@N@
Version: 1
Release: 1
Summary: sigul test rpm @N@
Group: Development/Tools
License: GPLv2

%description
Test RPM @N@ for sigul.

%prep

%build

%install
mkdir -p "$RPM_BUILD_ROOT/tmp"
cat > "$RPM_BUILD_ROOT/tmp/file@N@" <<\EOF
testrpm@N@ file
EOF

%files
%defattr(-,root,root,-)
/tmp/file@N@
