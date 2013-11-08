#
# spec file for package yast2-kerberos-server
#
# Copyright (c) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


Name:           yast2-kerberos-server
Version:        3.1.1
Release:        0

BuildRoot:      %{_tmppath}/%{name}-%{version}-build
Source0:        %{name}-%{version}.tar.bz2

Group:	        System/YaST
License:        GPL-2.0
#Wizard::SetDesktopTitleAndIcon
Requires:       yast2 >= 2.21.22
Requires:	yast2-ldap-client yast2-kerberos-client
BuildRequires:	perl-XML-Writer update-desktop-files yast2 yast2-testsuite yast2-ldap-client
BuildRequires:  yast2-devtools >= 3.0.6

BuildArchitectures:	noarch

Requires:       yast2-ruby-bindings >= 1.0.0

Summary:	YaST2 - Kerberos Server Configuration

%description
Provides basic configuration of a Kerberos server over the YaST2
Control Center.

%prep
%setup -n %{name}-%{version}

%build
%yast_build

%install
%yast_install


%files
%defattr(-,root,root)
%dir %{yast_yncludedir}/kerberos-server
%{yast_yncludedir}/kerberos-server/*
%{yast_clientdir}/kerberos-server.rb
%{yast_moduledir}/KerberosServer.*
%{yast_desktopdir}/kerberos-server.desktop
%{yast_scrconfdir}/*.scr
%{yast_agentdir}/*
%doc %{yast_docdir}
