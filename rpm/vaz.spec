Summary:          Management linux package on veeta.org.
Name:             vaz
Version:          0.0.1
Release:          1
License:          GPLv3
URL:              https://github.com/pyama86/vaz
Group:            System Environment/Base
Packager:         pyama86<www.kazu.com@gmail.com>
BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:        i386, x86_64

Source0:   %{name}.initd
Source2:   %{name}.logrotate
Source3:   %{name}.conf.sample

Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig, /sbin/service
Requires(postun): /sbin/service
Requires: yum-utils

%define debug_package %{nil}

%description
Get the version of the linux package and report it to veeta.org. You can use veeta.org to manage vulnerable packages.

%build

%install
%{__rm} -rf %{buildroot}
mkdir -p %{buildroot}/usr/bin
install -m 755 %{_sourcedir}/%{name} %{buildroot}/usr/bin/%{name}
mkdir -p %{buildroot}%{_sysconfdir}
install -m 644 %{_sourcedir}/%{name}.conf.sample %{buildroot}%{_sysconfdir}/%{name}.conf.sample

install -d -m 755 %{buildroot}/%{_localstatedir}/log/

install -d -m 755 %{buildroot}/%{_initrddir}
install    -m 755 %{_sourcedir}/%{name}.initd        %{buildroot}/%{_initrddir}/%{name}


install -d -m 755 %{buildroot}/%{_sysconfdir}/logrotate.d/
install    -m 644 %{_sourcedir}/%{name}.logrotate %{buildroot}/%{_sysconfdir}/logrotate.d/%{name}

%clean
%{__rm} -rf %{buildroot}

%post
chkconfig --add %{name}

%preun
if [ $1 = 0 ]; then
  service %{name} stop > /dev/null 2>&1
  chkconfig --del %{name}
fi

%postun

%files
%defattr(-, root, root)
/usr/bin/vaz
/etc/vaz.conf.sample
%{_initrddir}/%{name}
%{_sysconfdir}/logrotate.d/%{name}

%changelog
* Mon Sep 18 2017 pyama86 <www.kazu.com@gmail.com> - 0.0.1-1
- Pre Release
