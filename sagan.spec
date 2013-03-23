Name:		sagan
Version:	0.3.0git20130322
Release:	1%{?dist}
Summary:	Sagan is a multi-threaded, real time system and event log monitoring system, but with a twist.

License:	GPLv2
URL:		http://sagan.quadrantsec.com/
Source0:	http://sagan.quadrantsec.com/download/sagan-%{version}.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:	pcre-devel libesmtp-devel libpcap-devel libdnet-devel liblognorm-devel
Requires(pre):	shadow-utils
Requires:	pcre libesmtp libpcap libdnet liblognorm

%description
Sagan is a high performance, real-time log analysis & correlation engine. It uses a multi-threaded architecture to deliver high performance log & event analysis. Sagan's structure and rules work similarly to the Sourcefire "Snort" IDS/IPS engine.


%prep
%setup -q


%build
%configure --enable-esmtp
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
rm -rf $RPM_BUILD_ROOT/usr/bin/sagan


%clean
rm -rf $RPM_BUILD_ROOT

%pre
getent group sagan >/dev/null || groupadd -r sagan
getent passwd sagan >/dev/null || \
	useradd -r -g sagan -G adm -d /var/run/sagan -s /sbin/nologin \
		-c "Sagan user" sagan && \
	mkdir /var/run/sagan && chown sagan:sagan /var/run/sagan && \
	mkdir /var/log/sagan && chown sagan:sagan /var/log/sagan && \
	[ -x /sbin/restorecon ] && /sbin/restorecon /var/run/sagan /var/log/sagan
exit 0

%post
mkfifo /var/run/sagan.fifo
chown sagan:sagan /var/run/sagan.fifo

%preun
%{__rm} /var/run/sagan.fifo

%files
%defattr(-,root,root,-)
%doc
%{_mandir}/man?/*
/etc/sagan.conf
/usr/sbin/sagan
%attr(0644,sagan,sagan) %ghost /var/run/sagan.fifo
%dir /var/log/sagan
%dir /var/run/sagan

%changelog
* Fri Mar 22 2013 Stas Alekseev - 0.3.0git20130322-1
- Updated to build with the latest version from GIT.

* Thu Mar 21 2013 Stas Alekseev - 0.2.3-1
- Initial package.

