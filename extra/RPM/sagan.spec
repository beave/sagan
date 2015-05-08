%define		sagan_user	sagan
%define		sagan_group	sagan
%define		sagan_rules	4146f4f

Name:		sagan
Version:	1.0.0RC5
Release:	1%{?dist}
Summary:	High performance, real-time log analysis & correlation engine

Group:		Applications/System
License:	GPLv2
URL:		http://sagan.quadrantsec.com/
Source0:	http://sagan.quadrantsec.com/download/%{name}-%{version}.tar.gz
Source1:	%{name}-rules-%{sagan_rules}.tar.gz
Source2:	%{name}.logrotate
Source3:	%{name}.service
Source4:	%{name}.tmpfiles
Source5:	%{name}-setup.libexec
Patch0:		%{name}-sagan.conf.patch

BuildRequires:	GeoIP-devel
BuildRequires:	json-c-devel
BuildRequires:	libdnet-devel
BuildRequires:	libesmtp-devel
BuildRequires:	liblognorm1-devel >= 1.0.0
BuildRequires:	pcre-devel

Requires:	%{name}-rules

%systemd_requires


%description
Sagan is an open source (GNU/GPLv2) multi-threaded, high performance, real-time
log analysis & correlation engine developed by Quadrant Information Security
that runs on Unix operating systems. It is written in C and uses a
multi-threaded architecture to deliver high performance log & event analysis.
Sagan's structure and rules work similarly to the Sourcefire Snort IDS/IPS
engine. This allows Sagan to be compatible with Snort rule management software
and give Sagan the ability to correlate with Snort IDS/IPS data. Sagan can
record events to the Snort unified2 output format which makes Sagan compatible
with user interfaces such as Snorby, Sguil, BASE and proprietary consoles.

Sagan supports different output formats for reporting and analysis, log
normalization, script execution on event detection, automatic firewall support
via Snortsam, GeoIP detection/alerting, multi-line log support, and time
sensitive alerting.


%package rules
Release:	1.git%{sagan_rules}%{?dist}
Summary:	Sagan engine rule sets

Group:		Applications/System

BuildArch:	noarch


%description rules
This package contains the Sagan engine rule sets. You probably won't find these
useful unless you're actually using Sagan.


%prep
%setup -q
%patch -P0 -p1


%build
%configure \
	--sysconfdir=%{_sysconfdir}/%{name} \
	--enable-esmtp \
	--enable-geoip \
	--enable-libdnet \
	--enable-lognorm \
	--enable-snortsam
make %{?_smp_mflags}


%install
make install DESTDIR=%{buildroot}
rm -rf %{buildroot}%{_bindir}
tar -xzf %{S:1} -C %{buildroot}%{_sysconfdir}/%{name}
install -D -m 0644 %{S:2} %{buildroot}%{_sysconfdir}/logrotate.d/%{name}
install -D -m 0644 %{S:3} %{buildroot}%{_unitdir}/%{name}.service
install -D -m 0644 %{S:4} %{buildroot}%{_tmpfilesdir}/%{name}.conf
install -D -m 0755 %{S:5} %{buildroot}%{_libexecdir}/%{name}/%{name}-setup


%pre
getent group %{sagan_group} >/dev/null || \
	groupadd -r %{sagan_group}

getent passwd %{sagan_user} >/dev/null || \
	useradd -c "Sagan daemon" -d %{_localstatedir}/run/%{name} \
		-g %{sagan_group} -M -r -s /sbin/nologin %{sagan_user}


%post
%tmpfiles_create %{name}.conf
%systemd_post %{name}.service


%preun
%systemd_preun %{name}.service


%postun
%systemd_postun_with_restart %{name}.service


%files
%defattr(0644, root, root, 0755)
%doc AUTHORS ChangeLog COPYING FAQ INSTALL NEWS README TODO
%config(noreplace) %{_sysconfdir}/logrotate.d/%{name}
%attr(0640, root, %{sagan_group}) %config(noreplace) %{_sysconfdir}/%{name}/%{name}.conf
%attr(0750, root, %{sagan_group}) %dir %{_sysconfdir}/%{name}
%attr(0750, %{sagan_user}, %{sagan_group}) %dir %{_localstatedir}/log/%{name}
%attr(0750, %{sagan_user}, %{sagan_group}) %dir %{_localstatedir}/run/%{name}
%dir %{_libexecdir}/%{name}
%attr(0755, root, root) %{_libexecdir}/%{name}/%{name}-setup
%attr(0755, root, root) %{_sbindir}/%{name}
%{_mandir}/man8/sagan.8.gz
%{_tmpfilesdir}/%{name}.conf
%{_unitdir}/%{name}.service


%files rules
%defattr(0644, root, root, 0755)
%config(noreplace) %{_sysconfdir}/%{name}/%{name}-rules


%changelog
* Fri May  8 2015 Aleksey Chudov <aleksey.chudov@gmail.com> - 1.0.0RC5
- Build sagan-rules subpackage
* Fri Apr 17 2015 Aleksey Chudov <aleksey.chudov@gmail.com> - 1.0.0RC5
- Initial spec
