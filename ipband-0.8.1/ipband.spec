Summary: IP bandwidth watchdog.
Name: ipband 
Version: 0.8.1
Release: 1
License: GPL
Group: Applications/Network
Source: ipband-0.8.1.tgz
Requires: libpcap

%description
ipband is pcap based IP traffic monitor.  It listens to a
network interface in promiscuous mode, tallies  per-subnet
traffic and bandwidth usage and starts detailed logging if
specified threshold for the specific subnet is exceeded.
 
This utility could be handy in  a  limited  bandwidth  WAN
environment  (frame relay, ISDN etc. circuits) to pinpoint
offending traffic source if certain links become saturated
to  the  point  where  legitimate  packets  start  getting
dropped.

%prep
%setup

%build
make

%install
make install

%post
chkconfig --add ipband

%files
/usr/share/man/man8/ipband.8
/usr/sbin/ipband
/etc/ipband.sample.conf
/etc/rc.d/init.d/ipband
