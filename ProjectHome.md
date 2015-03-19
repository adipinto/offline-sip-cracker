# Project description #
Offline SIP Cracker, it's a very simple and optimized tool used to perform SIP authentication cracking through a dictionary-based attack. It can automatically parse _pcap file_ or get authentication fields by command-line.

  * In first case, provided pcap file will be parsed in order to search SIP authentication sessions correctly registered with SIP registrar server.
  * In second case, the penetration tester can provide SIP authentication fields manually through a command-line. This feature helps in case it's need to perform specific tests.

Main target of Offline SIP Cracker is to perform an optimized **offline** SIP authentication cracking, which means that it isn't needed any network traffic in order to perform a session cracking. With the described approach it's possible to bypass firewall or IDS/IPS protection since there's only needed a passive traffic dump, to stole the SIP authentication handshake.

# Dependencies #
Offline SIP Cracker is written in pure C language and it's optimized to compute MD5 digests using native EVP functions provided by OpenSSL library. In order to manage, parse and filter network traffic dumps, application uses PCAP library.

Software depends on following libraries:
  * [OpenSSL library](http://www.openssl.org/) to compute MD5 digests.
  * [PCAP library](http://www.tcpdump.org) to parse and filter pcap files.

# About #
Developed by Alessandro Di Pinto