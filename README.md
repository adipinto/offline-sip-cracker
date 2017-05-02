<h3>Project description</h3>
Offline SIP Cracker is a very simple and optimized tool used to perform SIP authentication cracking through a dictionary-based attack. It can automatically parse a pcap file or get the authentication fields directly by command-line.

In the first case, the provided pcap file will be parsed looking for SIP authentication sessions which are correctly registered to the SIP registrar server.
In the second case, the user must provide SIP authentication fields manually using the command-line. This feature is useful when it is needed to perform specific tests.
The tool's main goal is to perform an optimized offline SIP authentication cracking which means there is no need to perform any network traffic. With the proposed approach it is possible to bypass firewall or IDS/IPS protection since it is only needed a passive traffic dump in order to retrieve the SIP authentication handshake.


<h3>Dependencies</h3>
Offline SIP Cracker is written in pure C language and it is optimized to compute MD5 digests using native EVP functions provided by OpenSSL library. In order to manage, parse and filter network traffic dumps, the application uses the PCAP library.

Software depends on following libraries:

  <b>OpenSSL</b> library to compute MD5 digests.

  <b>PCAP</b> library to parse and filter pcap files.

<h3>About</h3>
Developed by Alessandro Di Pinto
