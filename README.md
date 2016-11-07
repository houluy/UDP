# UDP
UDP implementation using RAW SOCKET in Python 3.4

UDP checksum

one’s complement

(1) Construct the UDP header and UDP Pseudo header, as illustrated below, where Checksum is set zero at first.  
(2) Check the length of data, if it is an odd length of bytes, supplement a byte of zero (0x00) at the end of the data when counting checksum (This is important, not on the real data).  
(3) Form the sequence of bytes in the order: Pseudo header-\>UDP header-\>data.  
(4) Loop through the sequence and pull out two bytes each time (It is an even sequence because of the supplement), left shift the first byte for eight bits, then add the second byte. As a consequence, they become a 2-byte-long number.  
(5) Sum these 2-byte-long numbers. Add also the carries if there’s any of them. Make sure checksum stays 2-byte-long.  
(6) At the end of the loop, invert all the bits of the checksum, and take the last 16 bits as the final checksum.  

UDP Field:  
```
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|      Source     |   Destination   |
|       Port      |       Port      |
+--------+--------+--------+--------+
|      Length     |     Checksum    |
+--------+--------+--------+--------+
|
|        data octets ...
+--------------- ...
```
UDP Pseudo Header  
```
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|           source address          |
+--------+--------+--------+--------+
|        destination address        |
+--------+--------+--------+--------+
|  zero  |protocol|    UDP length   | 
+--------+--------+--------+--------+
```
IP Header  
```
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|Ver.|IHL|DSCP|ECN|   Total length  |
+--------+--------+--------+--------+
|  Identification |Flags|   Offset  |
+--------+--------+--------+--------+
|   TTL  |Protocol| Header Checksum |
+--------+--------+--------+--------+
|         Source IP address         |
+--------+--------+--------+--------+
|       Destination IP address      |
+--------+--------+--------+--------+
```
