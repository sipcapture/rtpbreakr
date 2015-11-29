# ![RTPbreakR](http://i.imgur.com/CztZLDE.png)

[![Build Status](https://travis-ci.org/sipcapture/rtpbreakr.svg?branch=master)](https://travis-ci.org/sipcapture/rtpbreakr)

### Requirements:

* Compile:
  * ```libpcap-dev```, ```libnet-dev```
* Runtime:
  * ```ffmpeg 2.x``` and ```gnuplot 4.4``` installed on the target system
   
 NOTE: For older ffmpeg versions (0.x) use [this version](https://github.com/sipcapture/rtpbreakr/tree/oldffmpeg)

### Usage
```
$ rtpbreakr (-r|-i) <source> [options]
```

### Example with n2disk Timeline
```
$ ./npcapextract -t /tmp/n2disk/timeline -b "2015-10-18 12:10:00" -e "2015-10-18 12:20:00" -o /path/to/rtp.pcap -f "((udp) and ((port 7800) or (port 32402)) and ((host 192.168.1.254) or (host 192.168.1.200)))” 
$ ./rtpbreakr -r /path/to/rtp.pcap -d /tmp
```

### Output:
```
/tmp/rtp.0.1.g711A
/tmp/rtp.0.1.txt
/tmp/rtp.0.1.mp3
/tmp/rtp.0.1.mp3.png
/tmp/rtp.0.2.g711A
/tmp/rtp.0.2.txt
/tmp/rtp.0.2.mp3
/tmp/rtp.0.2.mp3.png
/tmp/rtp.0.html
/tmp/rtp.0.txt

```
![mugshot](http://i.imgur.com/AnsJPOV.png)
