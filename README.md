# ![RTPbreakR](http://i.imgur.com/CztZLDE.png)

RTPbreakR is just a hack made out of some old code _(RIP rtpbreak 2008)_ with hardcoded system commands, features barely suitable for lab testing (if anything) and should not be used. At all. Ever. This being said.

### Requirements:

* Compile:
  * ```libpcap-dev```, ```libnet-dev```
* Runtime:
  * ```ffmpeg``` and ```gnuplot``` installed on the target system

### Usage
```
$ rtpbreakr (-r|-i) <source> [options]
```

### Example
```
$ ./rtpbreakr -r /path/to/some/rtp.pcap -d /tmp
```

### Output:
```
/tmp/rtp.0.1.g711A
/tmp/rtp.0.1.txt
/tmp/rtp.0.1.wav
/tmp/rtp.0.1.wav.png
/tmp/rtp.0.2.g711A
/tmp/rtp.0.2.txt
/tmp/rtp.0.2.wav
/tmp/rtp.0.2.wav.png
/tmp/rtp.0.html
/tmp/rtp.0.txt

```
