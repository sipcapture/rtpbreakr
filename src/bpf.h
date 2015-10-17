/*-
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence
 * Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)bpf.h       7.1 (Berkeley) 5/7/91
 *
 */


#define AP_DLT_NULL  0 /* no link-layer encapsulation */
#define AP_DLT_EN10MB  1 /* Ethernet (10Mb) */
#define AP_DLT_EN3MB  2 /* Experimental Ethernet (3Mb) */
#define AP_DLT_AX25  3 /* Amateur Radio AX.25 */
#define AP_DLT_PRONET  4 /* Proteon ProNET Token Ring */
#define AP_DLT_CHAOS  5 /* Chaos */
#define AP_DLT_IEEE802  6 /* IEEE 802 Networks */
#define AP_DLT_ARCNET  7 /* ARCNET */
#define AP_DLT_SLIP  8 /* Serial Line IP */
#define AP_DLT_PPP  9 /* Point-to-point Protocol */
#define AP_DLT_FDDI  10 /* FDDI */
#define AP_DLT_ATM_RFC1483 11 /* LLC/SNAP encapsulated atm */

#if defined(__OpenBSD__)
#define AP_DLT_LOOP  12 /* old DLT_LOOP interface :4 byte offset */
#define AP_DLT_RAW              14      /* raw IP: 0 byte offset */
#else
#define AP_DLT_RAW              12      /* raw IP: 0 byte offset*/
#define AP_DLT_LOOP             108
#endif

#define AP_DLT_ENC  13
#define AP_DLT_SLIP_BSDOS 15 /* BSD/OS Serial Line IP */
#define AP_DLT_PPP_BSDOS 16 /* BSD/OS Point-to-point Protocol */
#define AP_DLT_ATM_CLIP  19 /* Linux Classical-IP over ATM */
#define AP_DLT_PPP_SERIAL 50 /* PPP over serial with HDLC encapsulation */
#define AP_DLT_PPP_ETHER 51 /* PPP over Ethernet */
#define AP_DLT_C_HDLC  104 /* Cisco HDLC */
#define AP_DLT_CHDLC  DLT_C_HDLC
#define AP_DLT_IEEE802_11 105 /* IEEE 802.11 wireless */
#define AP_DLT_LINUX_SLL 113
#define AP_DLT_LTALK  114
#define AP_DLT_ECONET  115
#define AP_DLT_IPFILTER  116
#define AP_DLT_PFLOG  117
#define AP_DLT_CISCO_IOS 118
#define AP_DLT_PRISM_HEADER 119
#define AP_DLT_AIRONET_HEADER 120
