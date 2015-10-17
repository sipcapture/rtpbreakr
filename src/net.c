/*
 * net.c by xenion -- 2008-05-05 -- v.0e2f795ca3b9af8bf863598b0a729ec4
 *
 * Copyright (c) 2007-2008 Dallachiesa Michele <micheleDOTdallachiesaATposteDOTit>
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */


#include <libnet.h>
#include <pcap.h>
#include "bpf.h"
#include "common.h"
#include "net.h"


/* macros */

#define CASE(x,y) { case (x): return y; break; }


/*******************************************/


int
sizeof_datalink(pcap_t * p)
{
  int             dtl;


  if ((dtl = pcap_datalink(p)) < 0)
    FATAL("pcap_datalink(): %s", pcap_geterr(p));

  switch (dtl)
    {

      CASE(AP_DLT_NULL, 4);
      CASE(AP_DLT_EN10MB, 14);
      CASE(AP_DLT_EN3MB, 14);
      CASE(AP_DLT_AX25, -1);
      CASE(AP_DLT_PRONET, -1);
      CASE(AP_DLT_CHAOS, -1);
      CASE(AP_DLT_IEEE802, 22);
      CASE(AP_DLT_ARCNET, -1);
#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__) || defined (__BSDI__)

      CASE(AP_DLT_SLIP, 16);
#else

      CASE(AP_DLT_SLIP, 24);
#endif

#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__)

      CASE(AP_DLT_PPP, 4);
#elif defined (__sun)

      CASE(AP_DLT_PPP, 8);
#else

      CASE(AP_DLT_PPP, 24);
#endif

      CASE(AP_DLT_FDDI, 21);
      CASE(AP_DLT_ATM_RFC1483, 8);

      CASE(AP_DLT_LOOP, 4);   /* according to OpenBSD DLT_LOOP */
      CASE(AP_DLT_RAW, 0);

      CASE(AP_DLT_SLIP_BSDOS, 16);
      CASE(AP_DLT_PPP_BSDOS, 4);
      CASE(AP_DLT_ATM_CLIP, -1);
#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__)

      CASE(AP_DLT_PPP_SERIAL, 4);
      CASE(AP_DLT_PPP_ETHER, 4);
#elif defined (__sun)

      CASE(AP_DLT_PPP_SERIAL, 8);
      CASE(AP_DLT_PPP_ETHER, 8);
#else

      CASE(AP_DLT_PPP_SERIAL, 24);
      CASE(AP_DLT_PPP_ETHER, 24);
#endif

      CASE(AP_DLT_C_HDLC, -1);
      CASE(AP_DLT_IEEE802_11, 30);
      CASE(AP_DLT_LINUX_SLL, 16);
      CASE(AP_DLT_LTALK, -1);
      CASE(AP_DLT_ECONET, -1);
      CASE(AP_DLT_IPFILTER, -1);
      CASE(AP_DLT_PFLOG, -1);
      CASE(AP_DLT_CISCO_IOS, -1);
      CASE(AP_DLT_PRISM_HEADER, -1);
      CASE(AP_DLT_AIRONET_HEADER, -1);

    default:
      FATAL("unknown datalink type DTL_?=%d", dtl);
      break;
    }

  return 0;
}


void
add_pcap_filter(pcap_t *p, char *s)
{
  struct bpf_program bpf_filter;

  if (!s)
    {
      LOG(1,1," ! The pcap filter is NULL, ignored");
      return;
    }

//  LOG(1,1," * Adding pcap_filter: '%s'", s);

  if (pcap_compile(p, &bpf_filter, s, 0, 0) < 0)
    FATAL("pcap_compile(): %s", pcap_geterr(p));

  if (pcap_setfilter(p, &bpf_filter) < 0)
    FATAL("pcap_setfilter(): %s", pcap_geterr(p));

  pcap_freecode(&bpf_filter);
}


/* EOF */


