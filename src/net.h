/*
 * net.h by xenion -- 2008-05-05 -- v.9f90fb024b189a85013c576f412984a6
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

#ifndef NET_H
#define NET_H

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>
#include "bpf.h"
#include "ieee80211.h"

/* macros */

#define INET_NTOA(x) (inet_ntoa(*((struct in_addr *)&(x))))

#define SAFE_PCAP_CLOSE(x) do { if (x) { pcap_close(x); x = NULL; }}while(0)
#define SAFE_LIBNET_CLOSE(x) do { if (x) { libnet_destroy(x); x = NULL; }}while(0)


/* types */

struct pcap_pkt
  {
    struct    pcap_pkthdr hdr;
    u_int8_t *pkt;
    u_int16_t dllength;
    u_int16_t dlltype;
  } ;


/* protos */

extern int sizeof_datalink(pcap_t * p);
extern void add_pcap_filter(pcap_t *p, char *s);


#endif

/* EOF */

