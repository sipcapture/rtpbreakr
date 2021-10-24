/*
 * main.h by xenion -- 2008-05-05 -- v.50ea4697a08b7fa64400295ae63b67a1
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


/* const */

#define DEFAULT_OUTDIR "."

#define RTP_SEQWINDOW 200
#define RTP_TSWINDOW (500 * RTP_STREAM_PATTERN_PKTS)
#define RTP_STREAM_PATTERN_PKTS 5

// se un pkt sta nel buffer un tempo > di PKT_TIMEOUT, viene flushato
// se non arrivano pkt per un tempo > di PKT_TIMEOUT, la sessione viene
// considerata conclusa.
#define PKT_TIMEOUT 10.0
#define RTP_STREAM_PATTERN_TIMEOUT 0.25


/* types */

typedef struct
  {
    int verbose;
    char *rxfile;
    char *iface;
    char *outdir;
    int dllength;
    int fill_gaps;
    int rtp_hdr_pt;
    int udp_hdr_even_dst_port;
    int udp_hdr_unpriv_ports;
    char *mypcap_filter;
    float timeout_pkt;
    float timeout_pattern;
    int pattern_pkts;
    int rtp_payload_length;
    int dump_noise;
    char *user;
    int daemonize;
    int promisc;
    int syslog;
    int stdoutx;
    int dump_raw;
    int dump_pcap;
    int dump_wav;
    FILE *player;
  }
OPT;


typedef struct
  {
    struct pcap_pkt pcap;
    u_int32_t len; // length of udp payload (rtp header, extension and codec data).
    u_int32_t hdroff; // offset to reach the first udp byte, the rtp header.
    struct
      {
        u_int32_t off;
        u_int32_t len;
      }
    payload;
  }
pktrtp_t;


struct rtpbuf_entry
  {
    pktrtp_t pktrtp;
    LIST_ENTRY(rtpbuf_entry) l;
  };


LIST_HEAD(rtpbuf_head, rtpbuf_entry);


typedef struct
  {
#define ADDRS_TYPE_UNKNOWN 0
#define ADDRS_TYPE_IP 1
#define ADDRS_TYPE_TCP 2
#define ADDRS_TYPE_UDP 3
    int type;
    u_int32_t srcaddr;
    u_int32_t dstaddr;
    u_int16_t srcport;
    u_int16_t dstport;
  }
addrs_t;


struct rtp_stream_entry
  {
    int fid;
    int id;
    pcap_dumper_t *pdump;
    pcap_dumper_t *noise;
    FILE *f;
    FILE *raw;
    addrs_t addrs;
    u_int32_t ssrc;
    u_int32_t max_ts_seen; // max last timestamp seen
    u_int16_t max_seq_seen; // max last sequence seen
    u_int16_t last_seq_flhd; // last sequence flushed
    struct rtpbuf_head pkts; // buffered rtp packets
    struct timeval last_pkt;
    struct timeval first_pkt;
    u_int32_t pktcount_flhd;
    u_int32_t pktcount_inbuf;
    u_int32_t pktcount_lost;
    int pattern_found;
    int payload_type;
    u_int32_t last_payload_length;
    int payload_length_fixed;
    LIST_ENTRY(rtp_stream_entry) l; // list link
    struct rtp_stream_entry *rev;
    char command[1024];
  };


LIST_HEAD(rtp_streams_head, rtp_stream_entry);


struct rtp_streams_list
  {
    u_int32_t max_id;
    int32_t nclosed; // pattern not found and closed
    int32_t closed; //  pattern found and closed
    int32_t active; // active and pattern found
    u_int32_t pktcount_lost;
    u_int32_t pktcount_noise;
    u_int32_t pktcount;
    struct rtp_streams_head list;
  };


/* EOF */

