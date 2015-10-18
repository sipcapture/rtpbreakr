/*
 * main.c by xenion -- 2008-05-05 -- v.262c5cbb0ef3c107aae3316bca65296f
 *
 * Copyright (c) 2007-2008 Dallachiesa Michele <micheleDOTdallachiesaATposteDOTit>
 * Copyright (c) 2015 QXIP BV (info@qxip.net))
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


/* includes */

#include <time.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <linux/udp.h>
#include "queue.h"
#include "rtp.h"
#include "common.h"
#include "net.h"
#include "main.h"


/* globals */

struct rtp_streams_list rtp_streams;
pcap_t *mypcap = NULL;
pcap_dumper_t *pdump_noise = NULL;
struct timeval pcap_time;
u_int32_t pktcount = 0;
int ndxlog = -1;
int running = 0;
char errbuf[PCAP_ERRBUF_SIZE];
OPT o;


/* protos */

int dissect_ieee80211(struct pcap_pkt *ppkt, u_int32_t pktoff, u_int32_t pktlen);
int dissect_eth(struct pcap_pkt *ppkt, u_int32_t pktoff, u_int32_t pktlen);
int dissect_ip(struct pcap_pkt *ppkt, u_int32_t pktoff, u_int32_t pktlen);
int dissect_udp(struct pcap_pkt *ppkt,u_int32_t pktoff, u_int32_t pktlen, addrs_t addrs);
int dissect_rtp(struct pcap_pkt *ppkt,u_int32_t pktoff, u_int32_t pktlen, addrs_t addrs);
char *find_stream_rtp_pt(int pt, int short_vals);
void loop(int dlltype, int dllength);
int main(int argc, char **argv);
void            init_opt(int argc, char **argv);
void help();
void cleanup();
int timeout(struct timeval *a, struct timeval *b, float t);
struct rtp_stream_entry *rtp_search_stream(addrs_t addrs, rtp_hdr_t *rtphdr);
int rtp_stream_ts_seq_check(struct rtp_stream_entry *rtp_stream);
char *strtime(time_t t);
void rtp_streams_init();
void rtp_stream_add_pkt(struct rtp_stream_entry *rtp_stream, pktrtp_t *pktrtp);
void rtp_stream_flush(struct rtp_stream_entry *rtp_stream, int buf_timeout);
void rtp_stream_open_files(struct rtp_stream_entry *rtp_stream);
struct rtp_stream_entry *rtp_stream_add(pktrtp_t *pktrtp, addrs_t addrs);
void rtp_stream_close(struct rtp_stream_entry *rtp_stream);
void rtp_streams_close();
int rtp_pkt_handle(pktrtp_t *pktrtp, addrs_t addrs);
void rtp_streams_timeout();
void rtp_stream_search_rev(struct rtp_stream_entry *rtp_stream);
void sig_stats_handler(int signo);
void print_stream_stat(struct rtp_stream_entry *rtp_stream);


/* extern */

// here because in order to have this function defined,
// I should add #define _XOPEN_SOURCE=600 that brokens
// other things.
float strtof(const char *nptr, char **endptr);


/*******************************************/


int rtp_stream_ts_seq_check(struct rtp_stream_entry *rtp_stream)
{
  struct rtpbuf_entry *rtpbuf;
  rtp_hdr_t *rtphdr;
  int64_t prev_ts,v;
  int32_t prev_seq;


  prev_seq = -1;
  prev_ts = -1;

  LIST_FOREACH(rtpbuf, &rtp_stream->pkts, l)
  {
    rtphdr = (rtp_hdr_t *)(rtpbuf->pktrtp.pcap.pkt + rtpbuf->pktrtp.hdroff);

    if (prev_seq != -1 && (u_int16_t)(prev_seq+1) != ntohs(rtphdr->seq))
      return -1;
    prev_seq = ntohs(rtphdr->seq);

    v = (u_int32_t)ntohl(rtphdr->ts);
    if (v < rtp_stream->max_ts_seen) // maybe mod loop!!
      v += ((u_int32_t)(0-1))+1;
    //LOG(1,1,"ts: %llu",v);
    if (prev_ts > v)
      return -1;
    prev_ts = v;
  }

  return 0;
}


int dissect_ieee80211(struct pcap_pkt *ppkt, u_int32_t pktoff, u_int32_t pktlen)
{
  struct ieee80211_frame *wh;
  int32_t len;


  if (pktlen < sizeof(struct ieee80211_frame))
    {
      LOG(1,1," * warning: broken ieee 802.11 frame");
    }

  wh = (struct ieee80211_frame *)(ppkt->pkt+pktoff);

  len = sizeof(struct ieee80211_frame);

  if ((wh->i_fc[0]&IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_DATA)
    return 0;

  if ((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS)
    len += IEEE80211_ADDR_LEN;
  if (IEEE80211_QOS_HAS_SEQ(wh))
    len += sizeof(u_int16_t);

  len+=8;

  if (len > pktlen) // this packet is something not interesting
    {
      return 0;
    }

  if ( ntohs(*((int32_t *)&ppkt->pkt[len-2])) == ETHERTYPE_IP)
    return dissect_ip(ppkt,len,ppkt->hdr.caplen-len);

  return 0;
}


int dissect_eth(struct pcap_pkt *ppkt, u_int32_t pktoff, u_int32_t pktlen)
{
  struct libnet_ethernet_hdr *eth;


  if (pktlen < sizeof(struct libnet_ethernet_hdr))
    {
      LOG(1,1,"broken eth frame");
      return 0;
    }

  eth = (struct libnet_ethernet_hdr *)ppkt->pkt+pktoff;

  if (ntohs(eth->ether_type) == ETHERTYPE_IP)
    return dissect_ip(ppkt,sizeof(struct libnet_ethernet_hdr),ppkt->hdr.caplen-sizeof(struct libnet_ethernet_hdr));

  return 0;
}


int rtp_pkt_handle(pktrtp_t *pktrtp, addrs_t addrs)
{
  struct rtp_stream_entry *rtp_stream;
  rtp_hdr_t *rtphdr;


  rtphdr = (rtp_hdr_t *)(pktrtp->pcap.pkt + pktrtp->hdroff);

  if (! (rtp_stream = rtp_search_stream(addrs, rtphdr)))
    rtp_stream = rtp_stream_add(pktrtp, addrs);


  rtp_stream_add_pkt(rtp_stream, pktrtp);
  rtp_stream_flush(rtp_stream,o.timeout_pkt);

  return 0;
}


int
dissect_udp(struct pcap_pkt *ppkt, u_int32_t pktoff, u_int32_t pktlen, addrs_t addrs)
{
  struct libnet_udp_hdr *pktudp;
  int32_t len;


  if (pktlen < sizeof(struct udphdr))
    return 0;

  pktudp = (struct libnet_udp_hdr *) (ppkt->pkt +  pktoff);

  len = pktlen - sizeof(struct udphdr);

  if (len != ntohs(pktudp->uh_ulen)-sizeof(struct udphdr))
    return 0;

  addrs.type = ADDRS_TYPE_UDP;
  addrs.srcport = ntohs(pktudp->uh_sport);
  addrs.dstport = ntohs(pktudp->uh_dport);

//  LOG(1,0,"ip: %s:%d > ",INET_NTOA(addrs.srcaddr),addrs.srcport);
//  LOG(0,1,"%s:%d",INET_NTOA(addrs.dstaddr),addrs.dstport);

  return dissect_rtp(ppkt,pktoff+sizeof(struct libnet_udp_hdr),len,addrs);
}


void
loop(int dlltype,int dllength)
{
  struct pcap_pkt ppkt;


  ppkt.dllength = dllength;
  ppkt.dlltype = dlltype;

  for (;;)
    {
      ppkt.pkt = (u_int8_t *)pcap_next(mypcap, &ppkt.hdr);

      if (!ppkt.pkt)
        {
          if (o.iface)
            continue;

          if (o.rxfile)
            {
              LOG(1,1," * eof reached.");
              break;
            }
        }

      pktcount++;
      //      LOG(1,1,"pktcount: %d", pktcount);

      if (ppkt.hdr.caplen != ppkt.hdr.len)
        {
          LOG(1,1,"warning: frame length is %d but caplength is %d (should not happen)",
              ppkt.hdr.len, ppkt.hdr.caplen);
          continue;
        }

      if (ppkt.hdr.caplen < dllength)
        {
          LOG(1,1,"warning: broken datalink frame");
          continue;
        }


      pcap_time = ppkt.hdr.ts;

      switch (dlltype)
        {
        case AP_DLT_EN10MB:
          dissect_eth(&ppkt,0,ppkt.hdr.caplen);
          break;
        case AP_DLT_IEEE802_11:
          dissect_ieee80211(&ppkt,0,ppkt.hdr.caplen);
          break;
        default:
          dissect_ip(&ppkt,dllength,ppkt.hdr.caplen-dllength); //skip header and try...
        }

      rtp_streams_timeout();
    }
}


void list_rtp_pt()
{
  int i;


  LOG(1,1,"");
  LOG(1,1,"[known RTP payload types]");
  LOG(1,1,"");
  for (i=0;rtp_payload_type_vals[i].str;i++)
    LOG(1,1,"%d = %s", rtp_payload_type_vals[i].type, rtp_payload_type_vals[i].str);

  LOG(1,1,"");
}


void cleanup()
{
  rtp_streams_close();


  if (running)
    raise(SIGUSR2); // show state...

  SAFE_PCAP_CLOSE(mypcap);
  SAFE_FREE(o.rxfile);
  SAFE_FREE(o.iface);
  SAFE_FREE(o.outdir);
  SAFE_FREE(o.user);
  SAFE_FREE(o.mypcap_filter);
  SAFE_PDCLOSE(pdump_noise);
}


void
init_opt(int argc, char **argv)
{
  int             c;
  char pathname[PATH_MAX];

  o.udp_hdr_even_dst_port = 0;
  o.udp_hdr_unpriv_ports = 0;
  o.mypcap_filter = NULL;
  o.rtp_hdr_pt = -1;
  o.fill_gaps = 0;
  o.verbose = 0;
  o.rxfile = NULL;
  o.iface = NULL;
  o.outdir = strdup(DEFAULT_OUTDIR);
  o.dllength = -1;
  o.timeout_pkt = PKT_TIMEOUT;
  o.timeout_pattern = RTP_STREAM_PATTERN_TIMEOUT;
  o.rtp_payload_length = -1;
  o.dump_noise = 0;
  o.pattern_pkts = RTP_STREAM_PATTERN_PKTS;
  o.user =  NULL;
  o.daemonize = 0;
  o.promisc = 0;
  o.syslog = 0;
  o.stdout = 1;
  o.dump_raw = 1;
  o.dump_pcap = 1;
  o.dump_wav = 1;

  if (argc ==1)
    help();

  opterr = 0;

  while ((c = getopt(argc, argv, "r:i:d:L:y:p:l:t:T:P:Z:unvgekDmFfhwW")) != EOF)
    switch (c)
      {

      case 'e':
        o.udp_hdr_even_dst_port = 1;
        break;

      case 'p':
        o.mypcap_filter = strdup(optarg);
        break;

      case 'y':
        o.rtp_hdr_pt= atoi(optarg);
        if (o.rtp_hdr_pt < 0)
          FATAL("rtp_hdr_pt < 0");
        break;

      case 'g':
        o.fill_gaps = 1;
        break;

      case 'L':
        o.dllength = atoi(optarg);
        if (o.dllength <0)
          FATAL("dllength < 0");
        break;

      case 'r':
        SAFE_FREE(o.rxfile);
        o.rxfile = strdup(optarg);
        break;

      case 'i':
        SAFE_FREE(o.iface);
        o.iface =  strdup(optarg);
        break;

      case 'v':
        o.verbose = 1;
        break;

      case 'd':
        SAFE_FREE(o.outdir);
        o.outdir = strdup(optarg);
        break;

      case 'l':
        o.rtp_payload_length= atoi(optarg);
        if (o.rtp_payload_length < 0)
          FATAL("rtp_payload_length < 0");
        break;

      case 't':
        /* from manpage of strtof:
         * Since 0 can legitimately be returned on both success and failure, the calling  program
         * should  set  errno  to  0  before the call, and then determine if an error occurred by
         * checking whether errno has a non-zero value after the call.
         */
        errno = 0;
        o.timeout_pkt = strtof(optarg, NULL);
        if (errno != 0)
          FATAL("strtof(): %s", strerror(errno));
        if (o.timeout_pkt < 0)
          FATAL("timeout_pkt < 0");
        break;

      case 'T':
        errno = 0;
        o.timeout_pattern = strtof(optarg, NULL);
        if (errno != 0)
          FATAL("strtof(): %s", strerror(errno));
        if (o.timeout_pattern < 0)
          FATAL("timeout_pattern < 0");
        break;

      case 'u':
        o.udp_hdr_unpriv_ports = 1;
        break;

      case 'n':
        o.dump_noise =1;
        break;

      case 'P':
        o.pattern_pkts = atoi(optarg);
        if (o.pattern_pkts <=0)
          FATAL("pattern_pkts <= 0");
        break;

      case 'k':
        list_rtp_pt();
        exit(0);

      case 'Z':
        SAFE_FREE(o.user);
        o.user = strdup(optarg);
        break;

      case 'D':
        o.daemonize = 1;
        break;

      case 'm':
        o.promisc = 1;
        break;

      case 'F':
        o.syslog = 1;
        break;

      case 'f':
        o.stdout = 0;
        break;

      case 'h':
        help();
        break;

      case 'w':
        o.dump_raw = 0;
        break;
      case 'W':
        o.dump_pcap = 0;
        break;
      case 'S':
        o.dump_wav = 0;
        break;

      default:
        FATAL("option '%c' invalid", optopt);
      }

  if (o.daemonize)
    o.stdout = 0;

  if (o.stdout)
    enable_stdout();

  if (o.verbose)
    enable_verbose();

  get_next_name(o.outdir, "rtp.",".txt",&ndxlog) ;
  if (ndxlog == -1)
    FATAL("get_next_name(...): %s", strerror(errno));
  snprintf(pathname, PATH_MAX, "%s/rtp.%d.txt", o.outdir, ndxlog);
  open_logfile(pathname);

  if (o.syslog)
    enable_syslog();

  if (o.iface && o.rxfile)
    FATAL("dup packet source: -r or -i");

  if (!o.iface && !o.rxfile)
    FATAL("packet source required");

  if (o.rxfile)
    if ( (mypcap = pcap_open_offline(o.rxfile, errbuf)) == NULL)
      FATAL("pcap_open_offline(): %s", errbuf);

  if (o.iface)
    if ((mypcap = pcap_open_live(o.iface, 65535, o.promisc, 0, errbuf)) == NULL)
      FATAL("pcap_open_live(): %s", errbuf);

  if (o.dllength == -1 && sizeof_datalink(mypcap) == -1)
    FATAL("sizeof_datalink == -1");

  if (o.user)
    drop_privs(o.user, NULL); // group can be NULL, it's ok!

  if (o.dump_noise)
    {
      snprintf(pathname, PATH_MAX, "%s/rtp.%d.noise.pcap", o.outdir, ndxlog);
      if (!(pdump_noise = pcap_dump_open(mypcap, pathname)))
        FATAL("pcap_dump_open(): %s", pcap_geterr(mypcap));
    }


  if (o.daemonize)
    daemonize();


  LOG(1,1," + rtpbreak v%s running here!",VERSION);
  LOG(1,1," + pid: %d, date/time: %s",getpid(),strtime(time(NULL)));


  if (o.verbose)
    {
      LOG(1,0," + cmd: %s", argv[0]);
      for (c = 1; c < argc; c++)
        LOG(0,0," '%s'", argv[c]);
      LOG(0,1,"");
    }

  LOG(1,1," + Configuration");

  LOG(1,1,"   + INPUT");
  LOG(1,0,"     Packet source: ");

  if (o.rxfile)
    LOG(0,1,"rxfile '%s'", o.rxfile);
  else
    LOG(0,1,"iface '%s'", o.iface);

  LOG(1,0,"     Force datalink header length: ");
  if (o.dllength == -1)
    LOG(0,1,"disabled");
  else
    LOG(0,1,"%d bytes", o.dllength);

  LOG(1,1,"   + OUTPUT");

  LOG(1,1,"     Output directory: '%s'", o.outdir);
  LOG(1,1,"     RTP raw dumps: %s", o.dump_raw ? "enabled" : "disabled");
  LOG(1,1,"     RTP pcap dumps: %s", o.dump_pcap ? "enabled" : "disabled");

  if (o.dump_raw)
    LOG(1,1,"     Fill gaps: %s",o.fill_gaps ? "enabled" : "disabled");

  LOG(1,0,"     Dump noise: ");
  if (o.dump_noise)
    LOG(0,1,"'%s/rtp.%d.noise.pcap'", o.outdir, ndxlog);
  else
    LOG(0,1,"disabled");

  LOG(1,1,"     Logfile: '%s/rtp.%d.txt'", o.outdir, ndxlog);
  LOG(1,1,"     Logging to stdout: %s",o.stdout ? "enabled" : "disabled");
  LOG(1,1,"     Logging to syslog: %s",o.syslog ? "enabled" : "disabled");
  LOG(1,1,"     Be verbose: %s",o.verbose ? "enabled" : "disabled");
  LOG(1,1,"   + SELECT");
  LOG(1,1,"     Sniff packets in promisc mode: %s", o.promisc ?  "enabled" : "disabled");

  LOG(1,0,"     Add pcap filter: ");
  if (o.mypcap_filter)
    LOG(0,1,"'%s'", o.mypcap_filter);
  else
    LOG(0,1,"disabled");

  LOG(1,1,"     Expecting even destination UDP port: %s",o.udp_hdr_even_dst_port ? "enabled" : "disabled");

  LOG(1,1,"     Expecting unprivileged source/destination UDP ports: %s", o.udp_hdr_unpriv_ports ? "enabled" : "disabled");

  LOG(1,0,"     Expecting RTP payload type: ");
  if (o.rtp_hdr_pt == -1)
    LOG(0,1,"any");
  else
    LOG(0,1,"%d (%s)", o.rtp_hdr_pt, find_stream_rtp_pt(o.rtp_hdr_pt,0));

  LOG(1,0,"     Expecting RTP payload length: ");
  if (o.rtp_payload_length == -1)
    LOG(0,1,"any");
  else
    LOG(0,1,"%d bytes",  o.rtp_payload_length);

  LOG(1,1,"     Packet timeout: %.2f seconds", o.timeout_pkt);
  LOG(1,1,"     Pattern timeout: %.2f seconds", o.timeout_pattern);
  LOG(1,1,"     Pattern packets: %d", o.pattern_pkts);

  LOG(1,1,"   + EXECUTION");
  LOG(1,1,"     Running as user/group: %s/%s", getpwuid(getuid())->pw_name,getgrgid(getgid())->gr_name);
  LOG(1,1,"     Running daemonized: %s",  o.daemonize ? "enabled" : "disabled");


}


void rtp_streams_init()
{
  rtp_streams.list.lh_first = NULL;
  rtp_streams.max_id = 0;
  rtp_streams.closed = 0;
  rtp_streams.nclosed = 0;
  rtp_streams.active = 0;
  rtp_streams.pktcount = 0;
  rtp_streams.pktcount_noise = 0;
  rtp_streams.pktcount_lost = 0;
}


int
main(int argc, char **argv)
{
  init_sighandlers();
  signal(SIGUSR2, sig_stats_handler);
  init_opt(argc, argv);
  rtp_streams_init();


  if (o.mypcap_filter)
    add_pcap_filter(mypcap,o.mypcap_filter);

  LOG(1,1," * You can dump stats sending me a SIGUSR2 signal");

  LOG(1,1," * Reading packets...");

  running = 1;

  loop(pcap_datalink(mypcap),o.dllength == -1 ? sizeof_datalink(mypcap) : o.dllength);

  raise(SIGTERM);
  return 0; // never reached
}


int dissect_rtp(struct pcap_pkt *ppkt,u_int32_t pktoff, u_int32_t pktlen, addrs_t addrs)
{
  pktrtp_t pktrtp; // rtp packet
  int32_t len;
  int32_t off;
  rtp_hdr_t *rtphdr;


// rtcp solitamente gira su porte non privilegiate >1024...
  if (o.udp_hdr_unpriv_ports)
    if (addrs.dstport < 1024 || addrs.srcport < 1024)
      return 0;

  // rtcp gira su porte dispari mentre rtp su porte pari...
  // skippiamo le dispari.

  if (o.udp_hdr_even_dst_port)
    if (addrs.dstport % 2 != 0)
      return 0;

  if (pktlen <= sizeof(rtp_hdr_t))
    return 0;

  pktrtp.hdroff = pktoff;
  pktrtp.len = pktlen;


  rtphdr = (rtp_hdr_t *)(ppkt->pkt + pktoff);

  pktrtp.pcap = *ppkt;


  if (o.rtp_hdr_pt != -1)
    if (rtphdr->pt !=o.rtp_hdr_pt)
      return 0;

  if (rtphdr->v != 2)
    return 0;

  //VLOG(1,1,"pktcount: %d", pktcount);

  off = pktrtp.hdroff + sizeof(rtp_hdr_t);
  len = pktlen - sizeof(rtp_hdr_t);

  // se il flag per il padding e' 1 allora l'ultimo byte del padding
  // indica quanti byte di padding sono presenti.
  // (mai notati, ma non usando encryption e' normale).
  if (rtphdr->p)
    len-= ((u_int8_t *)rtphdr)[pktlen-1];

  // seguono i CSRC, ciascuno di 4 byte. il loro numero e' pari a
  // pktrtp.cc (li ho notati solo in yahoo messenger).
  if (rtphdr->cc >0)
    {
      len -= 4 * rtphdr->cc;
      off += 4 * rtphdr->cc;
    }

  if (rtphdr->x)
    {
      rtp_extension_hdr_t *rtpext;
      // l'extension header e' di 4 byte.
      if (len < 4)
        return 0;

      // the extension, if present, is after the CSRC list.
      rtpext = (rtp_extension_hdr_t *)((u_int8_t *)rtphdr+off);
      off += sizeof(rtp_extension_hdr_t) + rtpext->length;
      len -= sizeof(rtp_extension_hdr_t) + rtpext->length;
    }

  if (len < 0)
    return 0;

  pktrtp.payload.off = off;
  pktrtp.payload.len = len;

  if ( o.rtp_payload_length != -1)
    if (pktrtp.payload.len != o.rtp_payload_length)
      return 0;

  rtp_pkt_handle(&pktrtp,addrs);

  return 0;
}


int dissect_ip(struct pcap_pkt *ppkt, u_int32_t pktoff, u_int32_t pktlen)
{
  addrs_t addrs = { 0,0,0,0};
  struct libnet_ipv4_hdr *pktip;
  int32_t len;


  if (pktlen < sizeof(struct libnet_ipv4_hdr))
    return 0;

  pktip = (struct libnet_ipv4_hdr *) (ppkt->pkt + pktoff);

  len = ntohs(pktip->ip_len) - (pktip->ip_hl << 2);

  // nota: potrebbe esserci il trailer eth

  if (len < 0 || len > pktlen)
    return 0;

  addrs.srcaddr = pktip->ip_src.s_addr;
  addrs.dstaddr = pktip->ip_dst.s_addr;

  if (pktip->ip_p == IPPROTO_UDP)
    return dissect_udp(ppkt,pktoff+(pktip->ip_hl << 2),len,addrs);

  return 0;
}


struct rtp_stream_entry *rtp_search_stream(addrs_t addrs, rtp_hdr_t *pktrtp)
  {
    struct rtp_stream_entry *rtp_stream;
    int64_t vmin, vmax, v;
    // non usiamo u_int16_t u_int32_t perche per calcolare vmin,vmax e' possibile uscire dal range, del seq e del ts.


    //VLOG(1,1,"searching stream...");

    LIST_FOREACH(rtp_stream, &rtp_streams.list, l)
    {
      if (pktrtp->ssrc != rtp_stream->ssrc)
        continue;

      if (!(addrs.srcaddr == rtp_stream->addrs.srcaddr &&
            addrs.dstaddr == rtp_stream->addrs.dstaddr &&
            addrs.srcport == rtp_stream->addrs.srcport &&
            addrs.dstport == rtp_stream->addrs.dstport))
        continue;

      // controlliamo il sequence number:
      // consideriamo appartenenti a questo flusso
      // i sequence number compresi in una "finestra"
      // ampia RTP_SEQWINDOW, che ha come valore centrale
      // l'ultimo sequence number che abbiamo precedentemente
      // identificato come appartenente allo stream.

      v = ntohs(pktrtp->seq);

      if (rtp_stream->first_pkt.tv_sec != 0) // se none' il primo pkt...
        if (v < rtp_stream->max_seq_seen) // maybe mod loop!!
          v += ((u_int16_t)(0-1))+1;

      vmin = ((int64_t)rtp_stream->max_seq_seen) - RTP_SEQWINDOW / 2;
      vmax = ((int64_t)rtp_stream->max_seq_seen) + RTP_SEQWINDOW / 2;

      //VLOG(1,1,"seqcheck: vmin=%llu v=%llu vmax=%llu", vmin, v, vmax);
      if (v < vmin && v > vmax)
        {
          LOG(1,1,"seqcheck failed:  vmin=%llu v=%llu vmax=%llu", vmin, v, vmax);
          continue;
        }

      v = ntohl(pktrtp->ts);

      if (rtp_stream->first_pkt.tv_sec != 0) // se none' il primo pkt...
        if (v < rtp_stream->max_ts_seen) // maybe mod loop!!
          v += ((u_int32_t)(0-1))+1;

      vmin = ((int64_t)rtp_stream->max_ts_seen) - RTP_TSWINDOW / 2;
      vmax = ((int64_t)rtp_stream->max_ts_seen) + RTP_TSWINDOW / 2;

//      LOG(1,1,"tscheck: vmin=%llu v=%llu vmax=%llu", vmin, v, vmax);
      if (v < vmin && v > vmax)
        {
//            LOG(1,1,"tscheck failed");
          continue;
        }

      break;
    }

    /*
        if(rtp_stream)
          VLOG(1,1,"found!");
        else
          VLOG(1,1,"not found!");
    */

    return rtp_stream;
  }


void rtp_stream_add_pkt(struct rtp_stream_entry *rtp_stream, pktrtp_t *pktrtp)
{
  struct rtpbuf_entry *rtpbuf,*after,*new, *before;
  rtp_hdr_t *rtphdr, *rtphdr2;


  before = NULL;
  after = NULL;
  rtpbuf = NULL;

  rtphdr = (rtp_hdr_t *)(pktrtp->pcap.pkt + pktrtp->hdroff);

  if (rtp_stream->pktcount_flhd == 0)
    rtp_stream->payload_type = rtphdr->pt;

// 65535/2 per evitare possibili pacchetti duplicati ma gia' inseriti!
// succede anche quando sipcodec sta girando.
// rtp_stream->first_pkt.tv_sec != 0 ci assicura che non stiamo facendo
// il check sul primo pkt... che risulta sempre positivo, se il seq parte da 0
// come ad esempio in linphone.

  if (rtp_stream->first_pkt.tv_sec != 0 && ntohs(rtphdr->seq)+65535/2 < rtp_stream->max_seq_seen)
    {
// mod loop!! forziamo il flushing del buffer...
// e se il pattern none' gia' stato trovato, chiudiamo la sessione.
// se era una  sessione, verra' ricreata senza
// cadere in questa situazione. cosi' ci evitiamo di
// gestirla, che e' una palla e capita di rado.
      if (!rtp_stream->pattern_found)
        {
          rtp_stream_close(rtp_stream);
          return;
        }

      rtp_stream_flush(rtp_stream,0);

      if (rtp_stream->pkts.lh_first)
        FATAL("packets buffer not empty");

      rtp_stream->max_ts_seen = ntohl(rtphdr->ts);
      rtp_stream->max_seq_seen = ntohs(rtphdr->seq);

    }
  else
    {

      if (rtp_stream->first_pkt.tv_sec != 0)
        if (ntohs(rtphdr->seq)<= rtp_stream->max_seq_seen)
          return;
    }

// la lista contiene i pkt ordinati con seq in ordine crescente
  LIST_FOREACH(rtpbuf, &rtp_stream->pkts, l)
  {
    rtphdr2 = (rtp_hdr_t *)(rtpbuf->pktrtp.pcap.pkt + rtpbuf->pktrtp.hdroff);

    if (rtphdr->seq == rtphdr2->seq)
      {
//         LOG(1,1,"dup");
        return;
      }
    if (ntohs(rtphdr->seq) < ntohs(rtphdr2->seq))
      {
        LOG(1,1,"seq=%u insert before seq=%u", ntohs(rtphdr->seq),ntohs(rtphdr2->seq));
        before = rtpbuf;
        // il nuovo pacchetto X ha un seqnum minore di quello
        // che stiamo osservando nella lista, Y. quindi X va
        // inserito prima di Y.
        LOG(1,1,"breaking");
        break;
      }
    after = rtpbuf;
  }

  sig_lock(); // impediamo ctrl-c,...

  new = (struct rtpbuf_entry *)malloc(sizeof(struct rtpbuf_entry));
  memcpy(&new->pktrtp, &pktrtp, sizeof(pktrtp_t));
  new->pktrtp.pcap.hdr = pktrtp->pcap.hdr;
  new->pktrtp.pcap.pkt = (u_int8_t *)malloc(pktrtp->pcap.hdr.caplen);
  memcpy(new->pktrtp.pcap.pkt, pktrtp->pcap.pkt, pktrtp->pcap.hdr.caplen);
  new->pktrtp.len = pktrtp->len;
  new->pktrtp.hdroff = pktrtp->hdroff;
  new->pktrtp.payload.off = pktrtp->payload.off;
  new->pktrtp.payload.len = pktrtp->payload.len;

  if (rtp_stream->pkts.lh_first == NULL)
    {
      LIST_INSERT_HEAD(&rtp_stream->pkts, new,l);
    }
  else
    {
      if (before)
        {
          LIST_INSERT_BEFORE(before, new, l);
        }
      else
        {
          if (after)
            LIST_INSERT_AFTER(after, new, l);
          else FATAL("buffer not empty and before,after NULL");
        }
    }

  if (rtp_stream->first_pkt.tv_sec == 0)
    rtp_stream->first_pkt = pktrtp->pcap.hdr.ts;
  rtp_stream->last_pkt = pktrtp->pcap.hdr.ts;

  rtp_stream->pktcount_inbuf++;

  if (ntohl(rtphdr->ts) == 0 && rtp_stream->max_ts_seen == ((u_int32_t)(0-1)))
    rtp_stream->max_ts_seen  = 0;
  rtp_stream->max_ts_seen = MAX(rtp_stream->max_ts_seen, ntohl(rtphdr->ts));

  if (ntohs(rtphdr->seq) == 0 && rtp_stream->max_seq_seen == ((u_int16_t)(0-1)))
    rtp_stream->max_seq_seen = 0;
  else
    rtp_stream->max_seq_seen = MAX(rtp_stream->max_seq_seen, ntohs(rtphdr->seq));

  if (rtp_stream->last_payload_length != -1 &&
      rtp_stream->last_payload_length != pktrtp->payload.len)
    rtp_stream->payload_length_fixed = 0;
  rtp_stream->last_payload_length =  pktrtp->payload.len;

  sig_unlock();

  // we can perform a timestamp check:
  // (pkt_before.ts <= pkt.ts <= pkt_after.ts)

  if (!rtp_stream->pattern_found)
    if (rtp_stream->pktcount_inbuf >= o.pattern_pkts)
      {

// facciamo due controlli: verifichiamo che non
// ci siano salti fra i seq e che:
// (pkt_before.ts <= pkt.ts <= pkt_after.ts)

// questi due controlli vengono fatti soltanto
// se !rtp_stream->pattern_found

        if (rtp_stream_ts_seq_check(rtp_stream) == -1)
          {
            rtp_stream_close(rtp_stream);
            return;
          }

        rtp_streams.active++;

        rtp_stream->pattern_found=1;

        // "detected!..." nella flush, cosi' abbiamo anche il fid.
      }

}


void rtp_stream_flush(struct rtp_stream_entry *rtp_stream, int buf_timeout)
{
  struct rtpbuf_entry *rtpbuf, *rtpbuf2;
  rtp_hdr_t *rtphdr;
  int i,j;


  if (!rtp_stream->pattern_found)
    {

      if (buf_timeout != 0)
        return;

// qui ci finiamo soltanto quando chiudiamo la sessione, un falso positivo.

      LIST_FOREACH_SAFE(rtpbuf, &rtp_stream->pkts, l, rtpbuf2)
      {

        sig_lock();
        if (pdump_noise)
          pcap_dump((u_char *)pdump_noise, &rtpbuf->pktrtp.pcap.hdr, rtpbuf->pktrtp.pcap.pkt);

        rtp_streams.pktcount_noise++;

        LIST_REMOVE(rtpbuf, l);
        SAFE_FREE(rtpbuf->pktrtp.pcap.pkt);
        SAFE_FREE(rtpbuf);
        sig_unlock();

      }

      return;
    }

  // open log files for entry...
  if (!rtp_stream->f)
    {

      rtp_stream_open_files(rtp_stream);

      LOG(1,0," ! [rtp%d] detected: pt=%d(%s) ",rtp_stream->fid,rtp_stream->payload_type,find_stream_rtp_pt(rtp_stream->payload_type,1));

      LOG(0,0,"%s:%d => ",INET_NTOA(rtp_stream->addrs.srcaddr),rtp_stream->addrs.srcport);

      LOG(0,1,"%s:%d",INET_NTOA(rtp_stream->addrs.dstaddr),rtp_stream->addrs.dstport);

      SAFE_FPRINTF(rtp_stream->f,"RTP stream id: rtp.%d.%d\n", ndxlog, rtp_stream->fid);
      if (o.iface)
        SAFE_FPRINTF(rtp_stream->f,"Packet source: iface  '%s'\n", o.iface);
      if (o.rxfile)
        SAFE_FPRINTF(rtp_stream->f,"Packet source: rxfile '%s'\n", o.rxfile);

      SAFE_FPRINTF(rtp_stream->f,"First seen packet: %s (pcap time)\n", strtime(rtp_stream->first_pkt.tv_sec));
      SAFE_FPRINTF(rtp_stream->f, "Stream peers: %s:%d => ",INET_NTOA(rtp_stream->addrs.srcaddr),rtp_stream->addrs.srcport);
      SAFE_FPRINTF(rtp_stream->f,"%s:%d\n",INET_NTOA(rtp_stream->addrs.dstaddr),rtp_stream->addrs.dstport);
      SAFE_FPRINTF(rtp_stream->f,"RTP ssrc: %u\n", ntohl(rtp_stream->ssrc));
      SAFE_FPRINTF(rtp_stream->f,"RTP payload type: %d (%s)\n", rtp_stream->payload_type, find_stream_rtp_pt(rtp_stream->payload_type,0));

      rtp_stream_search_rev(rtp_stream);

    }


  // la lista contiene i pkt ordinati con seq in ordine crescente.
  // quindi, dal piu' vecchio all'ultimo. flushiamo i pkt nella lista
  // fino a quando si verifica almeno una di queste due condizioni:
  // 1. non ci sono salti fra i sequence (0 pkt persi)
  // 2. il pkt e' stato nel buffer per un tempo >= di buf_timeout

  LIST_FOREACH_SAFE(rtpbuf, &rtp_stream->pkts, l, rtpbuf2)
  {

    rtphdr =  (rtp_hdr_t *)(rtpbuf->pktrtp.pcap.pkt+rtpbuf->pktrtp.hdroff);

    // nota: se seq==0, allora il primo prevseq e' 65535 e fallirebbe_
    // il check se facciamo soltanto seq+1 perche non ce' casting a u_int16_t.
    // quindi, usiamo (u_int16_t)(seq+1): se seq==65535, risulta 0.

    if (((u_int16_t)(rtp_stream->last_seq_flhd+1) == ntohs(rtphdr->seq)) ||
        timeout(&pcap_time, &rtpbuf->pktrtp.pcap.hdr.ts,buf_timeout)
       )
      {
        sig_lock();

        // if (sequence ok OR timeout) ..

        if (rtp_stream->pdump)
          pcap_dump((u_char *)rtp_stream->pdump, &rtpbuf->pktrtp.pcap.hdr, rtpbuf->pktrtp.pcap.pkt);
        rtp_stream->pktcount_flhd++;
        rtp_stream->pktcount_inbuf--;

        rtp_streams.pktcount++;

        if (rtp_stream->last_seq_flhd == ((u_int16_t)(0-1)))
          j = 1;
        else
          j=ntohs(rtphdr->seq)-rtp_stream->last_seq_flhd; // usata anche per fill gaps!

        rtp_stream->pktcount_lost += j-1;
        rtp_streams.pktcount_lost+= j-1;


        if (o.dump_raw)
          {
            if (o.fill_gaps)
              {
                // if j == 1 (state of "no lost packets"), writes the pkt only 1 time
                for (i=0;i<j;i++)
                  fwrite(rtpbuf->pktrtp.pcap.pkt +  rtpbuf->pktrtp.payload.off, 1, rtpbuf->pktrtp.payload.len, rtp_stream->raw);
              }
            else
              {
                //  writes the pkt
                fwrite(rtpbuf->pktrtp.pcap.pkt +  rtpbuf->pktrtp.payload.off, 1, rtpbuf->pktrtp.payload.len, rtp_stream->raw);
              }
          }

        rtp_stream->last_seq_flhd=ntohs(rtphdr->seq);
        LIST_REMOVE(rtpbuf, l);
        SAFE_FREE(rtpbuf->pktrtp.pcap.pkt);
        SAFE_FREE(rtpbuf);
        sig_unlock();

      }
    else
      break;

  }


  //VLOG(1,1,"done.");

}


char *find_stream_rtp_pt(int pt, int short_vals)
{
  int i;


  if (short_vals)
    {
      for (i=0;rtp_payload_type_short_vals[i].str;i++)
        if (rtp_payload_type_short_vals[i].type == pt)
          {
            return rtp_payload_type_short_vals[i].str;
          }
      return "?";
    }
  else
    {
      for (i=0;rtp_payload_type_vals[i].str;i++)
        if (rtp_payload_type_vals[i].type == pt)
          {
            return rtp_payload_type_vals[i].str;
          }
      return "Unknown";
    }
  return "Unknown";
}


void
rtp_stream_open_files(struct rtp_stream_entry *rtp_stream)
{
  int count;
  char pathname[PATH_MAX];


  sig_lock();

  snprintf(pathname, PATH_MAX, "rtp.%d.",ndxlog);

  get_next_name(o.outdir, pathname, ".txt", &count);

  if (count == -1)
    FATAL("get_next_name(...): %s", strerror(errno));

  rtp_stream->fid = count;

  if (o.dump_pcap)
    {
      snprintf(pathname, PATH_MAX, "%s/rtp.%d.%d.pcap",o.outdir, ndxlog, rtp_stream->fid );
      if (!(rtp_stream->pdump = pcap_dump_open(mypcap, pathname)))
        FATAL("pcap_dump_open(): %s", pcap_geterr(mypcap));
    }

  snprintf(pathname, PATH_MAX, "%s/rtp.%d.%d.txt",o.outdir, ndxlog, rtp_stream->fid );

  LOG(1,1,"open di %s", pathname);

  if (!(rtp_stream->f = fopen(pathname, "w")))
    FATAL("fopen(): %s", strerror(errno));

  if (o.dump_wav)
    {
	// Set Command if codec is found
	if (strstr(find_stream_rtp_pt(rtp_stream->payload_type,1), "?") == NULL) {
		char namebody[64], codec[64];
		snprintf(namebody, sizeof(namebody),"%s/rtp.%d.%d",o.outdir,ndxlog, rtp_stream->fid );
		snprintf(codec, sizeof(codec),"%s",find_stream_rtp_pt(rtp_stream->payload_type,1) );

		if (strstr(codec, "711A") != NULL) {
    		  // contains g711a
		  	//  snprintf(rtp_stream->command, sizeof(rtp_stream->command), "sox -r8000 -c1 -t al %s/rtp.%d.%d-%s.raw -t wav %s/audio-%d.wav",o.outdir, ndxlog, rtp_stream->fid, find_stream_rtp_pt(rtp_stream->payload_type,1), o.outdir, rtp_stream->fid);
		  	snprintf(rtp_stream->command, sizeof(rtp_stream->command), "ffmpeg -nostats -loglevel 0 -acodec pcm_alaw -f alaw -ar 8000 -i %s.%s -ar 8000 %s.wav"
										   ";ffmpeg -nostats -loglevel 0 -i %s.wav -ac 1 -filter:a aresample=8000 -map 0:a -c:a pcm_s16le -f data - | gnuplot -p -e \"set terminal png size 2000,200;set output '%s.png';unset key;unset tics;unset border;set lmargin 0;set rmargin 0;set tmargin 0.5;set bmargin 0.5; plot '<cat' binary filetype=bin format='%%int16' endian=little array=1:0 with lines;\" ",
										   namebody, codec, namebody, namebody, namebody);
		} else if (strstr(codec, "711U") != NULL) {
        	  // contains g711u
		        //  snprintf(rtp_stream->command, sizeof(rtp_stream->command), "sox -r8000 -c1 -t ul %s/rtp.%d.%d-%s.raw -t wav %s/audio-%d.wav",o.outdir, ndxlog, rtp_stream->fid, find_stream_rtp_pt(rtp_stream->payload_type,1), o.outdir, rtp_stream->fid);
		  	snprintf(rtp_stream->command, sizeof(rtp_stream->command), "ffmpeg -nostats -loglevel 0 -acodec pcm_mulaw -f mulaw -ar 8000 -i %s.%s -ar 8000 %s.wav"
										   ";ffmpeg -nostats -loglevel 0 -i %s.wav -ac 1 -filter:a aresample=8000 -map 0:a -c:a pcm_s16le -f data - | gnuplot -p -e \"set terminal png size 2000,200;set output '%s.png';unset key;unset tics;unset border;set lmargin 0;set rmargin 0;set tmargin 0.5;set bmargin 0.5; plot '<cat' binary filetype=bin format='%%int16' endian=little array=1:0 with lines;\" ",
										   namebody, codec, namebody, namebody, namebody);
		} else if (strstr(codec, "729") != NULL) {
        	  // contains g729
		        snprintf(rtp_stream->command, sizeof(rtp_stream->command), "ffmpeg -nostats -loglevel 0 -acodec g729 -f g729 -i %s.%s %s.wav"
										   ";ffmpeg -nostats -loglevel 0 -i %s.wav -ac 1 -filter:a aresample=8000 -map 0:a -c:a pcm_s16le -f data - | gnuplot -p -e \"set terminal png size 2000,200;set output '%s.png';unset key;unset tics;unset border;set lmargin 0;set rmargin 0;set tmargin 0.5;set bmargin 0.5; plot '<cat' binary filetype=bin format='%%int16' endian=little array=1:0 with lines;\" ",
										   namebody, codec, namebody, namebody, namebody);
	        }
        } else { snprintf(rtp_stream->command, sizeof(rtp_stream->command), "NULL"); }

    }

  if (o.dump_raw)
    {
      snprintf(pathname, PATH_MAX, "%s/rtp.%d.%d.%s",o.outdir, ndxlog, rtp_stream->fid, find_stream_rtp_pt(rtp_stream->payload_type,1) );
      if (!(rtp_stream->raw = fopen(pathname, "w"))) {
        FATAL("fopen(): %s", strerror(errno));
      }
    }

  sig_unlock();

}


struct rtp_stream_entry * rtp_stream_add(pktrtp_t *pktrtp, addrs_t addrs)
  {
    struct rtp_stream_entry *rtp_stream;
    //signaling_t *signaling;
    rtp_hdr_t *rtphdr;


    rtp_streams.max_id++;

    rtphdr = (rtp_hdr_t *)(pktrtp->pcap.pkt + pktrtp->hdroff);

//    LOG(1,1,"creating and adding stream...");
    rtp_stream = (struct rtp_stream_entry *)malloc(sizeof(struct rtp_stream_entry));
    rtp_stream->addrs = addrs;
    rtp_stream->ssrc = rtphdr->ssrc;
    rtp_stream->max_seq_seen = ntohs(rtphdr->seq) -1;
    rtp_stream->last_seq_flhd = ntohs(rtphdr->seq) -1;
    rtp_stream->max_ts_seen = ntohl(rtphdr->ts); // usiamo questo valore soltanto nel tscheck, quindi anche se none' esatto va bene comunque.
    rtp_stream->fid = -1;
    rtp_stream->f = NULL;
    rtp_stream->raw = NULL;
    rtp_stream->pdump = NULL;
    rtp_stream->pattern_found = 0;
    rtp_stream->pktcount_inbuf = 0;
    rtp_stream->pktcount_flhd = 0;
    rtp_stream->pktcount_lost = 0;
    rtp_stream->pkts.lh_first = NULL;
    LIST_INSERT_HEAD(&rtp_streams.list,rtp_stream,l);
    rtp_stream->id = rtp_streams.max_id-1;
    rtp_stream->last_pkt.tv_sec = 0;
    rtp_stream->last_pkt.tv_usec = 0;
    rtp_stream->first_pkt.tv_sec = 0;
    rtp_stream->first_pkt.tv_usec = 0;
    rtp_stream->payload_type = -1;
    rtp_stream->last_payload_length = -1;
    rtp_stream->payload_length_fixed = 1; // assume yes
    rtp_stream->rev = NULL;

    return rtp_stream;
  }


void print_stream_stat(struct rtp_stream_entry *rtp_stream)
{
  int s;


  s =rtp_stream->last_pkt.tv_sec - rtp_stream->first_pkt.tv_sec;
  LOG(0,1,"packets inbuffer=%d flushed=%d lost=%d(%.2f%%), call_length=%dm%ds", rtp_stream->pktcount_inbuf,rtp_stream->pktcount_flhd, rtp_stream->pktcount_lost, PERCENTAGE(rtp_stream->pktcount_lost, rtp_stream->pktcount_flhd + rtp_stream->pktcount_lost), s/60,s%60);
}


void rtp_stream_close(struct rtp_stream_entry *rtp_stream)
{
  int s;


  LIST_REMOVE(rtp_stream, l);

  rtp_stream_flush(rtp_stream,0);
// nota su rtp_stream_flush(rtp_stream,0):
// se ce' stato un errore durante l'apertura dei file relativi a questo stream
// rtp, chiamando rtp_stream_flush(rtp_stream,0) viene liberata la memoria
// tentando di aprire i file (nella rtp_stream_flush). questo comporta un loop
// nella fatal che comunque viene riconosciuto internamente alla fatal e gestito
// forzando la terminazione immediata del processo.

  if (rtp_stream->pattern_found)
    {
      LOG(1,0," * [rtp%d] closed: ", rtp_stream->fid);
      print_stream_stat(rtp_stream);
      rtp_streams.active--;
      rtp_streams.closed++;
    }
  else
    {
      rtp_streams.nclosed++;
    }

  SAFE_PDCLOSE(rtp_stream->pdump);
  SAFE_FCLOSE(rtp_stream->raw);


  SAFE_FPRINTF(rtp_stream->f,"Last seen packet: %s (pcap time)\n", strtime(rtp_stream->last_pkt.tv_sec));

  s =rtp_stream->last_pkt.tv_sec - rtp_stream->first_pkt.tv_sec;
  SAFE_FPRINTF(rtp_stream->f,"Call length: %dm%ds\n",s / 60,s % 60);
  SAFE_FPRINTF(rtp_stream->f,"Flushed packets: %d\n",  rtp_stream->pktcount_flhd);
  SAFE_FPRINTF(rtp_stream->f,"Lost packets: %d (%.2f%%)\n", rtp_stream->pktcount_lost,  PERCENTAGE(rtp_stream->pktcount_lost,rtp_stream->pktcount_flhd + rtp_stream->pktcount_lost));
  SAFE_FPRINTF(rtp_stream->f,"RTP payload length: %d bytes (%s)\n",rtp_stream->last_payload_length, rtp_stream->payload_length_fixed ? "fixed" : "variable, this is the last seen");

  // after this fclose, no more fprint to file!!
  SAFE_FCLOSE(rtp_stream->f);

  // Execute command, if any
  if (o.dump_wav && strstr(find_stream_rtp_pt(rtp_stream->payload_type,1), "?") == NULL) {
	  LOG(1,1,"Converting %s (%s) to WAV, PNG", find_stream_rtp_pt(rtp_stream->payload_type,0), find_stream_rtp_pt(rtp_stream->payload_type,1) );
	  // LOG(1,1,"Debug Command: %s", rtp_stream->command);
	  system(rtp_stream->command);
  }

  if (rtp_stream->rev && rtp_stream->rev->rev)
    rtp_stream->rev->rev = NULL;

  SAFE_FREE(rtp_stream);
}


void rtp_streams_close()
{
  VLOG(1,1,"closing streams...");

  while (rtp_streams.list.lh_first)
    rtp_stream_close(rtp_streams.list.lh_first);

}


void help()
{
  printf("Copyright (c) 2007-2008 Dallachiesa Michele <micheleDOTdallachiesaATposteDOTit>\n");
  printf("Copyright (c) 2015 QXIP BV <info@qxip.net>\n");
  printf("rtpbreakr v%s is free software, covered by the GNU General Public License.\n\n", VERSION);
  printf("USAGE: rtpbreakr (-r|-i) <source> [options]\n");

  printf("\n INPUT\n\n");
  printf("  -r <str>      Read packets from pcap file <str>\n");
  printf("  -i <str>      Read packets from network interface <str>\n");
  printf("  -L <int>      Force datalink header length == <int> bytes\n");
  printf("\n OUTPUT\n\n");
  printf("  -d <str>      Set output directory to <str> (def:%s)\n",DEFAULT_OUTDIR);
  printf("  -w            Disable RTP raw dumps\n");
  printf("  -W            Disable RTP pcap dumps\n");
  printf("  -W            Disable RTP external dumps\n");
  printf("  -g            Fill gaps in RTP raw dumps (caused by lost packets)\n");
  printf("  -n            Dump noise packets\n");
  printf("  -f            Disable stdout logging\n");
  printf("  -F            Enable syslog logging\n");
  printf("  -v            Be verbose\n");
  printf("\n SELECT\n\n");
  printf("  -m            Sniff packets in promisc mode\n");
  printf("  -p <str>      Add pcap filter <str>\n");
  printf("  -e            Expect even destination UDP port\n");
  printf("  -u            Expect unprivileged source/destination UDP ports (>1024)\n");
  printf("  -y <int>      Expect RTP payload type == <int>\n");
  printf("  -l <int>      Expect RTP payload length == <int> bytes\n");
  printf("  -t <float>    Set packet timeout to <float> seconds (def:%.2f)\n", PKT_TIMEOUT);
  printf("  -T <float>    Set pattern timeout to <float> seconds (def:%.2f)\n", RTP_STREAM_PATTERN_TIMEOUT);
  printf("  -P <int>      Set pattern packets count to <int> (def:%d)\n", o.pattern_pkts);
  printf("\n EXECUTION\n\n");
  printf("  -Z <str>      Run as user <str>\n");
  printf("  -D            Run in background (option -f implicit)\n");
  printf("\n MISC\n\n");
  printf("  -k            List known RTP payload types\n");
  printf("  -h            This\n");
  printf("\n");

  exit(0);
}


void sig_stats_handler(int signo)
{
  struct rtp_stream_entry *rtp_stream;
  int s;
  int n;

  LOG(1,1," + Status");
  LOG(1,1,"   Alive RTP Sessions: %d", rtp_streams.active);
  LOG(1,1,"   Closed RTP Sessions: %d", rtp_streams.closed);
  LOG(1,1,"   Detected RTP Sessions: %d", rtp_streams.active + rtp_streams.closed);
  LOG(1,1,"   Flushed RTP packets: %d", rtp_streams.pktcount);
  LOG(1,1,"   Lost RTP packets: %d (%.2f%%)", rtp_streams.pktcount_lost,
      PERCENTAGE(rtp_streams.pktcount_lost,rtp_streams.pktcount + rtp_streams.pktcount_lost));

  LOG(1,1,"   Noise (false positive) packets: %d", rtp_streams.pktcount_noise);

  n = 0;

  LIST_FOREACH(rtp_stream, &rtp_streams.list, l)
  {
    if (!rtp_stream->pattern_found)
      continue;

    n++;
    s =rtp_stream->last_pkt.tv_sec - rtp_stream->first_pkt.tv_sec;
    LOG(1,0," + [rtp%d] stats: ", rtp_stream->fid);
    print_stream_stat(rtp_stream);
  }

  if (n == 0)
    LOG(1,1," + No active RTP streams");


}


void rtp_streams_timeout()
{
  static struct timeval last_run =
    {
      0,0
    };
  struct rtp_stream_entry *rtp_stream, *rtp_stream2;


  if (!timeout(&pcap_time,&last_run,o.timeout_pattern))
    return;
  last_run = pcap_time;


  LIST_FOREACH_SAFE(rtp_stream, &rtp_streams.list, l, rtp_stream2)
  {

    if (rtp_stream->pattern_found)
      {
        if (timeout(&pcap_time, &rtp_stream->last_pkt,o.timeout_pkt))
          {
            rtp_stream_close(rtp_stream);
            continue;
          }
      }
    else
      {
        if (timeout(&pcap_time, &rtp_stream->last_pkt,o.timeout_pattern))
          {
            rtp_stream_close(rtp_stream);
            continue;
          }
      }

  }

//LOG(1,1,"done.");
}


int timeout(struct timeval *a, struct timeval *b, float t)
{
  struct timeval c;
  float r;


  TIMEVAL_SUB(a, b, &c);

  r = c.tv_sec + (float)c.tv_usec /1000000;

//LOG(1,1,"a:%f b:%f a-b:%f , a-b:%f", a->tv_sec + (float)a->tv_usec /1000000,b->tv_sec +(float) b->tv_usec /1000000, c.tv_sec + (float)c.tv_usec /1000000,r);

  return r > t ? 1 : 0;
}


void rtp_stream_search_rev(struct rtp_stream_entry *rtp_stream)
{
  struct rtp_stream_entry *rtp_stream2;


  LIST_FOREACH(rtp_stream2, &rtp_streams.list, l)
  {
    if (!rtp_stream2->pattern_found || rtp_stream2->rev)
      continue;
    if (rtp_stream2 != rtp_stream &&
        rtp_stream2->addrs.srcaddr == rtp_stream->addrs.dstaddr &&
        rtp_stream2->addrs.dstaddr == rtp_stream->addrs.srcaddr)
      {
        LOG(1,1," * [rtp%d] probable reverse RTP stream: [rtp%d]",rtp_stream->fid,  rtp_stream2->fid);

        rtp_stream->rev = rtp_stream2;
        rtp_stream2->rev = rtp_stream;

        SAFE_FPRINTF(rtp_stream->f,"Probable reverse RTP stream id: rtp.%d.%d\n",ndxlog,rtp_stream->rev->fid);

      }
  }

}


/* EOF */

