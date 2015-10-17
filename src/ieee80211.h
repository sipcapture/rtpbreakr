/*
 * ieee80211.h by xenion -- 2008-05-05 -- v.c486a4662d73aaca28a52ba95febd8b3
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

// adapted from:
//  $FreeBSD: src/sys/net80211/ieee80211.h,v 1.9.2.2 2006/08/10 06:07:49 sam Exp $

/* does frame have QoS sequence control data */
#define IEEE80211_QOS_HAS_SEQ(wh) \
        (((wh)->i_fc[0] & \
          (IEEE80211_FC0_TYPE_MASK | IEEE80211_FC0_SUBTYPE_QOS)) == \
          (IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_QOS))

#define IEEE80211_ADDR_LEN      6               /* size of 802.11 address */
#define IEEE80211_FC0_TYPE_MASK                 0x0c
#define IEEE80211_FC0_TYPE_DATA                 0x08
#define IEEE80211_FC1_DIR_MASK                  0x03
#define IEEE80211_FC1_DIR_DSTODS                0x03    /* AP ->AP  */
#define IEEE80211_FC0_SUBTYPE_MASK              0xf0
#define IEEE80211_FC0_SUBTYPE_QOS               0x80

struct ieee80211_frame
  {
    u_int8_t        i_fc[2];
    u_int8_t        i_dur[2];
    u_int8_t        i_addr1[ETHER_ADDR_LEN];
    u_int8_t        i_addr2[ETHER_ADDR_LEN];
    u_int8_t        i_addr3[ETHER_ADDR_LEN];
    u_int8_t        i_seq[2];
    /* possibly followed by addr4[ETHER_ADDR_LEN]; */
  };


/* EOF */


