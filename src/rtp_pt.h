/*
 * rtp_pt.h by xenion -- 2008-05-05 -- v.4464c61a1c3fe5803ccbaa426c87a448
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

/*
 * RTP Payload types, from Wireshark sources.
 * Table B.2 / H.225.0
 * Also RFC 1890, and
 * http://www.iana.org/assignments/rtp-parameters
 */


typedef struct
  {
    int type;
    char *str;
  }
value_string;


#define PT_PCMU         0       /* RFC 1890 */
#define PT_1016         1       /* RFC 1890 */
#define PT_G721         2       /* RFC 1890 */
#define PT_GSM          3       /* RFC 1890 */
#define PT_G723         4       /* From Vineet Kumar of Intel; see the Web page */
#define PT_DVI4_8000    5       /* RFC 1890 */
#define PT_DVI4_16000   6       /* RFC 1890 */
#define PT_LPC          7       /* RFC 1890 */
#define PT_PCMA         8       /* RFC 1890 */
#define PT_G722         9       /* RFC 1890 */
#define PT_L16_STEREO   10      /* RFC 1890 */
#define PT_L16_MONO     11      /* RFC 1890 */
#define PT_QCELP        12      /* Qualcomm Code Excited Linear Predictive coding? */
#define PT_CN           13      /* RFC 3389 */
#define PT_MPA          14      /* RFC 1890, RFC 2250 */
#define PT_G728         15      /* RFC 1890 */
#define PT_DVI4_11025   16      /* from Joseph Di Pol of Sun; see the Web page */
#define PT_DVI4_22050   17      /* from Joseph Di Pol of Sun; see the Web page */
#define PT_G729         18
#define PT_CN_OLD       19      /* Payload type reserved (old version Comfort Noise) */
#define PT_CELB         25      /* RFC 2029 */
#define PT_JPEG         26      /* RFC 2435 */
#define PT_NV           28      /* RFC 1890 */
#define PT_H261         31      /* RFC 2032 */
#define PT_MPV          32      /* RFC 2250 */
#define PT_MP2T         33      /* RFC 2250 */
#define PT_H263         34      /* from Chunrong Zhu of Intel; see the Web page */


const  value_string rtp_payload_type_vals[] =
{
  {
    PT_PCMU,      "ITU-T G.711 PCMU"
  },
  { PT_1016,      "USA Federal Standard FS-1016" },
  { PT_G721,      "ITU-T G.721" },
  { PT_GSM,       "GSM 06.10" },
  { PT_G723,      "ITU-T G.723" },
  { PT_DVI4_8000, "DVI4 8000 samples/s" },
  { PT_DVI4_16000, "DVI4 16000 samples/s" },
  { PT_LPC,       "Experimental linear predictive encoding from Xerox PARC" },
  { PT_PCMA,      "ITU-T G.711 PCMA" },
  { PT_G722,      "ITU-T G.722" },
  { PT_L16_STEREO, "16-bit uncompressed audio, stereo" },
  { PT_L16_MONO,  "16-bit uncompressed audio, monaural" },
  { PT_QCELP,     "Qualcomm Code Excited Linear Predictive coding" },
  { PT_CN,        "Comfort noise" },
  { PT_MPA,       "MPEG-I/II Audio"},
  { PT_G728,      "ITU-T G.728" },
  { PT_DVI4_11025, "DVI4 11025 samples/s" },
  { PT_DVI4_22050, "DVI4 22050 samples/s" },
  { PT_G729,      "ITU-T G.729" },
  { PT_CN_OLD,    "Comfort noise (old)" },
  { PT_CELB,      "Sun CellB video encoding" },
  { PT_JPEG,      "JPEG-compressed video" },
  { PT_NV,        "'nv' program" },
  { PT_H261,      "ITU-T H.261" },
  { PT_MPV,       "MPEG-I/II Video"},
  { PT_MP2T,      "MPEG-II transport streams"},
  { PT_H263,      "ITU-T H.263" },
  { 0,            NULL },
};


const value_string rtp_payload_type_short_vals[] =
{
  {
    PT_PCMU,      "g711U"
  },
  { PT_1016,      "fs-1016" },
  { PT_G721,      "g721" },
  { PT_GSM,       "GSM" },
  { PT_G723,      "g723" },
  { PT_DVI4_8000, "DVI4 8k" },
  { PT_DVI4_16000, "DVI4 16k" },
  { PT_LPC,       "Exp. from Xerox PARC" },
  { PT_PCMA,      "g711A" },
  { PT_G722,      "g722" },
  { PT_L16_STEREO, "16-bit audio, stereo" },
  { PT_L16_MONO,  "16-bit audio, monaural" },
  { PT_QCELP,     "Qualcomm" },
  { PT_CN,        "CN" },
  { PT_MPA,       "MPEG-I/II Audio"},
  { PT_G728,      "g728" },
  { PT_DVI4_11025, "DVI4 11k" },
  { PT_DVI4_22050, "DVI4 22k" },
  { PT_G729,      "g729" },
  { PT_CN_OLD,    "CN(old)" },
  { PT_CELB,      "CellB" },
  { PT_JPEG,      "JPEG" },
  { PT_NV,        "NV" },
  { PT_H261,      "h261" },
  { PT_MPV,       "MPEG-I/II Video"},
  { PT_MP2T,      "MPEG-II streams"},
  { PT_H263,      "h263" },
  { 0,            NULL },
};

/* eof */

