/* Copyright (C) 2014 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#ifndef __DECODE_GTPU_H__
#define __DECODE_GTPU_H__

#define GTP_U_PORT 2152

#define GTP_HDR_LEN 8
#define GTP_OPT_HDR_LEN 4

#define GTP_PROTO_IPV4 4
#define GTP_PROTO_IPV6 6

enum GtpMessageTypes {
    GTP_TYPE_PDU = 0xff,
    GTP_TYPE_ECHO_REQUEST = 0x01,
    GTP_TYPE_ECHO_REPLY = 0x02,
    GTP_TYPE_ERROR_INDICATION = 0x1a
};

typedef struct GtpHdr_ {
    uint8_t version; /**< Version and flags. */
    uint8_t type;
    uint16_t length;
    uint32_t teid;

    uint16_t seq; /**< Optional sequence number. */
    uint8_t npdu; /**< Optional N-PDU number. */
    uint8_t nh; /**< Optional next extension header type. */
} __attribute__((__packed__)) GtpHdr;



#define GTP_VERSION(hdr) hdr->version >> 5
#define GTP_PT(hdr) (hdr->version >> 4) & 0x1
#define GTP_E(hdr) (hdr->version >> 2) & 0x1
#define GTP_S(hdr) (hdr->version >> 1) & 0x1
#define GTP_PN(hdr) hdr->version & 0x1

void DecodeGTPRegisterTests(void);

#endif /* !__DECODE_GTPU_H__ */
