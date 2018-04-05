// cap_parse.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#pragma pack(1)

/**
* Name........: cap2hccapx.c
* Autor.......: Jens Steube <jens.steube@gmail.com>, Philipp "philsmd" Schmidt <philsmd@hashcat.net>
* License.....: MIT
*/

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// from pcap.h

#define TCPDUMP_MAGIC 0xa1b2c3d4
#define TCPDUMP_CIGAM 0xd4c3b2a1

#define TCPDUMP_DECODE_LEN 65535

#define DLT_NULL        0   /* BSD loopback encapsulation */
#define DLT_EN10MB      1   /* Ethernet (10Mb) */
#define DLT_EN3MB       2   /* Experimental Ethernet (3Mb) */
#define DLT_AX25        3   /* Amateur Radio AX.25 */
#define DLT_PRONET      4   /* Proteon ProNET Token Ring */
#define DLT_CHAOS       5   /* Chaos */
#define DLT_IEEE802     6   /* IEEE 802 Networks */
#define DLT_ARCNET      7   /* ARCNET, with BSD-style header */
#define DLT_SLIP        8   /* Serial Line IP */
#define DLT_PPP         9   /* Point-to-point Protocol */
#define DLT_FDDI        10  /* FDDI */
#define DLT_RAW         12  /* Raw headers (no link layer) */
#define DLT_RAW2        14
#define DLT_RAW3        101

#define DLT_IEEE802_11  105 /* IEEE 802.11 wireless */
#define DLT_IEEE802_11_RADIO 127

struct pcap_file_header {
	u32 magic;
	u16 version_major;
	u16 version_minor;
	u32 thiszone; /* gmt to local correction */
	u32 sigfigs;  /* accuracy of timestamps */
	u32 snaplen;  /* max length saved portion of each pkt */
	u32 linktype; /* data link type (LINKTYPE_*) */
};

struct pcap_pkthdr {
	u32 tv_sec;   /* timestamp seconds */
	u32 tv_usec;  /* timestamp microseconds */
	u32 caplen;   /* length of portion present */
	u32 len;      /* length this packet (off wire) */
};

typedef struct pcap_file_header pcap_file_header_t;
typedef struct pcap_pkthdr pcap_pkthdr_t;

// from linux/ieee80211.h
#pragma pack(push)
#pragma pack(1)
struct ieee80211_hdr_3addr {
	u16 frame_control;
	u16 duration_id;
	u8  addr1[6];
	u8  addr2[6];
	u8  addr3[6];
	u16 seq_ctrl;

};

struct ieee80211_qos_hdr {
	u16 frame_control;
	u16 duration_id;
	u8  addr1[6];
	u8  addr2[6];
	u8  addr3[6];
	u16 seq_ctrl;
	u16 qos_ctrl;

};

typedef struct ieee80211_hdr_3addr ieee80211_hdr_3addr_t;
typedef struct ieee80211_qos_hdr   ieee80211_qos_hdr_t;

struct ieee80211_llc_snap_header
{
	/* LLC part: */
	u8 dsap;          /**< Destination SAP ID */
	u8 ssap;          /**< Source SAP ID */
	u8 ctrl;          /**< Control information */

	/* SNAP part: */
	u8 oui[3];        /**< Organization code, usually 0 */
	u16 ethertype;    /**< Ethernet Type field */

};

#pragma pack(pop)

typedef struct ieee80211_llc_snap_header ieee80211_llc_snap_header_t;

#define IEEE80211_FCTL_FTYPE        0x000c
#define IEEE80211_FCTL_STYPE        0x00f0
#define IEEE80211_FCTL_TODS         0x0100
#define IEEE80211_FCTL_FROMDS       0x0200

#define IEEE80211_FTYPE_MGMT        0x0000
#define IEEE80211_FTYPE_DATA        0x0008

#define IEEE80211_STYPE_PROBE_REQ   0x0040
#define IEEE80211_STYPE_PROBE_RESP  0x0050
#define IEEE80211_STYPE_BEACON      0x0080
#define IEEE80211_STYPE_QOS_DATA    0x0080

#define IEEE80211_LLC_DSAP              0xAA
#define IEEE80211_LLC_SSAP              0xAA
#define IEEE80211_LLC_CTRL              0x03
#define IEEE80211_DOT1X_AUTHENTICATION  0x8E88

/* Management Frame Information Element Types */
#define MFIE_TYPE_SSID      0
#define MFIE_TYPE_RATES     1
#define MFIE_TYPE_FH_SET    2
#define MFIE_TYPE_DS_SET    3
#define MFIE_TYPE_CF_SET    4
#define MFIE_TYPE_TIM       5
#define MFIE_TYPE_IBSS_SET  6
#define MFIE_TYPE_CHALLENGE 16
#define MFIE_TYPE_ERP       42
#define MFIE_TYPE_RSN       48
#define MFIE_TYPE_RATES_EX  50
#define MFIE_TYPE_GENERIC   221

// from ks7010/eap_packet.h

#define WBIT(n) (1 << (n))

#define WPA_KEY_INFO_TYPE_MASK (WBIT(0) | WBIT(1) | WBIT(2))
#define WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 WBIT(0)
#define WPA_KEY_INFO_TYPE_HMAC_SHA1_AES WBIT(1)
#define WPA_KEY_INFO_KEY_TYPE WBIT(3) /* 1 = Pairwise, 0 = Group key */
#define WPA_KEY_INFO_KEY_INDEX_MASK (WBIT(4) | WBIT(5))
#define WPA_KEY_INFO_KEY_INDEX_SHIFT 4
#define WPA_KEY_INFO_INSTALL WBIT(6)  /* pairwise */
#define WPA_KEY_INFO_TXRX WBIT(6) /* group */
#define WPA_KEY_INFO_ACK WBIT(7)
#define WPA_KEY_INFO_MIC WBIT(8)
#define WPA_KEY_INFO_SECURE WBIT(9)
#define WPA_KEY_INFO_ERROR WBIT(10)
#define WPA_KEY_INFO_REQUEST WBIT(11)
#define WPA_KEY_INFO_ENCR_KEY_DATA WBIT(12) /* IEEE 802.11i/RSN only */

// radiotap header from http://www.radiotap.org/

struct ieee80211_radiotap_header
{
	u8  it_version;     /* set to 0 */
	u8  it_pad;
	u16 it_len;         /* entire length */
	u32 it_present;     /* fields present */

};

typedef struct ieee80211_radiotap_header ieee80211_radiotap_header_t;

// own structs

struct auth_packet
{
	u8  version;
	u8  type;
	u16 length;
	u8  key_descriptor;
	u16 key_information;
	u16 key_length;
	u64 replay_counter;
	u8  wpa_key_nonce[32];
	u8  wpa_key_iv[16];
	u8  wpa_key_rsc[8];
	u8  wpa_key_id[8];
	u8  wpa_key_mic[16];
	u16 wpa_key_data_length;

};

typedef struct auth_packet auth_packet_t;

#define MAX_ESSID_LEN 32

struct essid_t
{
	u8   bssid[6];
	char essid[MAX_ESSID_LEN + 4];
	int  essid_len;
	bool operator<(const essid_t& e) const;
};

#define EAPOL_TTL 2

#define EXC_PKT_NUM_1 1
#define EXC_PKT_NUM_2 2
#define EXC_PKT_NUM_3 3
#define EXC_PKT_NUM_4 4

typedef enum
{
	MESSAGE_PAIR_M12E2 = 0,
	MESSAGE_PAIR_M14E4 = 1,
	MESSAGE_PAIR_M32E2 = 2,
	MESSAGE_PAIR_M32E3 = 3,
	MESSAGE_PAIR_M34E3 = 4,
	MESSAGE_PAIR_M34E4 = 5,

} message_pair_t;

#define BROADCAST_MAC "\xff\xff\xff\xff\xff\xff"

struct excpkt_t
{
	int excpkt_num;

	u32 tv_sec;
	u32 tv_usec;

	u64 replay_counter;

	u8  mac_ap[6];
	u8  mac_sta[6];

	u8  nonce[32];

	u16 eapol_len;
	u8  eapol[256];

	u8  keyver;
	u8  keymic[16];

	bool operator<(const excpkt_t& e) const;
};

// databases

set<essid_t> essids;
set<excpkt_t> excpkts;

// output

#define HCCAPX_SIGNATURE 0x58504348 // HCPX
/*
struct hccapx
{
u32 signature;
u32 version;
u8  authenticated;
u8  essid_len;
u8  essid[32];
u8  keyver;
u8  keymic[16];
u8  mac_ap[6];
u8  nonce_ap[32];
u8  mac_sta[6];
u8  nonce_sta[32];
u16 eapol_len;
u8  eapol[256];

} ;

typedef struct hccapx hccapx_t;
*/
// functions

u8 hex_convert(const u8 c)
{
	return (c & 15) + (c >> 6) * 9;
}

u8 hex_to_u8(const u8 hex[2])
{
	u8 v = 0;

	v |= ((u8)hex_convert(hex[1]) << 0);
	v |= ((u8)hex_convert(hex[0]) << 4);

	return (v);
}

/*
bool excpkt_t::operator<(const excpkt_t& e) const
{
	const int excpkt_diff = excpkt_num - e.excpkt_num;
	if (excpkt_diff != 0) return false;

	const int rc_nonce = memcmp(nonce, e.nonce, 32);
	if (rc_nonce != 0) return false;

	const int rc_mac_ap = memcmp(mac_ap, e.mac_ap, 6);
	if (rc_mac_ap != 0) return false;

	const int rc_mac_sta = memcmp(mac_sta, e.mac_sta, 6);
	if (rc_mac_sta != 0) return false;

	if (replay_counter != e.replay_counter) return false;
	return true;
}

bool essid_t::operator==(const essid_t& e) const
{	
	return memcmp(bssid, e.bssid, 6) == 0;
}
*/
bool excpkt_t::operator<(const excpkt_t& e) const
{
	const int excpkt_diff = excpkt_num - e.excpkt_num;
	if (excpkt_diff != 0) return excpkt_diff<0;

	const int rc_nonce = memcmp(nonce, e.nonce, 32);
	if (rc_nonce != 0) return rc_nonce<0;

	const int rc_mac_ap = memcmp(mac_ap, e.mac_ap, 6);
	if (rc_mac_ap != 0) return rc_mac_ap<0;

	const int rc_mac_sta = memcmp(mac_sta, e.mac_sta, 6);
	if (rc_mac_sta != 0) return rc_mac_sta<0;

	if (replay_counter != e.replay_counter) return (replay_counter < e.replay_counter);
	return true;
}

bool essid_t::operator<(const essid_t& e) const
{
	return (memcmp(bssid, e.bssid, 6) < 0);
}


static void db_excpkt_add(excpkt_t *excpkt, const u32 tv_sec, const u32 tv_usec, const u8 mac_ap[6], const u8 mac_sta[6])
{
	excpkt->tv_sec = tv_sec;
	excpkt->tv_usec = tv_usec;

	memcpy(excpkt->mac_ap, mac_ap, 6);
	memcpy(excpkt->mac_sta, mac_sta, 6);

	if (excpkts.find(*excpkt) == excpkts.end())
		excpkts.insert(*excpkt);
}

static void db_essid_add(essid_t *essid, const u8 addr3[6])
{
	memcpy(essid->bssid, addr3, 6);
	if (essids.find(*essid) == essids.end())
		essids.insert(*essid);
}

static int handle_llc(const ieee80211_llc_snap_header_t *ieee80211_llc_snap_header)
{
	if (ieee80211_llc_snap_header->dsap != IEEE80211_LLC_DSAP) return -1;
	if (ieee80211_llc_snap_header->ssap != IEEE80211_LLC_SSAP) return -1;
	if (ieee80211_llc_snap_header->ctrl != IEEE80211_LLC_CTRL) return -1;

	if (ieee80211_llc_snap_header->ethertype != IEEE80211_DOT1X_AUTHENTICATION) return -1;

	return 0;
}

static int handle_auth(const auth_packet_t *auth_packet, const int pkt_offset, const int pkt_size, excpkt_t *excpkt)
{
	const u16 ap_key_information = _byteswap_ushort(auth_packet->key_information);
	const u16 ap_length = _byteswap_ushort(auth_packet->length);
	const u16 ap_wpa_key_data_length = _byteswap_ushort(auth_packet->wpa_key_data_length);
	const u64 ap_replay_counter = _byteswap_uint64(auth_packet->replay_counter);

	if (ap_length == 0) return -1;

	// determine handshake exchange number

	int excpkt_num = 0;

	if (ap_key_information & WPA_KEY_INFO_ACK)
	{
		if (ap_key_information & WPA_KEY_INFO_INSTALL)
		{
			excpkt_num = EXC_PKT_NUM_3;
		}
		else
		{
			excpkt_num = EXC_PKT_NUM_1;
		}
	}
	else
	{
		if (ap_key_information & WPA_KEY_INFO_SECURE)
		{
			excpkt_num = EXC_PKT_NUM_4;
		}
		else
		{
			excpkt_num = EXC_PKT_NUM_2;
		}
	}

	// process packet based on handshake exchange number

	excpkt->excpkt_num = excpkt_num;

	memcpy(excpkt->nonce, auth_packet->wpa_key_nonce, 32);

	excpkt->replay_counter = ap_replay_counter;

	if (excpkt_num == EXC_PKT_NUM_1)
	{
		// nothing to do
	}
	else if (excpkt_num == EXC_PKT_NUM_2)
	{
		excpkt->eapol_len = sizeof(auth_packet_t) + ap_wpa_key_data_length;

		if ((pkt_offset + excpkt->eapol_len) > pkt_size) return -1;

		if ((sizeof(auth_packet_t) + ap_wpa_key_data_length) > sizeof(excpkt->eapol)) return -1;

		// we need to copy the auth_packet_t but have to clear the keymic
		auth_packet_t auth_packet_orig;

		memcpy(&auth_packet_orig, auth_packet, sizeof(auth_packet_t));

		memset(auth_packet_orig.wpa_key_mic, 0, 16);

		memcpy(excpkt->eapol, &auth_packet_orig, sizeof(auth_packet_t));
		memcpy(excpkt->eapol + sizeof(auth_packet_t), auth_packet + 1, ap_wpa_key_data_length);

		memcpy(excpkt->keymic, auth_packet->wpa_key_mic, 16);

		excpkt->keyver = ap_key_information & WPA_KEY_INFO_TYPE_MASK;
	}
	else if (excpkt_num == EXC_PKT_NUM_3)
	{
		// reduce by one

		excpkt->replay_counter--;
	}
	else if (excpkt_num == EXC_PKT_NUM_4)
	{
		return -1;
	}
	else
	{
		return -1;
	}

	return 0;
}

static int get_essid_from_beacon(const u8 *packet, const pcap_pkthdr_t *header, u32 length_skip, essid_t *essid)
{
	if (length_skip > header->caplen) return -1;

	u32 length = header->caplen - length_skip;

	const u8 *beacon = packet + length_skip;

	const u8 *cur = beacon;
	const u8 *end = beacon + length;

	while (cur < end)
	{
		if ((cur + 2) >= end) break;

		u8 tagtype = *cur++;
		u8 taglen = *cur++;

		if ((cur + taglen) >= end) break;

		if (tagtype == MFIE_TYPE_SSID)
		{
			if (taglen < MAX_ESSID_LEN)
			{
				memcpy(essid->essid, cur, taglen);

				essid->essid_len = taglen;

				return 0;
			}
		}

		cur += taglen;
	}

	return -1;
}

static void process_packet(const u8 *packet, const pcap_pkthdr_t *header)
{
	if (header->caplen < sizeof(ieee80211_hdr_3addr_t)) return;

	// our first header: ieee80211

	ieee80211_hdr_3addr_t *ieee80211_hdr_3addr = (ieee80211_hdr_3addr_t *)packet;

	const u16 frame_control = ieee80211_hdr_3addr->frame_control;

	if ((frame_control & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_MGMT)
	{
		if (memcmp(ieee80211_hdr_3addr->addr3, BROADCAST_MAC, 6) == 0) return;

		essid_t essid;

		memset(&essid, 0, sizeof(essid_t));

		int rc_beacon = -1;

		const int stype = frame_control & IEEE80211_FCTL_STYPE;

		if ((stype == IEEE80211_STYPE_BEACON) || (stype == IEEE80211_STYPE_PROBE_RESP))
		{
			u32 length_skip = sizeof(ieee80211_hdr_3addr_t) + sizeof(u64) + sizeof(u16) + sizeof(u16);

			rc_beacon = get_essid_from_beacon(packet, header, length_skip, &essid);
		}
		else if (stype == IEEE80211_STYPE_PROBE_REQ)
		{
			u32 length_skip = sizeof(ieee80211_hdr_3addr_t);

			rc_beacon = get_essid_from_beacon(packet, header, length_skip, &essid);
		}

		if (rc_beacon == -1) return;

		if (essid.essid_len == 0) return;

		// add the beacon to our database

		db_essid_add(&essid, ieee80211_hdr_3addr->addr3);
	}
	else if ((frame_control & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_DATA)
	{
		// process header: ieee80211

		int set = 0;

		if (frame_control & IEEE80211_FCTL_TODS)   set++;
		if (frame_control & IEEE80211_FCTL_FROMDS) set++;

		if (set != 1) return;

		// find offset to llc/snap header

		int llc_offset;

		if ((frame_control & IEEE80211_FCTL_STYPE) == IEEE80211_STYPE_QOS_DATA)
		{
			llc_offset = sizeof(ieee80211_qos_hdr_t);
		}
		else
		{
			llc_offset = sizeof(ieee80211_hdr_3addr_t);
		}

		// process header: the llc/snap header

		if (header->caplen < (llc_offset + sizeof(ieee80211_llc_snap_header_t))) return;

		const ieee80211_llc_snap_header_t *ieee80211_llc_snap_header = (ieee80211_llc_snap_header_t *)&packet[llc_offset];

		const int rc_llc = handle_llc(ieee80211_llc_snap_header);

		if (rc_llc == -1) return;

		// process header: the auth header

		const int auth_offset = llc_offset + sizeof(ieee80211_llc_snap_header_t);

		if (header->caplen < (auth_offset + sizeof(auth_packet_t))) return;

		const auth_packet_t *auth_packet = (auth_packet_t *)&packet[auth_offset];

		excpkt_t excpkt;

		memset(&excpkt, 0, sizeof(excpkt_t));

		const int rc_auth = handle_auth(auth_packet, auth_offset, header->caplen, &excpkt);

		if (rc_auth == -1) return;

		if ((excpkt.excpkt_num == EXC_PKT_NUM_1) || (excpkt.excpkt_num == EXC_PKT_NUM_3))
		{
			db_excpkt_add(&excpkt, header->tv_sec, header->tv_usec, ieee80211_hdr_3addr->addr2, ieee80211_hdr_3addr->addr1);
		}
		else if (excpkt.excpkt_num == EXC_PKT_NUM_2)
		{
			db_excpkt_add(&excpkt, header->tv_sec, header->tv_usec, ieee80211_hdr_3addr->addr1, ieee80211_hdr_3addr->addr2);
		}
	}
}

//https://stackoverflow.com/questions/2342162/stdstring-formatting-like-sprintf
std::string string_format(const std::string fmt_str, va_list ap) {
	int final_n, n = ((int)fmt_str.size()) * 2; /* Reserve two times as much as the length of the fmt_str */
	std::unique_ptr<char[]> formatted;
	while (1) {
		formatted.reset(new char[n]); /* Wrap the plain char array into the unique_ptr */
		strcpy_s(&formatted[0], n, fmt_str.c_str());
		final_n = vsnprintf(&formatted[0], n, fmt_str.c_str(), ap);
		if (final_n < 0 || final_n >= n)
			n += abs(final_n - n + 1);
		else
			break;
	}
	return std::string(formatted.get());
}

//template<class ...Us>
void log_message(string of, string text, ...)
{
	std::ofstream o;
	o.open(of, ios::out | ios::ate | ios::app);
	if (!o.is_open())
		return;
	va_list ap;
	va_start(ap, text);
	o << string_format(text, ap);
	va_end(ap);
	o << std::endl;
	o.close();
}

string sanitize(const char* p)
{
	char buf[32 + 1];
	strncpy(buf, p, 32);
	buf[32] = 0;
	const string ok_chars = " _-.@#";
	for (int i = 0; i < 32; i++)
		if (buf[i] != 0 && !isalnum(buf[i]) && (ok_chars.find(buf[i]) == string::npos))
			buf[i] = '_';
	return string(buf);
}

string mac_string(const u8* p)
{
	char buf[32];
	sprintf_s(buf, "%02X%02X%02X%02X%02X%02X", p[0], p[1], p[2], p[3], p[4], p[5]);
	return string(buf);
}


#pragma pack(push, 1)
struct hccapx_t
{
	uint32_t signature;
	uint32_t version;
	uint8_t authenticated;
	uint8_t essid_len;
	uint8_t essid[32];
	uint8_t keyver;
	uint8_t keymic[16];
	uint8_t mac_ap[6];
	uint8_t nonce_ap[32];
	uint8_t mac_sta[6];
	uint8_t nonce_sta[32];
	uint16_t eapol_len;
	uint8_t eapol[256];
};

struct hccapx_v4
{
	u32 signature;
	u32 version;
	u8  message_pair;
	u8  essid_len;
	u8  essid[32];
	u8  keyver;
	u8  keymic[16];
	u8  mac_ap[6];
	u8  nonce_ap[32];
	u8  mac_sta[6];
	u8  nonce_sta[32];
	uint16_t eapol_len;
	u8  eapol[256];
};
#pragma pack(pop)

int hccap_conv(string s, string o_err, string out_dir, string o_result, bool v4)
{
	const char* in = s.c_str();
	// manual beacon
	// start with pcap handling

	FILE *pcap = fopen(s.c_str(), "rb");

	if (pcap == NULL)
	{
		log_message(o_err, "%s: %s", s.c_str(), strerror(errno));
		return -1;
	}

	// check pcap header

	pcap_file_header_t pcap_file_header;

	const size_t nread = fread(&pcap_file_header, sizeof(pcap_file_header_t), 1, pcap);

	if (nread != 1)
	{
		log_message(o_err, "%s: Could not read pcap header", in);
		return -1;
	}

	int bitness = 0;

	if (pcap_file_header.magic == TCPDUMP_MAGIC)
	{
		bitness = 0;
	}
	else if (pcap_file_header.magic == TCPDUMP_CIGAM)
	{
		bitness = 1;
	}
	else
	{
		log_message(o_err, "%s: Invalid pcap header", in);
		return 1;
	}

	if (bitness == 1)
	{
		pcap_file_header.magic = _byteswap_ulong(pcap_file_header.magic);
		pcap_file_header.version_major = _byteswap_ushort(pcap_file_header.version_major);
		pcap_file_header.version_minor = _byteswap_ushort(pcap_file_header.version_minor);
		pcap_file_header.thiszone = _byteswap_ulong(pcap_file_header.thiszone);
		pcap_file_header.sigfigs = _byteswap_ulong(pcap_file_header.sigfigs);
		pcap_file_header.snaplen = _byteswap_ulong(pcap_file_header.snaplen);
		pcap_file_header.linktype = _byteswap_ulong(pcap_file_header.linktype);
	}

	if ((pcap_file_header.linktype != DLT_IEEE802_11) && (pcap_file_header.linktype != DLT_IEEE802_11_RADIO))
	{
		log_message(o_err, "%s: Unsupported linktype detected", in);
		return -1;
	}

	// walk the packets

	while (!feof(pcap))
	{
		pcap_pkthdr_t header;

		const size_t nread1 = fread(&header, sizeof(pcap_pkthdr_t), 1, pcap);

		if (nread1 != 1) continue;

		if (bitness == 1)
		{
			header.tv_sec = _byteswap_ulong(header.tv_sec);
			header.tv_usec = _byteswap_ulong(header.tv_usec);
			header.caplen = _byteswap_ulong(header.caplen);
			header.len = _byteswap_ulong(header.len);
		}

		u8 packet[TCPDUMP_DECODE_LEN];

		if (header.caplen >= TCPDUMP_DECODE_LEN)
		{
			log_message(o_err, "%s: Oversized packet detected\n", in);
			break;
		}

		u32 pos = ftell(pcap);
		const u32 nread2 = fread(&packet, sizeof(u8), header.caplen, pcap);

		if (nread2 != header.caplen)
		{
			log_message(o_err, "%s: incomplete packet at %d", in, pos);
			break;
			//			return -1;
		}

		u8 *packet_ptr = packet;

		if (pcap_file_header.linktype == DLT_IEEE802_11_RADIO)
		{
			if (header.caplen < sizeof(ieee80211_radiotap_header_t))
			{
				log_message(o_err, "%s: Could not read radiotap header", in);

				return -1;
			}

			ieee80211_radiotap_header_t *ieee80211_radiotap_header = (ieee80211_radiotap_header_t *)packet;

			if (ieee80211_radiotap_header->it_version != 0)
			{
				log_message(o_err, "%s: Invalid radiotap header", in);
				return -1;
			}

			packet_ptr += ieee80211_radiotap_header->it_len;
			header.caplen -= ieee80211_radiotap_header->it_len;
			header.len -= ieee80211_radiotap_header->it_len;
		}

		process_packet(packet_ptr, &header);
	}

	fclose(pcap);

	// inform the user

	log_message(o_err, "%s: networks detected: %d", in, essids.size());

	if (essids.empty()) return 0;

	int written = 0;

	// find matching packets

	//	for (lsearch_cnt_t excpkt_ap_pos = 0; excpkt_ap_pos < excpkts_cnt; excpkt_ap_pos++)
	//	{
	//		const excpkt_t *excpkt_ap = excpkts + excpkt_ap_pos;
	//		printf("%d %d:%06d %08x:%08x replay %d type %d eapol ",
	//			excpkt_ap_pos,
	//			excpkt_ap->tv_sec, excpkt_ap->tv_usec,
	//			*(int*)excpkt_ap->mac_ap, *(int*)excpkt_ap->mac_sta, excpkt_ap->replay_counter, excpkt_ap->excpkt_num);
	//		for (int i = 0; i < 10; i++)
	//			printf("%08x ", *(int*)(excpkt_ap->eapol + i * 4));
	//		printf("\n");
	//	}
	std::set<string> new_files;
	for (const auto& essid: essids)
	{
		for (const auto& pkt_ap: excpkts)
		{
			if ((pkt_ap.excpkt_num != EXC_PKT_NUM_1) && (pkt_ap.excpkt_num != EXC_PKT_NUM_3)) continue;

			if (memcmp(essid.bssid, pkt_ap.mac_ap, 6) != 0) continue;

			for (const auto& pkt_sta: excpkts)
			{
				double t_ap = pkt_ap.tv_sec + 0.000001*pkt_ap.tv_usec;
				double t_sta = pkt_sta.tv_sec + 0.000001*pkt_sta.tv_usec;

				if (pkt_sta.excpkt_num != EXC_PKT_NUM_2) continue;

				if (memcmp(pkt_ap.mac_ap, pkt_sta.mac_ap, 6) != 0) continue;
				if (memcmp(pkt_ap.mac_sta, pkt_sta.mac_sta, 6) != 0) continue;

				const bool valid_replay_counter = (pkt_ap.replay_counter == pkt_sta.replay_counter);

				if (!v4 && !valid_replay_counter)
					continue;

				if (pkt_ap.excpkt_num == EXC_PKT_NUM_1)
				{
					if (t_ap > t_sta) continue;
					if ((t_ap + EAPOL_TTL) < t_sta) continue;
				}
				else
				{
					if (t_sta > t_ap) continue;
					if ((t_sta + EAPOL_TTL) < t_ap) continue;
				}

				const u8 authenticated = (pkt_ap.excpkt_num == EXC_PKT_NUM_3);


				u8 message_pair = 255;

				if (v4)
				{
					if ((pkt_ap.excpkt_num == EXC_PKT_NUM_1) && (pkt_sta.excpkt_num == EXC_PKT_NUM_2))
					{
						if (pkt_sta.eapol_len > 0)
						{
							message_pair = MESSAGE_PAIR_M12E2;
						}
						else
						{
							continue;
						}
					}
					else if ((pkt_ap.excpkt_num == EXC_PKT_NUM_1) && (pkt_sta.excpkt_num == EXC_PKT_NUM_4))
					{
						if (pkt_sta.eapol_len > 0)
						{
							message_pair = MESSAGE_PAIR_M14E4;
						}
						else
						{
							continue;
						}
					}
					else if ((pkt_ap.excpkt_num == EXC_PKT_NUM_3) && (pkt_sta.excpkt_num == EXC_PKT_NUM_2))
					{
						if (pkt_sta.eapol_len > 0)
						{
							message_pair = MESSAGE_PAIR_M32E2;
						}
						else if (pkt_ap.eapol_len > 0)
						{
							message_pair = MESSAGE_PAIR_M32E3;
						}
						else
						{
							continue;
						}
					}
					else if ((pkt_ap.excpkt_num == EXC_PKT_NUM_3) && (pkt_sta.excpkt_num == EXC_PKT_NUM_4))
					{
						if (pkt_ap.eapol_len > 0)
						{
							message_pair = MESSAGE_PAIR_M34E3;
						}
						else if (pkt_sta.eapol_len > 0)
						{
							message_pair = MESSAGE_PAIR_M34E4;
						}
						else
						{
							continue;
						}
					}
					else
					{
						log_message(o_err, "BUG!!! AP:%d STA:%d", pkt_ap.excpkt_num, pkt_sta.excpkt_num);
					}

					int export = 1;

					switch (message_pair)
					{
					case MESSAGE_PAIR_M32E3: export = 0; break;
					case MESSAGE_PAIR_M34E3: export = 0; break;
					}

					if (export == 1)
					{
						/*
						printf(" --> STA=%02x:%02x:%02x:%02x:%02x:%02x, Message Pair=%u, Replay Counter=%llu\n",
						pkt_sta.mac_sta[0],
						pkt_sta.mac_sta[1],
						pkt_sta.mac_sta[2],
						pkt_sta.mac_sta[3],
						pkt_sta.mac_sta[4],
						pkt_sta.mac_sta[5],
						message_pair,
						pkt_sta.replay_counter);
						*/
					}
					else
					{
						/*
						printf(" --> STA=%02x:%02x:%02x:%02x:%02x:%02x, Message Pair=%u [Skipped Export]\n",
						pkt_sta.mac_sta[0],
						pkt_sta.mac_sta[1],
						pkt_sta.mac_sta[2],
						pkt_sta.mac_sta[3],
						pkt_sta.mac_sta[4],
						pkt_sta.mac_sta[5],
						message_pair);
						*/
						continue;
					}
				}
				/*
				printf("Packet %d x %d\n", excpkt_ap_pos, excpkt_sta_pos);
				printf(" --> STA=%02x:%02x:%02x:%02x:%02x:%02x, Authenticated=%u, Replay Counter=%" PRIu64 "\n",
				excpkt_sta->mac_sta[0],
				excpkt_sta->mac_sta[1],
				excpkt_sta->mac_sta[2],
				excpkt_sta->mac_sta[3],
				excpkt_sta->mac_sta[4],
				excpkt_sta->mac_sta[5],
				authenticated,
				excpkt_sta->replay_counter);
				*/

				string sanitized_essid = sanitize(essid.essid);
				if (sanitized_essid.size() == 0)
					continue;
				string ap_str = mac_string(pkt_ap.mac_ap);
				string fn;
				if (out_dir == ".")
					fn = sanitized_essid + "." + ap_str + "." + mac_string(pkt_sta.mac_sta) + ".hccapx";
				else
					fn = out_dir + "\\" + sanitized_essid + "." + ap_str + "." + mac_string(pkt_sta.mac_sta) + ".hccapx";
				FILE* fp = 0;

				if (new_files.find(fn) == new_files.end())
				{
					fopen_s(&fp, fn.c_str(), "rb");
					if (fp != 0)
					{
						fclose(fp);
						log_message(o_err, "%s: %s already exists", in, fn.c_str());
						continue;
					}
					new_files.insert(fn);
				}
				// finally, write hccapx

				hccapx_t hccapx;

				hccapx.signature = HCCAPX_SIGNATURE;

				if (!v4)
				{
					hccapx.version = 3;
					hccapx.authenticated = authenticated;
				}
				else
				{
					hccapx.version = 4;
					hccapx.authenticated = message_pair;

					if (valid_replay_counter == false)
					{
						hccapx.authenticated |= 0x80;
					}
				}

				hccapx.essid_len = essid.essid_len;
				memcpy(&hccapx.essid, essid.essid, 32);

				hccapx.keyver = pkt_sta.keyver;
				memcpy(&hccapx.keymic, pkt_sta.keymic, 16);

				memcpy(&hccapx.mac_ap, pkt_ap.mac_ap, 6);
				memcpy(&hccapx.nonce_ap, pkt_ap.nonce, 32);

				memcpy(&hccapx.mac_sta, pkt_sta.mac_sta, 6);
				memcpy(&hccapx.nonce_sta, pkt_sta.nonce, 32);

				hccapx.eapol_len = pkt_sta.eapol_len;
				memcpy(&hccapx.eapol, pkt_sta.eapol, 256);

				fopen_s(&fp, fn.c_str(), "rb");
				bool need_to_record = true;
				if (fp != 0)
				{
					need_to_record = false;
					fclose(fp);
				}

				fopen_s(&fp, fn.c_str(), "ab");
				if (fp == NULL)
				{
					log_message(o_err, "%s: failed to open %s for writing", in, fn.c_str());
				}

				fwrite(&hccapx, sizeof(hccapx_t), 1, fp);
				fclose(fp);
				written++;
				if (need_to_record)
					log_message(o_result, "%s\t%s", ap_str.c_str(), fn.c_str());
			}
		}
	}
	return 0;
}


int _tmain(int argc, _TCHAR* argv[])
{
	bool v4 = (argc == 6 && !strcmp(argv[5], "v4"));
	if (argc >= 5)
	{
		hccap_conv(argv[1], argv[2], argv[3], argv[4], v4);
		return 0;
	}
	printf("Usage: %s capfile log_file outdir result_list\n");
	return -1;
}

