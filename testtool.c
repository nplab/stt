/*
 *
 * SCTP test tool stt.
 *
 * Copyright (C) 2002-2008 by Michael Tuexen
 *
 * Realized in co-operation between Siemens AG and the Muenster University of
 * Applied Sciences.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * There are two mailinglists available at http://www.sctp.de which should be
 * used for any discussion related to this implementation.
 *
 * Contact: tuexen@fh-muenster.de
 *
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <stdio.h>
#include <libguile.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include "common.h"
#include "parameter.h"
#include "cause.h"
#include "chunk.h"
#include "checksum.h"
#include "common_header.h"
#include "addresses.h"
#include "tlv.h"

extern scm_t_bits address_tag;
extern scm_t_bits common_header_tag;
extern scm_t_bits chunk_tag;
/*
 * TODO before release as 1.0
 * - Documentation
 * - add AddIP support
 * TODO after 1.0
 * - add error causes
 * - add print routines
 * - Fix bugs, add user requested featues
 */

#if !defined(IOV_MAX)
#define IOV_MAX 1024
#endif
#define CHECKSUM_CRC32C  1
#define CHECKSUM_ADLER32 2
#define CHECKSUM_ZERO    3
#define CHECKSUM_WRONG   4

static unsigned char packet[IP_MAXPACKET];
static struct iovec iovec[IOV_MAX];
static int sctpv4_fd = -1;
static int sctpv6_fd = -1;
static struct sockaddr_in address_any_v4;
static struct sockaddr_in6 address_any_v6;

static scm_t_uint32
sctp_checksum(struct iovec iov[],
              uint16_t iov_cnt,
              scm_t_int16 checksum_algo)
{
	scm_t_uint32 checksum, adler32, crc32c;
	uint16_t i;

	switch (checksum_algo) {
	case CHECKSUM_CRC32C:
		crc32c = initialize_crc32c();
		for (i = 1; i < iov_cnt; i++) {
			crc32c = update_crc32c(crc32c, iov[i].iov_base, iov[i].iov_len);
		}
		crc32c = finalize_crc32c(crc32c);
		checksum = crc32c;
		break;
	case CHECKSUM_ADLER32:
		adler32 = initialize_adler32();
		for (i = 1; i < iov_cnt; i++) {
			adler32 = update_adler32(adler32, iov[i].iov_base, iov[i].iov_len);
		}
		adler32 = finalize_adler32(adler32);
		checksum = crc32c;
		break;
	case CHECKSUM_ZERO:
		checksum = 0;
		break;
	case CHECKSUM_WRONG:
		crc32c = initialize_crc32c();
		adler32 = initialize_adler32();
		for (i = 1; i < iov_cnt; i++) {
			crc32c = update_crc32c(crc32c, iov[i].iov_base, iov[i].iov_len);
			adler32 = update_adler32(adler32, iov[i].iov_base, iov[i].iov_len);
		}
		crc32c = finalize_crc32c(crc32c);
		adler32 = finalize_adler32(adler32);
		/* avoid 0, crc32c, and adler32 */
		for (checksum = 1; checksum < 4; checksum++) {
			if ((checksum != crc32c) && (checksum != adler32)) {
				break;
			}
		}
		break;
	}
	return (checksum);
}

static SCM
sctp_send_iov(struct iovec iov[],
              uint16_t iov_cnt,
              struct sockaddr *to_address,
              struct sockaddr *from_address,
              scm_t_uint16 checksum_algo)
{
	scm_t_uint32 checksum, adler32, crc32c;
	scm_t_int32 is_ipv4;
	scm_t_uint16 i;
	struct msghdr msg;
#ifdef LINUX
	struct iphdr ip_header;
#else
	struct ip ip_header;
#endif 

	is_ipv4 = (to_address->sa_family == AF_INET);
	if (is_ipv4) {
		if (sctpv4_fd < 0) {
			return SCM_BOOL_F;
		}
	} else {
		if (sctpv6_fd < 0) {
			return SCM_BOOL_F;
		}
	}

	if (is_ipv4) {
		scm_t_uint16 length;
		
		length = 0;
		for(i = 0; i < iov_cnt; i++ ) {
			length += iov[i].iov_len;
		}
#ifdef LINUX
		ip_header.version  = IPVERSION;
		ip_header.ihl      = sizeof(ip_header) >> 2;
		ip_header.tos      = TOS;
		ip_header.tot_len  = htons(length + sizeof(ip_header));
		ip_header.id       = 0;
		ip_header.frag_off = 0;
		ip_header.ttl      = IPDEFTTL;
		ip_header.protocol = IPPROTO_SCTP;
		ip_header.check    = 0;
		memcpy((void *)&(ip_header.daddr), (const void *)&(((struct sockaddr_in *)to_address)->sin_addr),   sizeof(struct in_addr));
		memcpy((void *)&(ip_header.saddr), (const void *)&(((struct sockaddr_in *)from_address)->sin_addr), sizeof(struct in_addr));
#else
		ip_header.ip_v     = IPVERSION;
		ip_header.ip_hl    = sizeof(ip_header) >> 2;
		ip_header.ip_tos   = TOS;
		ip_header.ip_len   = length + sizeof(ip_header);
		ip_header.ip_id    = 0;
		ip_header.ip_off   = 0;
		ip_header.ip_ttl   = IPDEFTTL;
		ip_header.ip_p     = IPPROTO_SCTP;
		ip_header.ip_sum   = 0;
		memcpy((void *)&(ip_header.ip_dst), (const void *)&(((struct sockaddr_in *)to_address)->sin_addr),   sizeof(struct in_addr));
		memcpy((void *)&(ip_header.ip_src), (const void *)&(((struct sockaddr_in *)from_address)->sin_addr), sizeof(struct in_addr));
#endif
		iov[0].iov_base = (void *)&ip_header;
		iov[0].iov_len  = sizeof(ip_header);
	} else {
		iov[0].iov_base = NULL;
		iov[0].iov_len  = 0;
	}
	
	((struct common_header *)(iov[1].iov_base))->checksum = htonl(0);
	((struct common_header *)(iov[1].iov_base))->checksum = htonl(sctp_checksum(iov, iov_cnt, checksum_algo));

	msg.msg_name       = (void *)to_address;
	msg.msg_namelen    = (is_ipv4)?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6);
	msg.msg_iov        = iov;
	msg.msg_iovlen     = iov_cnt;
	msg.msg_control    = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags      = 0;
	if (sendmsg((is_ipv4)?sctpv4_fd:sctpv6_fd, (const struct msghdr *)&msg, 0) < 0) {
		return SCM_BOOL_F;
	} else {
		return SCM_BOOL_T;
	}
}

static SCM
sctp_send(SCM s_common_header,
          SCM s_chunks,
          SCM s_to_address,
          SCM s_from_address,
          scm_t_uint16 checksum_algo,
          const char *name)
{
	size_t length, number_of_chunks;
	struct sockaddr *to_address, *from_address;

	scm_assert_smob_type(common_header_tag, s_common_header);
	SCM_ASSERT(scm_is_simple_vector(s_chunks), s_chunks, SCM_ARG2, name);
	scm_assert_smob_type(address_tag, s_to_address);
	if (!(SCM_UNBNDP(s_from_address))) {
		scm_assert_smob_type(address_tag, s_from_address);
	}

	to_address   = (struct sockaddr *)SCM_SMOB_DATA(s_to_address);
	from_address = NULL;
	switch(to_address->sa_family) {
	case AF_INET:
		if SCM_UNBNDP(s_from_address)
			from_address = (struct sockaddr *)&address_any_v4;
		else
			from_address = (struct sockaddr *)SCM_SMOB_DATA(s_from_address);
		if (from_address->sa_family != AF_INET)
			return (SCM_BOOL_F);
		break;
	case AF_INET6:
		if (!(SCM_UNBNDP(s_from_address)))
			return (SCM_BOOL_F);
		break;
	}

	length = scan_tlv_list(s_chunks, chunk_tag, MAX_SCTP_PACKET_LENGTH - COMMON_HEADER_LENGTH);
	if (length > (MAX_SCTP_PACKET_LENGTH - COMMON_HEADER_LENGTH)) {
		return SCM_BOOL_F;
	}

	number_of_chunks = SCM_SIMPLE_VECTOR_LENGTH(s_chunks);

	iovec[0].iov_base = NULL;
	iovec[0].iov_len  = 0;
	iovec[1].iov_base = (void *)SCM_SMOB_DATA(s_common_header);
	iovec[1].iov_len  = sizeof(struct common_header);
	if (number_of_chunks + 2 > IOV_MAX) {
		put_tlv_list(packet , s_chunks);
		iovec[2].iov_base = (void *)packet;
		iovec[2].iov_len  = length;
		number_of_chunks = 1;
	} else {
		struct chunk *chunk;
		size_t i;

		for(i = 0; i < number_of_chunks; i++) {
			chunk = (struct chunk *)SCM_SMOB_DATA(SCM_SIMPLE_VECTOR_REF(s_chunks, i));
			iovec[i+2].iov_base = (void *)chunk;
			iovec[i+2].iov_len = ADD_PADDING(ntohs(chunk->length));
		}
	}
	return sctp_send_iov(iovec, 2 + number_of_chunks, to_address, from_address, checksum_algo);
}

static SCM
sctp_send_with_crc32c(SCM s_common_header, SCM s_chunks, SCM s_to_address, SCM s_from_address)
{

	return sctp_send(s_common_header, s_chunks, s_to_address, s_from_address, CHECKSUM_CRC32C, "sctp-send-with-crc32c");
}

static SCM
sctp_send_with_adler32(SCM s_common_header, SCM s_chunks, SCM s_to_address, SCM s_from_address)
{
	return sctp_send(s_common_header, s_chunks, s_to_address, s_from_address, CHECKSUM_ADLER32, "sctp-send-with-adler32");
}

static SCM
sctp_send_with_zero(SCM s_common_header, SCM s_chunks, SCM s_to_address, SCM s_from_address)
{
	return sctp_send(s_common_header, s_chunks, s_to_address, s_from_address, CHECKSUM_ZERO, "sctp-send-with-zero");
}

static SCM
sctp_send_with_wrong(SCM s_common_header, SCM s_chunks, SCM s_to_address, SCM s_from_address)
{
	return sctp_send(s_common_header, s_chunks, s_to_address, s_from_address, CHECKSUM_WRONG, "sctp-send-with-wrong");
}

static SCM
sctp_send_raw(SCM s_common_header,
              SCM s_bytes,
              SCM s_to_address,
              SCM s_from_address,
              scm_t_uint16 checksum_algo,
              const char *name)
{
	size_t length, i;
	struct sockaddr *to_address, *from_address;

	scm_assert_smob_type(common_header_tag, s_common_header);
	SCM_ASSERT(scm_is_simple_vector(s_bytes), s_bytes, SCM_ARG2, name);
	scm_assert_smob_type(address_tag, s_to_address);
	if (!(SCM_UNBNDP(s_from_address))) {
		scm_assert_smob_type(address_tag, s_from_address);
	}

	to_address   = (struct sockaddr *)SCM_SMOB_DATA(s_to_address);
	from_address = NULL;
	switch(to_address->sa_family) {
	case AF_INET:
		if SCM_UNBNDP(s_from_address)
			from_address = (struct sockaddr *)&address_any_v4;
		else
			from_address = (struct sockaddr *)SCM_SMOB_DATA(s_from_address);
		if (from_address->sa_family != AF_INET)
			return (SCM_BOOL_F);
		break;
	case AF_INET6:
		if (!(SCM_UNBNDP(s_from_address)))
			return (SCM_BOOL_F);
		break;
	}

	length = SCM_SIMPLE_VECTOR_LENGTH(s_bytes);
	if (length > (MAX_SCTP_PACKET_LENGTH - COMMON_HEADER_LENGTH)) {
		return(SCM_BOOL_F);
	}
	
	for (i = 0; i < length; i++) {
		packet[i] = scm_to_uchar(SCM_SIMPLE_VECTOR_REF(s_bytes, i));
	}

	iovec[0].iov_base = NULL;
	iovec[0].iov_len  = 0;
	iovec[1].iov_base = (void *)SCM_SMOB_DATA(s_common_header);
	iovec[1].iov_len  = sizeof(struct common_header);
	iovec[2].iov_base = (void *)packet;
	iovec[2].iov_len  = length;

	return sctp_send_iov(iovec, 3, to_address, from_address, checksum_algo);
}

static SCM
sctp_send_raw_with_crc32c(SCM s_common_header, SCM s_bytes, SCM s_to_address, SCM s_from_address)
{
	return sctp_send_raw(s_common_header, s_bytes, s_to_address, s_from_address, CHECKSUM_CRC32C, "sctp-send-raw-with-crc32c");
}

static SCM
sctp_send_raw_with_adler32(SCM s_common_header, SCM s_bytes, SCM s_to_address, SCM s_from_address)
{
	return sctp_send_raw(s_common_header, s_bytes, s_to_address, s_from_address, CHECKSUM_ADLER32, "sctp-send-raw-with-adler32");
}

static SCM
sctp_send_raw_with_zero(SCM s_common_header, SCM s_bytes, SCM s_to_address, SCM s_from_address)
{
	return sctp_send_raw(s_common_header, s_bytes, s_to_address, s_from_address, CHECKSUM_ZERO, "sctp-send-raw-with-zero");
}

static SCM
sctp_send_raw_with_wrong(SCM s_common_header, SCM s_bytes, SCM s_to_address, SCM s_from_address)
{
	return sctp_send_raw(s_common_header, s_bytes, s_to_address, s_from_address, CHECKSUM_WRONG, "sctp-send-raw-with-wrong");
}

static SCM
sctp_receive_v4()
{
	SCM s_source, s_destination, s_header, s_chunks, s_checksum_correct;
	scm_t_int32 ip_packet_length;
	scm_t_uint16 sctp_packet_length, ip_header_length;
	scm_t_uint32 save_checksum, checksum;

	struct common_header *common_header;
#ifdef LINUX
	struct iphdr *ip_header;
#else
	struct ip *ip_header;
#endif
	struct sockaddr_in *addr;

	if ((ip_packet_length = recv(sctpv4_fd, packet, sizeof(packet), 0)) < 0) {
		return scm_list_5(SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F);
	}

#ifdef LINUX
	ip_header          = (struct iphdr *) packet;
	ip_header_length   = (ip_header->ihl << 2);
#else
	ip_header          = (struct ip *) packet;
	ip_header_length   = ip_header->ip_hl << 2;
#endif
	sctp_packet_length = (scm_t_uint16)ip_packet_length - ip_header_length;

	addr = (struct sockaddr_in *)scm_gc_malloc(sizeof(struct sockaddr_in), "address");
	memset((void *) addr, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
	addr->sin_len    = sizeof(struct sockaddr_in);
#endif
	addr->sin_family = AF_INET;
	addr->sin_port   = 0;
#ifdef LINUX
	memcpy((void *) &addr->sin_addr, (const void *) &ip_header->saddr, sizeof(struct in_addr));
#else
	memcpy((void *) &addr->sin_addr, (const void *) &ip_header->ip_src, sizeof(struct in_addr));
#endif
	SCM_NEWSMOB(s_source, address_tag, addr);

	addr = (struct sockaddr_in *)scm_gc_malloc(sizeof(struct sockaddr_in), "address");
	memset((void *) addr, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
	addr->sin_len    = sizeof(struct sockaddr_in);
#endif
	addr->sin_family = AF_INET;
	addr->sin_port   = 0;
#ifdef LINUX
	memcpy((void *) &addr->sin_addr, (const void *) &ip_header->daddr, sizeof(struct in_addr));
#else
	memcpy((void *) &addr->sin_addr, (const void *) &ip_header->ip_dst, sizeof(struct in_addr));
#endif
	SCM_NEWSMOB(s_destination, address_tag, addr);

	if (sctp_packet_length >= COMMON_HEADER_LENGTH) {
		common_header = (struct common_header *)(packet + ip_header_length);
		save_checksum = ntohl(common_header->checksum);
		common_header->checksum = htonl(0);
		checksum = initialize_crc32c();
		checksum = update_crc32c(checksum, packet + ip_header_length, sctp_packet_length);
		checksum = finalize_crc32c(checksum);
		if (checksum == save_checksum) {
			s_checksum_correct = SCM_BOOL_T;
		} else {
			s_checksum_correct = SCM_BOOL_F;
		}
		common_header->checksum = ntohl(save_checksum);
		common_header = (struct common_header *)scm_gc_malloc(COMMON_HEADER_LENGTH, "common_header");
		memset((void *) common_header, 0, COMMON_HEADER_LENGTH);
		memcpy((void *) common_header, (const void *) (packet + ip_header_length), COMMON_HEADER_LENGTH);
		SCM_NEWSMOB(s_header, common_header_tag, common_header);
		s_chunks = get_tlv_list(packet + ip_header_length + COMMON_HEADER_LENGTH, sctp_packet_length - COMMON_HEADER_LENGTH, "chunks", chunk_tag);
	} else {
		s_header = SCM_BOOL_F;
		s_chunks = SCM_BOOL_F;
		s_checksum_correct = SCM_BOOL_F;
	}
	return scm_list_5(s_header, s_chunks, s_destination, s_source, s_checksum_correct);
}

static SCM 
sctp_receive_v6()
{
	SCM s_source, s_destination, s_header, s_chunks, s_checksum_correct;
	scm_t_int32 sctp_packet_length;
	scm_t_uint32 save_checksum, checksum;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov[1];
	char ctlbuf[1000];
	struct common_header *common_header;
	struct sockaddr_in6 *addr;
	struct in6_pktinfo *info;

	addr = (struct sockaddr_in6 *)scm_gc_malloc(sizeof(struct sockaddr_in6), "address");
	memset((void *) addr, 0, sizeof(struct sockaddr_in6));
	iov[0].iov_base = packet;
	iov[0].iov_len  = sizeof(packet);
	msg.msg_name       = addr;
	msg.msg_namelen    = sizeof(struct sockaddr_in6);
	msg.msg_iov        = iov;
	msg.msg_iovlen     = 1;
	msg.msg_control    = ctlbuf;
	msg.msg_controllen = sizeof(ctlbuf);
	msg.msg_flags      = 0;

	if ((sctp_packet_length = recvmsg(sctpv6_fd, &msg, 0)) < 0) {
		scm_gc_free(addr, sizeof(struct sockaddr_in6), "address");
		return scm_list_5(SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F);
	}
	SCM_NEWSMOB(s_source, address_tag, addr);
	s_destination = SCM_BOOL_F;
	if (msg.msg_controllen > 0) {
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if ((cmsg->cmsg_level == IPPROTO_IPV6) &&
			    (cmsg->cmsg_type == IPV6_PKTINFO)) {
				info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
				addr = (struct sockaddr_in6 *)scm_gc_malloc(sizeof(struct sockaddr_in6), "address");
				memset((void *)addr, 0, sizeof(struct sockaddr_in6));
#ifdef HAVE_SIN6_LEN
				addr->sin6_len    = sizeof(struct sockaddr_in6);
#endif
				addr->sin6_family = AF_INET6;
				addr->sin6_port   = 0;
				memcpy((void *)&addr->sin6_addr, (const void *)&info->ipi6_addr, sizeof(struct in6_addr));
				SCM_NEWSMOB(s_destination, address_tag, addr);
			}
		}
	}

	if (sctp_packet_length >= COMMON_HEADER_LENGTH) {
		common_header = (struct common_header *)packet;
		save_checksum = ntohl(common_header->checksum);
		common_header->checksum = htonl(0);
		checksum = initialize_crc32c();
		checksum = update_crc32c(checksum, packet, sctp_packet_length);
		checksum = finalize_crc32c(checksum);
		if (checksum == save_checksum) {
			s_checksum_correct = SCM_BOOL_T;
		} else {
			s_checksum_correct = SCM_BOOL_F;
		}
		common_header->checksum = ntohl(save_checksum);
		common_header = (struct common_header *)scm_gc_malloc(COMMON_HEADER_LENGTH, "common_header");
		memset((void *) common_header, 0, COMMON_HEADER_LENGTH);
		memcpy((void *) common_header, (const void *)packet, COMMON_HEADER_LENGTH);
		SCM_NEWSMOB(s_header, common_header_tag, common_header);
		s_chunks = get_tlv_list(packet + COMMON_HEADER_LENGTH, sctp_packet_length - COMMON_HEADER_LENGTH, "chunks", chunk_tag);
	} else {
		s_header = SCM_BOOL_F;
		s_chunks = SCM_BOOL_F;
		s_checksum_correct = SCM_BOOL_F;
	}
	return scm_list_5(s_header, s_chunks, s_destination, s_source, s_checksum_correct);
}

static SCM 
sctp_receive(SCM s_ms)
{
	scm_t_uint32 time_to_wait;
	struct timeval timeval;
	struct timeval *timevalptr;
	int maxfd;
	fd_set rset;

	if (SCM_UNBNDP(s_ms)) {
		timevalptr = NULL;
	} else {
		time_to_wait    = scm_to_uint32(s_ms);
		timeval.tv_sec  = time_to_wait / 1000;
		timeval.tv_usec = 1000 * (time_to_wait % 1000);
		timevalptr      = &timeval;
	}

	maxfd = MAX(sctpv4_fd, sctpv6_fd) + 1;
	FD_ZERO(&rset);
	if (sctpv4_fd >= 0) {
		FD_SET(sctpv4_fd, &rset);
	}
	if (sctpv6_fd >= 0) {
		FD_SET(sctpv6_fd, &rset);
	}

	if (select(maxfd, &rset, NULL, NULL, timevalptr) < 0) {
		if (errno != EINTR) {
			perror("select");
			exit(-1);
		} else {
			return scm_list_5(SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F);
		}
	}
	if (FD_ISSET(sctpv4_fd, &rset)) {
		return sctp_receive_v4();
	}
	if (FD_ISSET(sctpv6_fd, &rset)) {
		return sctp_receive_v6();
	}
	return scm_list_5(SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F, SCM_BOOL_F);
}

static void
close_sockets()
{
	if (sctpv4_fd >= 0) {
		if (close(sctpv4_fd) < 0) {
			perror("close");
			exit(-1);
		} else {
			sctpv4_fd = -1;
		}
	}
	if (sctpv6_fd >= 0) {
		if (close(sctpv6_fd) < 0) {
			perror("close");
			exit(-1);
		} else {
			sctpv6_fd = -1;
		}
	}
}

static void
open_sockets()
{
	sctpv4_fd = socket(AF_INET, SOCK_RAW, IPPROTO_SCTP);
	if (sctpv4_fd >= 0) {
		const int on = 1;

		if (setsockopt(sctpv4_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
			perror("setsockopt");
			exit(-1);
		}
	}
	sctpv6_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_SCTP);
	if (sctpv6_fd >= 0) {
		const int on = 1;
#if defined(DARWIN)
		if (setsockopt(sctpv6_fd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on)) < 0) {
			perror("setsockopt");
			exit(-1);
		}
#endif
#if defined(LINUX) || defined(FREEBSD)
		if (setsockopt(sctpv6_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0) {
			perror("setsockopt");
			exit(-1);
		}
#endif
	}
	if ((sctpv4_fd < 0) && (sctpv6_fd < 0)) {
		fprintf(stderr, "Can't open any socket.\n");
		exit(-1);
	}
}

static SCM
sctp_reset ()
{
	close_sockets();
	open_sockets();
	return SCM_BOOL_T;
}

static void
register_send_receive(void)
{
	scm_c_define_gsubr ("sctp-send-with-crc32c",      3, 1, 0, sctp_send_with_crc32c);
	scm_c_define_gsubr ("sctp-send-with-adler32",     3, 1, 0, sctp_send_with_adler32);
	scm_c_define_gsubr ("sctp-send-with-zero",        3, 1, 0, sctp_send_with_zero);
	scm_c_define_gsubr ("sctp-send-with-wrong",       3, 1, 0, sctp_send_with_wrong);
	scm_c_define_gsubr ("sctp-send-raw-with-crc32c",  3, 1, 0, sctp_send_raw_with_crc32c);
	scm_c_define_gsubr ("sctp-send-raw-with-adler32", 3, 1, 0, sctp_send_raw_with_adler32);
	scm_c_define_gsubr ("sctp-send-raw-with-zero",    3, 1, 0, sctp_send_raw_with_zero);
	scm_c_define_gsubr ("sctp-send-raw-with-wrong",   3, 1, 0, sctp_send_raw_with_wrong);
	scm_c_define_gsubr ("sctp-receive",               0, 1, 0, sctp_receive);
	scm_c_define_gsubr ("sctp-reset",                 0, 0, 0, sctp_reset);
}


#if defined(__APPLE__) || defined(__FreeBSD__)
#define SYSTEMCONFIGFILENAME    "/usr/local/share/stt/init.scm"
#else
#define SYSTEMCONFIGFILENAME    "/usr/share/stt/init.scm"
#endif
#define USERCONFIGFILENAME      ".stt.scm"
#define DIRECTORYSEPARATOR      "/"

static void
read_system_config_file(void)
{
	struct stat st;

	if (stat(SYSTEMCONFIGFILENAME, &st) == 0) {
		scm_c_primitive_load(SYSTEMCONFIGFILENAME);
	}
}

static void
read_user_config_file(void)
{
	char *homedir;
	char *filename;
	struct stat st;

	homedir = getenv("HOME");
	if (homedir == NULL) {
		return;
	}
	filename = (char *)malloc(strlen(homedir) + strlen(USERCONFIGFILENAME) + strlen(DIRECTORYSEPARATOR) + 1);
	if (filename == NULL) {
		return;
	}
	sprintf(filename, "%s%s%s", homedir, DIRECTORYSEPARATOR, USERCONFIGFILENAME);
	if (stat(filename, &st) == 0) {
		scm_c_primitive_load(filename);
	}
	free(filename);
}

static void
inner_main(void *closure, int argc, char **argv)
{
	register_send_receive();
	init_addresses();
	init_common_header_type();
	init_parameters();
	init_chunks();
	init_causes();
	read_system_config_file();
	read_user_config_file();
	scm_shell (argc, argv);
}

int
main(int argc, char *argv[])
{
	memset((void *)&address_any_v4, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
	address_any_v4.sin_len         = sizeof(struct sockaddr_in);
#endif
	address_any_v4.sin_family      = AF_INET;
	address_any_v4.sin_port        = 0;
	address_any_v4.sin_addr.s_addr = htonl(INADDR_ANY);

	memset((void *)&address_any_v6, 0, sizeof(struct sockaddr_in6));
#ifdef HAVE_SIN6_LEN
	address_any_v6.sin6_len       = sizeof(struct sockaddr_in6);
#endif
	address_any_v6.sin6_family    = AF_INET6;
	address_any_v6.sin6_port      = 0;
	address_any_v6.sin6_flowinfo  = 0;
	address_any_v6.sin6_addr      = in6addr_any;

	open_sockets();
	scm_boot_guile (argc, argv, inner_main, 0);
	return(0);
}
