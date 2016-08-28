/*
 *
 * SCTP test tool stt.
 *
 * Copyright (C) 2002-2008 by Michael Tuexen
 *
 * Realized in co-operation between Siemens AG and the Muenster University
 * of Applied Sciences.
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
 * Contact: tuexen@fh-muenster.de
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <libguile.h>

scm_t_bits address_tag;

static SCM
make_ipv4_address(SCM s_address)
{
	struct sockaddr_in *addr;
	struct in_addr sin_addr;
	char *address;
	
	address = scm_to_locale_string(s_address);
	if (inet_pton(AF_INET, address, &sin_addr) == 1) {
		free(address);
		addr = (struct sockaddr_in *)
		       scm_gc_malloc(sizeof(struct sockaddr_in), "address");
		memset((void *) addr, 0, sizeof(struct sockaddr_in));
#if defined (HAVE_SIN_LEN)
		addr->sin_len    = sizeof(struct sockaddr_in);
#endif
		addr->sin_family = AF_INET;
		addr->sin_port   = 0;
		addr->sin_addr   = sin_addr;
		SCM_RETURN_NEWSMOB(address_tag, addr);
	} else {
		free(address);
		return SCM_BOOL_F;
	}
}

static SCM
make_ipv6_address(SCM s_address)
{
	struct sockaddr_in6 *addr;
	struct in6_addr sin6_addr;
	char *address;

	address = scm_to_locale_string(s_address);
	if (inet_pton(AF_INET6, address, &sin6_addr) == 1) {
		free(address);
		addr = (struct sockaddr_in6 *)
		       scm_gc_malloc(sizeof(struct sockaddr_in6), "address");
		memset((void *) addr, 0, sizeof(struct sockaddr_in6));
#if defined (HAVE_SIN6_LEN)
		addr->sin6_len      = sizeof(struct sockaddr_in6);
#endif
		addr->sin6_family   = AF_INET6;
		addr->sin6_port     = 0;
		addr->sin6_flowinfo = 0;
		memcpy((void *) &(addr->sin6_addr),
		       (const void *) &sin6_addr,
		       sizeof(struct in6_addr));
		SCM_RETURN_NEWSMOB (address_tag, addr);
	} else {
		free(address);
		return SCM_BOOL_F;
	}
}

static SCM
mark_address(SCM address_smob)
{
	return SCM_BOOL_F;
}

static size_t
free_address (SCM address_smob)
{  
	struct sockaddr *address;
	
	address = (struct sockaddr *) SCM_SMOB_DATA (address_smob);
	switch (address->sa_family) {
	case AF_INET:
		scm_gc_free(address, sizeof(struct sockaddr_in), "address");
		break;
	case AF_INET6:
		scm_gc_free(address, sizeof(struct sockaddr_in6), "address");
		break;
	default:
		break;
	}
	return 0;
}

static int
print_address (SCM address_smob, SCM port, scm_print_state *pstate)
{
	struct sockaddr *address;
	char address_string[INET6_ADDRSTRLEN];

	memset((void *)address_string, 0, INET6_ADDRSTRLEN);
	scm_puts("#<address: ", port);

	address = (struct sockaddr *) SCM_SMOB_DATA (address_smob);
	switch (address->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET,
		          &(((struct sockaddr_in *)address)->sin_addr),
		          address_string,
		          INET_ADDRSTRLEN);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6,
		          &(((struct sockaddr_in6 *)address)->sin6_addr),
		          address_string,
		          INET6_ADDRSTRLEN);
		break;
	default:
		break;
	}
	scm_puts(address_string, port);
	scm_puts (">", port);
	return 1;
}

static SCM
equalp_address(SCM address_1_smob, SCM address_2_smob)
{
	struct sockaddr *address_1, *address_2;

	address_1 = (struct sockaddr *) SCM_SMOB_DATA (address_1_smob);
	address_2 = (struct sockaddr *) SCM_SMOB_DATA (address_2_smob);

	switch (address_1->sa_family) {
	case AF_INET:
		switch (address_2->sa_family) {
		case AF_INET:
			if (memcmp(&((struct sockaddr_in *)address_1)->sin_addr,
			           &((struct sockaddr_in *)address_2)->sin_addr,
			           sizeof(struct in_addr)) == 0) {
				return SCM_BOOL_T;
			} else {
				return SCM_BOOL_F;
			}
		case AF_INET6:
			return SCM_BOOL_F;
			break;
		default:
			return SCM_BOOL_F;
			break;
		}
		break;
	case AF_INET6:
		switch (address_2->sa_family) {
		case AF_INET:
			return SCM_BOOL_F;
			break;
		case AF_INET6:
			if (memcmp(&((struct sockaddr_in6 *)address_1)->sin6_addr,
			           &((struct sockaddr_in6 *)address_2)->sin6_addr,
			           sizeof(struct in6_addr)) == 0) {
				return SCM_BOOL_T;
			} else {
				return SCM_BOOL_F;
			}
			break;
		default:
			return SCM_BOOL_F;
			break;
		}
		break;
	default:
		break;
	}
	return SCM_BOOL_F;
}

void
init_addresses(void)
{
	address_tag = scm_make_smob_type("address", 0);

	scm_set_smob_mark(address_tag, mark_address);
	scm_set_smob_free(address_tag, free_address);
	scm_set_smob_print(address_tag, print_address);
	scm_set_smob_equalp(address_tag, equalp_address);
	scm_c_define_gsubr("make-ipv4-address", 1, 0, 0, make_ipv4_address);
	scm_c_define_gsubr("make-ipv6-address", 1, 0, 0, make_ipv6_address);
}
