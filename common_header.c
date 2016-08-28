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

#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <libguile.h>
#include "common_header.h"
 
scm_t_bits common_header_tag;

static SCM
make_common_header(SCM s_source_port, SCM s_destination_port, SCM s_verification_tag)
{
	struct common_header *common_header;
	scm_t_uint16 source_port, destination_port;
	scm_t_uint32 verification_tag, checksum;

	source_port      = scm_to_uint16(s_source_port);
	destination_port = scm_to_uint16(s_destination_port);
	verification_tag = scm_to_uint32(s_verification_tag);
	checksum         = 0;

	common_header = (struct common_header *) scm_gc_malloc(sizeof(struct common_header), "common_header");
	memset((void *) common_header, 0, sizeof(struct common_header));

	common_header->source_port      = htons(source_port);
	common_header->destination_port = htons(destination_port);
	common_header->verification_tag = htonl(verification_tag);
	common_header->checksum         = htonl(checksum);

	SCM_RETURN_NEWSMOB(common_header_tag, common_header);
}

static SCM
common_header_p(SCM smob)
{
	if (SCM_SMOB_PREDICATE(common_header_tag, smob)) {
		return SCM_BOOL_T;
	} else {
		return SCM_BOOL_F;
	}
}

SCM
get_source_port(SCM common_header_smob)
{
	struct common_header *common_header;

	scm_assert_smob_type(common_header_tag, common_header_smob);
	common_header = (struct common_header *) SCM_SMOB_DATA(common_header_smob);
	return scm_from_uint16(ntohs(common_header->source_port));
}

SCM
get_destination_port(SCM common_header_smob)
{
	struct common_header *common_header;

	scm_assert_smob_type(common_header_tag, common_header_smob);
	common_header = (struct common_header *) SCM_SMOB_DATA(common_header_smob);
	return scm_from_uint16(ntohs(common_header->destination_port));
}

SCM
get_verification_tag(SCM common_header_smob)
{
	struct common_header *common_header;

	scm_assert_smob_type(common_header_tag, common_header_smob);
	common_header = (struct common_header *) SCM_SMOB_DATA(common_header_smob);
	return scm_from_uint32(ntohl(common_header->verification_tag));
}

static SCM
mark_common_header(SCM common_header_smob)
{
	return SCM_BOOL_F;
}

static size_t
free_common_header(SCM common_header_smob)
{
	struct common_header *common_header = (struct common_header *)SCM_SMOB_DATA (common_header_smob);

	scm_gc_free(common_header, sizeof(struct common_header), "common_header");
	return 0;
}

static int
print_common_header(SCM common_header_smob, SCM port, scm_print_state *pstate)
{
	struct common_header *common_header = (struct common_header *) SCM_SMOB_DATA(common_header_smob);

	scm_puts("#<common_header: src=", port);
	scm_display(scm_from_uint16(ntohs(common_header->source_port)), port);
	scm_puts(", dst=", port);
	scm_display(scm_from_uint16(ntohs(common_header->destination_port)), port);
	scm_puts(", tag=", port);
	scm_display(scm_from_uint32(ntohl(common_header->verification_tag)), port);
	scm_puts(">", port);

	/* non-zero means success */
	return 1;
}

/* 
 *Two common headers are equalp iff their ports and the verification
 *tags are equal. The checksum is not taken into account
*/
static SCM
equalp_common_header(SCM common_header_1_smob, SCM common_header_2_smob)
{
	struct common_header *common_header_1 = (struct common_header *) SCM_SMOB_DATA(common_header_1_smob);
	struct common_header *common_header_2 = (struct common_header *) SCM_SMOB_DATA(common_header_2_smob);

	if (common_header_1->source_port != common_header_2->source_port) {
		return SCM_BOOL_F;
	}

	if (common_header_1->destination_port != common_header_2->destination_port) {
		return SCM_BOOL_F;
	}

	if (common_header_1->verification_tag != common_header_2->verification_tag) {
		return SCM_BOOL_F;
	}

	return SCM_BOOL_T;
}

void
init_common_header_type(void)
{
	common_header_tag = scm_make_smob_type("common_header", sizeof(struct common_header));

	scm_set_smob_mark(common_header_tag, mark_common_header);
	scm_set_smob_free(common_header_tag, free_common_header);
	scm_set_smob_print(common_header_tag, print_common_header);
	scm_set_smob_equalp(common_header_tag, equalp_common_header);

	scm_c_define_gsubr("make-common-header",   3, 0, 0, make_common_header);
	scm_c_define_gsubr("common-header?",       1, 0, 0, common_header_p);
	scm_c_define_gsubr("get-source-port",      1, 0, 0, get_source_port);
	scm_c_define_gsubr("get-destination-port", 1, 0, 0, get_destination_port);
	scm_c_define_gsubr("get-verification-tag", 1, 0, 0, get_verification_tag);
}
