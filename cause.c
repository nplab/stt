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
#include <arpa/inet.h>
#include <libguile.h>
#include "common.h"
#include "tlv.h"

scm_t_bits cause_tag;
extern scm_t_bits parameter_tag;

static SCM
make_cause (SCM s_code, SCM s_info)
{
	struct cause *cause;
	scm_t_uint16 code;
	size_t cause_length, total_length, i;

	code = scm_to_uint16(s_code);
	/* FIXME */
	SCM_ASSERT(scm_is_simple_vector(s_info), s_info, SCM_ARG2, "make-cause");

	if (SCM_SIMPLE_VECTOR_LENGTH(s_info) > MAX_CAUSE_INFO_LENGTH) {
		/* FIXME */
		scm_out_of_range("make-cause", s_info);
	}
	cause_length = CAUSE_HEADER_LENGTH + SCM_SIMPLE_VECTOR_LENGTH(s_info);
	total_length = ADD_PADDING(cause_length);
	cause = (struct cause *)scm_gc_malloc(total_length, "cause");
	memset((void *) cause, 0, total_length);

	cause->code   = htons((scm_t_uint16)code);
	cause->length = htons((scm_t_uint16)cause_length);
	for(i = 0; i < SCM_SIMPLE_VECTOR_LENGTH(s_info); i++) {
		cause->info[i] = scm_to_uint8(SCM_SIMPLE_VECTOR_REF(s_info, i));
	}
	SCM_RETURN_NEWSMOB(cause_tag, cause);
}

	
static SCM
make_cause_with_parameter(scm_t_uint16 code, SCM parameter_smob)
{
	struct cause *cause;
	struct parameter* parameter;
	scm_t_uint16 par_length, cause_length, total_length, length;
	
	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct parameter *)SCM_SMOB_DATA(parameter_smob);
	par_length = ntohs(parameter->length);
	if (par_length > MAX_CAUSE_INFO_LENGTH) 
		scm_out_of_range("make-cause-with-parameter", parameter_smob);

	cause_length = CAUSE_HEADER_LENGTH + par_length;
	total_length = ADD_PADDING(cause_length);
	cause = (struct cause *)scm_gc_malloc(total_length, "cause");
	memset((void *) cause, 0, total_length);

	cause->code   = htons((uint16_t)code);
	cause->length = htons((uint16_t)cause_length);
	length= ADD_PADDING(par_length);
	memcpy((void *)(cause->info), (const void *)parameter, length);
	SCM_RETURN_NEWSMOB(cause_tag, cause);
}

static SCM
make_request_to_delete_last_remaining_address_cause(SCM parameter_smob)
{
	scm_assert_smob_type(parameter_tag, parameter_smob);
	return make_cause_with_parameter(DELETE_LAST_IP_ADDRESS, parameter_smob);
}

static SCM
make_request_to_delete_source_address_cause(SCM parameter_smob)
{
	scm_assert_smob_type(parameter_tag, parameter_smob);
	return make_cause_with_parameter(DELETE_SOURCE_IP_ADDRESS, parameter_smob);
}

static SCM
make_operation_refused_due_to_resource_shortage_cause(SCM parameter_smob)
{
	scm_assert_smob_type(parameter_tag, parameter_smob);
	return make_cause_with_parameter(RESOURCE_SHORTAGE, parameter_smob);
}

static SCM
make_request_refused_no_authorization_cause(SCM parameter_smob)
{
	scm_assert_smob_type(parameter_tag, parameter_smob);
	return make_cause_with_parameter(NO_AUTHORIZATION, parameter_smob);
}

static SCM
get_parameter_from_cause(SCM cause_smob)
{
	SCM v;
	struct cause *cause;
	
	scm_assert_smob_type(cause_tag, cause_smob);
	cause = (struct cause *)SCM_SMOB_DATA(cause_smob);
	v = get_tlv_list((unsigned char*)(cause->info), ntohs(cause->length) - CAUSE_HEADER_LENGTH, "cause", parameter_tag);
	return SCM_SIMPLE_VECTOR_REF(v, 0);
}

static SCM
cause_p(SCM smob)
{
	if (SCM_SMOB_PREDICATE(cause_tag, smob)) {
		return SCM_BOOL_T;
	} else {
		return SCM_BOOL_F;
	}
}

static SCM
get_cause_code(SCM cause_smob)
{
	struct cause *cause;

	scm_assert_smob_type(cause_tag, cause_smob);
	cause = (struct cause *)SCM_SMOB_DATA(cause_smob);
	return scm_from_uint16(ntohs(cause->code));
}

static SCM
get_cause_length(SCM cause_smob)
{
	struct cause *cause;
	scm_assert_smob_type(cause_tag, cause_smob);
	cause = (struct cause *)SCM_SMOB_DATA(cause_smob);
	return scm_from_uint16(ntohs(cause->length));
}

static SCM
get_cause_info (SCM cause_smob)
{
	struct cause *cause;
	SCM s_value;
	size_t i, cause_length;

	scm_assert_smob_type(cause_tag, cause_smob);
	cause = (struct cause *)SCM_SMOB_DATA(cause_smob);
	if (ntohs(cause->length) < CAUSE_HEADER_LENGTH) {
		cause_length = 0;
	} else {
		cause_length = (size_t)(ntohs(cause->length) - CAUSE_HEADER_LENGTH);
	}
	s_value = scm_c_make_vector(cause_length, SCM_UNSPECIFIED);
	for(i = 0; i < cause_length; i++) {
		SCM_SIMPLE_VECTOR_SET(s_value, i, scm_from_uint8(cause->info[i]));
	}

	return s_value;
}

static SCM
mark_cause(SCM cause_smob)
{
	return SCM_BOOL_F;
}

static size_t
free_cause(SCM cause_smob)
{
	struct cause *cause = (struct cause *)SCM_SMOB_DATA(cause_smob);
	size_t total_length;

	total_length = ADD_PADDING(ntohs(cause->length));
	scm_gc_free(cause, total_length, "cause");
	return 0;
}

static int
print_cause(SCM cause_smob, SCM port, scm_print_state *pstate)
{
	struct cause *cause = (struct cause *)SCM_SMOB_DATA(cause_smob);

	scm_puts("#<cause: ", port);
	scm_puts("code=", port);
	scm_display(scm_from_uint16(ntohs(cause->code)), port);
	scm_puts(", length=", port);
	scm_display(scm_from_uint16(ntohs(cause->length)), port);
	scm_puts (">", port);
	return 1;
}

static SCM
equalp_cause(SCM cause_1_smob, SCM cause_2_smob)
{
	scm_t_uint16 length;
	struct cause *cause_1 = (struct cause *)SCM_SMOB_DATA(cause_1_smob);
	struct cause *cause_2 = (struct cause *)SCM_SMOB_DATA(cause_2_smob);

	if (cause_1->code != cause_2->code) {
		return SCM_BOOL_F;
	}

	if (cause_1->length != cause_2->length) {
		return SCM_BOOL_F;
	}
 
	length = ntohs(cause_1->length);

	if (length <= CAUSE_HEADER_LENGTH) {
		return SCM_BOOL_T;
	}
	
	if (memcmp((const void *) cause_1->info,
	           (const void *) cause_2->info,
	           length - CAUSE_HEADER_LENGTH))
		return SCM_BOOL_F;
	else
		return SCM_BOOL_T;
}

void
init_causes(void)
{
	cause_tag = scm_make_smob_type("cause", 0);

	scm_set_smob_mark(cause_tag, mark_cause);
	scm_set_smob_free(cause_tag, free_cause);
	scm_set_smob_print(cause_tag, print_cause);
	scm_set_smob_equalp(cause_tag, equalp_cause);

	scm_c_define_gsubr("make-cause",       2, 0, 0, make_cause);
	scm_c_define_gsubr("cause?",           1, 0, 0, cause_p);
	scm_c_define_gsubr("get-cause-code",   1, 0, 0, get_cause_code);
	scm_c_define_gsubr("get-cause-length", 1, 0, 0, get_cause_length);
	scm_c_define_gsubr("get-cause-info",   1, 0, 0, get_cause_info);
	scm_c_define_gsubr("make-request-to-delete-last-remaining-address-cause", 1, 0, 0, make_request_to_delete_last_remaining_address_cause);
	scm_c_define_gsubr("make-request-to-delete-source-address-cause", 1, 0, 0, make_request_to_delete_source_address_cause);
	scm_c_define_gsubr("make-operation-refused-due-to-resource-shortage-cause", 1, 0, 0, make_operation_refused_due_to_resource_shortage_cause);
	scm_c_define_gsubr("make-request-refused-no-authorization-cause", 1, 0, 0, make_request_refused_no_authorization_cause);
	scm_c_define_gsubr("get-parameter-from-cause", 1, 0, 0, get_parameter_from_cause);
}
