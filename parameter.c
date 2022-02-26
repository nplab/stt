/*
 *
 * SCTP test tool stt.
 *
 * Copyright (C) 2002-2008 by Michael Tuexen
 *
 * Realized in co-operation between Siemens AG and the University of
 * Applied Sciences, Muenster.
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
 * Contact: discussion@sctp.de
 *          tuexen@fh-muenster.de
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <libguile.h>
#include "common.h"
#include "tlv.h"

#define IPV4_ADDRESS_PARAMETER_LENGTH          8
#define IPV6_ADDRESS_PARAMETER_LENGTH          20
#define ECN_CAPABLE_PARAMETER_LENGTH           4
#define COOKIE_PRESERVATIVE_PARAMETER_LENGTH   8
#define ECN_CAPABLE_PARAMETER_LENGTH           4
#define FORWARD_TSN_SUPPORTED_PARAMETER_LENGTH 4
#define CORRELATION_ID_LENGTH                  4
#define CODE_POINT_LENGTH                      4

extern scm_t_bits address_tag;
extern scm_t_bits cause_tag;

scm_t_bits parameter_tag;

struct ipv4_address_parameter {
	scm_t_uint16 type;
	scm_t_uint16 length;
	struct in_addr address;
}__attribute__((packed));

struct ipv6_address_parameter {
	scm_t_uint16 type;
	scm_t_uint16 length;
	struct in6_addr address;
}__attribute__((packed));

struct cookie_preservative_parameter {
	scm_t_uint16 type;
	scm_t_uint16 length;
	scm_t_uint32 life;
}__attribute__((packed));

struct supported_address_type_parameter {
	scm_t_uint16 type;
	scm_t_uint16 length;
	scm_t_uint16 address_type[0];
}__attribute__((packed));

struct modify_ip_address_parameter {
	scm_t_uint16 type;
	scm_t_uint16 length;
	scm_t_uint32 correlation_id;
	scm_t_uint8 address[0];
}__attribute__((packed));

struct adaption_layer_indication_parameter {
	scm_t_uint16 type;
	scm_t_uint16 length;
	scm_t_uint16 code_point;
}__attribute__((packed));

struct success_indication_parameter {
	scm_t_uint16 type;
	scm_t_uint16 length;
	scm_t_uint32 correlation_id;
}__attribute__((packed));

struct error_cause_indication_parameter {
	scm_t_uint16 type;
	scm_t_uint16 length;
	scm_t_uint32 correlation_id;
	scm_t_uint8 error_causes[0];
}__attribute__((packed));

struct supported_extensions_parameter {
	scm_t_uint16 type;
	scm_t_uint16 length;
	scm_t_uint8 chunk_type[0];
}__attribute__((packed));

static SCM
make_tlv_parameter(scm_t_uint16 parameter_type, const char *proc_name, SCM s_value)
{
	struct parameter *parameter;
	size_t parameter_length, total_length, i;
 
	if (SCM_SIMPLE_VECTOR_LENGTH(s_value) > MAX_PARAMETER_VALUE_LENGTH) {
		/* FIXME */
		scm_out_of_range(proc_name, s_value);
	}
	parameter_length = PARAMETER_HEADER_LENGTH + SCM_SIMPLE_VECTOR_LENGTH(s_value);
	total_length = ADD_PADDING(parameter_length);
	parameter = (struct parameter *)scm_gc_malloc(total_length, "parameter");
	memset((void *) parameter, 0, total_length);
	parameter->type = htons(parameter_type);
	parameter->length = htons(parameter_length);  
	for (i = 0; i < SCM_SIMPLE_VECTOR_LENGTH(s_value); i++) {
		parameter->value[i] = scm_to_uint8(SCM_SIMPLE_VECTOR_REF(s_value, i));
	}
	SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
make_heartbeat_parameter(SCM s_info)
{
	SCM_ASSERT(scm_is_simple_vector(s_info), s_info, SCM_ARG1, "make-heartbeat-parameter");
	return make_tlv_parameter(HEARTBEAT_PARAMETER_TYPE, "make-heartbeat-parameter", s_info);
}

static SCM
get_heartbeat_info(SCM parameter_smob)
{
	struct parameter *parameter;
	SCM s_info;
	size_t i, length;

	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct parameter *)SCM_SMOB_DATA(parameter_smob);
	if (ntohs(parameter->type) != HEARTBEAT_PARAMETER_TYPE) {
		/* FIXME */
		scm_syserror_msg("get-heartbeat-info", "incorrect parameter type", parameter_smob, 0);
	}
	if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH) {
		/* FIXME */
		scm_syserror_msg("get-heartbeat-info", "incorrect parameter length", parameter_smob, 0);
	}
	length = ntohs(parameter->length) - PARAMETER_HEADER_LENGTH;
	s_info = scm_c_make_vector(length, SCM_UNSPECIFIED);
	for (i = 0; i < length; i++){
		SCM_SIMPLE_VECTOR_SET(s_info, i, scm_from_uint8(parameter->value[i]));
	}
	return s_info;
}

static SCM
make_ipv4_address_parameter(SCM address_smob)
{
	struct ipv4_address_parameter *parameter;
	struct sockaddr_in *addr;

	scm_assert_smob_type(address_tag, address_smob);
	addr = (struct sockaddr_in *) SCM_SMOB_DATA (address_smob);
	if (addr->sin_family != AF_INET) {
		/* FIXME */
		scm_syserror_msg ("make-ipv4-address-parameter", "incorrect address type", address_smob, 0);
	}
	parameter = (struct ipv4_address_parameter *)scm_gc_malloc(IPV4_ADDRESS_PARAMETER_LENGTH, "parameter");
	memset((void *) parameter, 0, IPV4_ADDRESS_PARAMETER_LENGTH);
	parameter->type = htons(IPV4_ADDRESS_PARAMETER_TYPE);
	parameter->length = htons(IPV4_ADDRESS_PARAMETER_LENGTH);
	memcpy((void *)&(parameter->address), (const void *)&(addr->sin_addr), sizeof(struct in_addr));
	SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_ipv4_address(SCM parameter_smob)
{
	struct ipv4_address_parameter *parameter;
	struct sockaddr_in *address;

	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct ipv4_address_parameter *) SCM_SMOB_DATA (parameter_smob);
	if (ntohs(parameter->type) != IPV4_ADDRESS_PARAMETER_TYPE) {
		/* FIXME */
		scm_syserror_msg("get-ipv4-address", "incorrect parameter type", parameter_smob, 0);
	}
	if (ntohs(parameter->length) != IPV4_ADDRESS_PARAMETER_LENGTH) {
		/* FIXME */
		scm_syserror_msg("get-ipv4-address", "incorrect parameter length", parameter_smob, 0);
	}
	address = (struct sockaddr_in *)scm_gc_malloc(sizeof(struct sockaddr_in), "address");
	memset((void *) address, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
	address->sin_len = sizeof(struct sockaddr_in);
#endif
	address->sin_family = AF_INET;
	address->sin_port = 0;
	memcpy((void *)&(address->sin_addr), (const void *)&(parameter->address), sizeof(struct sockaddr_in));
	SCM_RETURN_NEWSMOB(address_tag, address);
}

static SCM
make_ipv6_address_parameter(SCM address_smob)
{
	struct ipv6_address_parameter *parameter;
	struct sockaddr_in6 *addr;

	scm_assert_smob_type(address_tag, address_smob);
	addr = (struct sockaddr_in6 *) SCM_SMOB_DATA(address_smob);
	if (addr->sin6_family != AF_INET6) {
		/* FIXME */
		scm_syserror_msg ("make_ipv6_address_parameter", "incorrect address type", address_smob, 0);
	}

	parameter = (struct ipv6_address_parameter *)scm_gc_malloc(IPV6_ADDRESS_PARAMETER_LENGTH, "parameter");
	memset((void *) parameter, 0, IPV6_ADDRESS_PARAMETER_LENGTH);
	parameter->type = htons(IPV6_ADDRESS_PARAMETER_TYPE);
	parameter->length = htons(IPV6_ADDRESS_PARAMETER_LENGTH);
	memcpy((void *)(&parameter->address), (const void *)&(addr->sin6_addr), sizeof(struct in6_addr));
	SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_ipv6_address(SCM parameter_smob)
{
	struct ipv6_address_parameter *parameter;
	struct sockaddr_in6 *address;

	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct ipv6_address_parameter *)SCM_SMOB_DATA(parameter_smob);
	if (ntohs(parameter->type) != IPV6_ADDRESS_PARAMETER_TYPE) {
		/* FIXME */
		scm_syserror_msg ("get-ipv6-address", "incorrect parameter type", parameter_smob, 0);
	}
	if (ntohs(parameter->length) != IPV6_ADDRESS_PARAMETER_LENGTH) {
		/* FIXME */
		scm_syserror_msg ("get-ipv6-address", "incorrect parameter length", parameter_smob, 0);
	}
	address = (struct sockaddr_in6 *)scm_gc_malloc(sizeof(struct sockaddr_in6), "address");
	memset((void *) address, 0, sizeof(struct sockaddr_in6));
#ifdef HAVE_SIN6_LEN
	address->sin6_len = sizeof(struct sockaddr_in6);
#endif
	address->sin6_family = AF_INET6;
	address->sin6_port = 0;
	address->sin6_flowinfo = 0;
	memcpy((void *)&(address->sin6_addr), (const void *)&(parameter->address), sizeof(struct sockaddr_in6));
	SCM_RETURN_NEWSMOB(address_tag, address);
}

static SCM
make_cookie_parameter(SCM s_info)
{
	SCM_ASSERT(scm_is_simple_vector(s_info), s_info, SCM_ARG1, "make-cookie-parameter");
	return make_tlv_parameter(COOKIE_PARAMETER_TYPE, "make-cookie-parameter", s_info);
}

static SCM
get_cookie_parameter_cookie(SCM parameter_smob)
{
	struct parameter *parameter;
	SCM s_cookie;
	size_t i, length;

	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct parameter *) SCM_SMOB_DATA (parameter_smob);
	if (ntohs(parameter->type) != COOKIE_PARAMETER_TYPE) {
		/* FIXME */
		scm_syserror_msg ("get-cookie-parameter-cookie", "incorrect parameter type", parameter_smob, 0);
	}
	if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH) {
		/* FIXME */
		scm_syserror_msg ("get-cookie-parameter-cookie", "incorrect parameter length", parameter_smob, 0);
	}
	length    = ntohs(parameter->length) - PARAMETER_HEADER_LENGTH;
	s_cookie  = scm_c_make_vector(length, SCM_UNSPECIFIED);
	for (i = 0; i < length; i++) {
		SCM_SIMPLE_VECTOR_SET(s_cookie, i, scm_from_uint8(parameter->value[i]));
	}
	return s_cookie;
}

static SCM
make_unrecognized_parameter_parameter(SCM s_unrecognized_parameter)
{
	struct parameter *parameter, *unrecognized_parameter;
	scm_t_uint16 length, parameter_length, total_length;

	scm_assert_smob_type(parameter_tag, s_unrecognized_parameter);
	unrecognized_parameter = (struct parameter *)SCM_SMOB_DATA(s_unrecognized_parameter);
	length = ntohs(unrecognized_parameter->length);

	if (length > MAX_PARAMETER_VALUE_LENGTH) {
		scm_out_of_range("make-unrecognized-parameter-parameter", s_unrecognized_parameter);
	}

	parameter_length = length + PARAMETER_HEADER_LENGTH;
	total_length = ADD_PADDING(parameter_length);
	parameter = (struct parameter *)scm_gc_malloc(total_length, "parameter");
	memset((void *) parameter, 0, total_length);
	parameter->type = htons(UNRECOGNIZED_PARAMETER_PARAMETER_TYPE);
	parameter->length = htons(parameter_length);
	memcpy((void *)parameter->value, (const void *) unrecognized_parameter, length);
	SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_unrecognized_parameter(SCM parameter_smob)
{
	struct parameter *parameter, *unrecognized_parameter;
	scm_t_uint16 length, total_length;

	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct parameter *)SCM_SMOB_DATA(parameter_smob);
	if (ntohs(parameter->type) != UNRECOGNIZED_PARAMETER_PARAMETER_TYPE) {
		scm_syserror_msg ("get-unrecognized-parameter", "incorrect parameter type", parameter_smob, 0);
	}
	if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH) {
		scm_syserror_msg ("get-unrecognized-parameter", "incorrect parameter length", parameter_smob, 0);
	}
	length = ntohs(parameter->length) - PARAMETER_HEADER_LENGTH;
	total_length = ADD_PADDING(length); 
	unrecognized_parameter = (struct parameter *)scm_gc_malloc(total_length, "parameter");
	memset((void *) unrecognized_parameter, 0, total_length);
	memcpy((void *)unrecognized_parameter, (const void *)parameter->value, length);
	SCM_RETURN_NEWSMOB (parameter_tag, unrecognized_parameter);
}

static SCM
make_cookie_preservative_parameter(SCM s_life)
{
	struct cookie_preservative_parameter *parameter;
	scm_t_uint32 life;

	life = scm_to_uint32(s_life);
	parameter = (struct cookie_preservative_parameter *)scm_gc_malloc(COOKIE_PRESERVATIVE_PARAMETER_LENGTH, "parameter");
	memset((void *)parameter, 0, COOKIE_PRESERVATIVE_PARAMETER_LENGTH);

	parameter->type = htons(COOKIE_PRESERVATIVE_PARAMETER_TYPE);
	parameter->length = htons(COOKIE_PRESERVATIVE_PARAMETER_LENGTH);
	parameter->life = htonl(life);
	SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_life_time(SCM parameter_smob)
{
	struct cookie_preservative_parameter *parameter;

	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct cookie_preservative_parameter *)SCM_SMOB_DATA(parameter_smob);
	if (ntohs(parameter->type) != COOKIE_PRESERVATIVE_PARAMETER_TYPE) {
		scm_syserror_msg ("get-life-time", "incorrect parameter type", parameter_smob, 0);
	}
	if (ntohs(parameter->length) != COOKIE_PRESERVATIVE_PARAMETER_LENGTH) {
		scm_syserror_msg ("get-life-time", "incorrect parameter length", parameter_smob, 0);
	}
	parameter = (struct cookie_preservative_parameter *)SCM_SMOB_DATA(parameter_smob);
	return scm_from_uint32(ntohl(parameter->life));
}

static SCM
make_hostname_parameter(SCM s_name)
{
	struct parameter *parameter;
	scm_t_uint16 parameter_length, total_length;
	size_t i;
	
	SCM_ASSERT(scm_is_string(s_name), s_name, SCM_ARG1, "make-hostname-parameter");

	if (scm_c_string_length(s_name) > MAX_PARAMETER_VALUE_LENGTH) {
		scm_out_of_range("make_hostname_parameter", s_name);
	}
	parameter_length = PARAMETER_HEADER_LENGTH + scm_c_string_length(s_name);
	total_length = ADD_PADDING(parameter_length);
	parameter = (struct parameter *)scm_gc_malloc(total_length, "parameter");
	memset((void *)parameter, 0, total_length);

	parameter->type = htons(HOSTNAME_PARAMETER_TYPE);
	parameter->length = htons(parameter_length);
	for (i = 0; i < scm_c_string_length(s_name); i++) {
		parameter->value[i] = scm_to_uint8(scm_char_to_integer(scm_c_string_ref(s_name, i)));
	}
	SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_hostname(SCM parameter_smob)
{
	struct parameter *parameter;

	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct parameter *) SCM_SMOB_DATA (parameter_smob);
	if (ntohs(parameter->type) != HOSTNAME_PARAMETER_TYPE) {
		scm_syserror_msg ("get-hostname", "incorrect parameter type", parameter_smob, 0);
	}
	if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH) {
		scm_syserror_msg ("get-hostname", "incorrect parameter length", parameter_smob, 0);
	}
	return scm_from_locale_stringn((char *)parameter->value, ntohs(parameter->length) - PARAMETER_HEADER_LENGTH);
}

static SCM
make_supported_address_type_parameter(SCM s_types)
{
	struct supported_address_type_parameter *parameter;
	scm_t_uint16 parameter_value_length, parameter_length, total_length;
	size_t i;
	
	SCM_ASSERT (scm_is_simple_vector(s_types), s_types, SCM_ARG1, "make-supported-address-type-parameter");
	if (SCM_SIMPLE_VECTOR_LENGTH(s_types) > (MAX_PARAMETER_VALUE_LENGTH / 2)) {
		scm_out_of_range("make-supported-address-type-parameter", s_types);
	}
	parameter_value_length = 2 * SCM_SIMPLE_VECTOR_LENGTH(s_types);
	parameter_length = PARAMETER_HEADER_LENGTH + parameter_value_length;
	total_length = ADD_PADDING(parameter_length);
	parameter = (struct supported_address_type_parameter *)scm_gc_malloc(total_length, "parameter");
	memset((void *) parameter, 0, total_length);
	parameter->type = htons(SUPPORTED_ADDRESS_TYPE_PARAMETER_TYPE);
	parameter->length = htons(parameter_length);  
	for (i = 0; i < SCM_SIMPLE_VECTOR_LENGTH(s_types); i++) {
		parameter->address_type[i] = htons(scm_to_uint16(SCM_SIMPLE_VECTOR_REF(s_types, i)));
	}
	SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_supported_address_types(SCM parameter_smob)
{
	struct supported_address_type_parameter *parameter;
	SCM s_types;
	size_t number_of_types, type_number;

	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct supported_address_type_parameter *)SCM_SMOB_DATA(parameter_smob);
	if (ntohs(parameter->type) != SUPPORTED_ADDRESS_TYPE_PARAMETER_TYPE) {
		scm_syserror_msg ("get-supported-address-types", "incorrect parameter type", parameter_smob, 0);
	}
	if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH) {
		scm_syserror_msg ("get-supported-address-types", "incorrect parameter length", parameter_smob, 0);
	}
	number_of_types = (ntohs(parameter->length) - PARAMETER_HEADER_LENGTH) / 2;

	s_types = scm_c_make_vector(number_of_types, SCM_UNSPECIFIED);
	for (type_number = 0; type_number < number_of_types; type_number++) {
		SCM_SIMPLE_VECTOR_SET(s_types, type_number, scm_from_uint16(ntohs(parameter->address_type[type_number])));
	}
	return s_types;
}

static SCM
make_supported_extensions_parameter(SCM s_types)
{
	struct supported_extensions_parameter *parameter;
	scm_t_uint16 parameter_value_length, parameter_length, total_length;
	size_t i;
	
	SCM_ASSERT (scm_is_simple_vector(s_types), s_types, SCM_ARG1, "make-supported-extensions-parameter");
	if (SCM_SIMPLE_VECTOR_LENGTH(s_types) > MAX_PARAMETER_VALUE_LENGTH ) {
		scm_out_of_range("make-supported-extensions-parameter", s_types);
	}
	parameter_value_length = SCM_SIMPLE_VECTOR_LENGTH(s_types);
	parameter_length = PARAMETER_HEADER_LENGTH + parameter_value_length;
	total_length = ADD_PADDING(parameter_length);
	parameter = (struct supported_extensions_parameter *)scm_gc_malloc(total_length, "parameter");
	memset((void *) parameter, 0, total_length);
	parameter->type = htons(SUPPORTED_EXTENSIONS_PARAMETER_TYPE);
	parameter->length = htons(parameter_length);  
	for (i = 0; i < SCM_SIMPLE_VECTOR_LENGTH(s_types); i++) {
		parameter->chunk_type[i] = scm_to_uint8(SCM_SIMPLE_VECTOR_REF(s_types, i));
	}
	SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_supported_extensions(SCM parameter_smob)
{
	struct supported_extensions_parameter *parameter;
	SCM s_types;
	size_t number_of_chunks, chunk_number;

	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct supported_extensions_parameter *)SCM_SMOB_DATA(parameter_smob);
	if (ntohs(parameter->type) != SUPPORTED_EXTENSIONS_PARAMETER_TYPE) {
		scm_syserror_msg ("get-supported-extensions", "incorrect parameter type", parameter_smob, 0);
	}
	if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH) {
		scm_syserror_msg ("get-supported-extensions", "incorrect parameter length", parameter_smob, 0);
	}
	number_of_chunks = ntohs(parameter->length) - PARAMETER_HEADER_LENGTH;

	s_types = scm_c_make_vector(number_of_chunks, SCM_UNSPECIFIED);
	for (chunk_number = 0; chunk_number < number_of_chunks; chunk_number++) {
		SCM_SIMPLE_VECTOR_SET(s_types, chunk_number, scm_from_uint8(parameter->chunk_type[chunk_number]));
	}
	return s_types;
}

static SCM
make_ecn_capable_parameter()
{
	struct parameter *parameter = (struct parameter *)scm_gc_malloc(ECN_CAPABLE_PARAMETER_LENGTH, "parameter");

	memset((void *) parameter, 0, ECN_CAPABLE_PARAMETER_LENGTH);
	parameter->type   = htons(ECN_CAPABLE_PARAMETER_TYPE);
	parameter->length = htons(ECN_CAPABLE_PARAMETER_LENGTH);

	SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
make_forward_tsn_supported_parameter()
{
	struct parameter *parameter = (struct parameter *)scm_gc_malloc(FORWARD_TSN_SUPPORTED_PARAMETER_LENGTH, "parameter");

	memset((void *)parameter, 0, FORWARD_TSN_SUPPORTED_PARAMETER_LENGTH);
	parameter->type = htons(FORWARD_TSN_SUPPORTED_PARAMETER_TYPE);
	parameter->length = htons(FORWARD_TSN_SUPPORTED_PARAMETER_LENGTH);

	SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
make_add_ip_address_parameter(SCM s_correlation_id, SCM s_address_parameter)
{
	struct parameter *address_parameter;
	struct modify_ip_address_parameter *parameter;
	scm_t_uint32 correlation_id;
	scm_t_uint16 address_parameter_length, parameter_length, total_length;

	correlation_id = scm_to_uint32(s_correlation_id);
	scm_assert_smob_type(parameter_tag, s_address_parameter);

	address_parameter = (struct parameter *) SCM_SMOB_DATA (s_address_parameter);
	address_parameter_length  = ntohs(address_parameter->length);
	parameter_length = PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH + address_parameter_length;
	total_length = ADD_PADDING(parameter_length);

	parameter = (struct modify_ip_address_parameter *)scm_gc_malloc(total_length, "parameter");
	memset((void *) parameter, 0, total_length);
	parameter->type = htons(ADD_IP_ADDRESS_PARAMETER_TYPE);
	parameter->length = htons(parameter_length);
	parameter->correlation_id = htonl(correlation_id);
	memcpy((void *)parameter->address, (const void *)address_parameter, address_parameter_length);

	SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
get_correlation_id(SCM parameter_smob)
{
	struct modify_ip_address_parameter *parameter;

	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct modify_ip_address_parameter *)SCM_SMOB_DATA(parameter_smob);
	if ((ntohs(parameter->type) != ADD_IP_ADDRESS_PARAMETER_TYPE) &&
	    (ntohs(parameter->type) != DELETE_IP_ADDRESS_PARAMETER_TYPE) &&
	    (ntohs(parameter->type) != SET_PRIMARY_ADDRESS_PARAMETER_TYPE) &&
	    (ntohs(parameter->type) != ERROR_CAUSE_INDICATION_PARAMETER_TYPE) &&
	    (ntohs(parameter->type) != SUCCESS_INDICATION_PARAMETER_TYPE)) {
		scm_syserror_msg ("get-correlation-id", "incorrect parameter type", parameter_smob, 0);
	}
	if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH) {
		scm_syserror_msg ("get-correlation-id", "incorrect parameter length", parameter_smob, 0);
	}

	return scm_from_uint32(ntohl(parameter->correlation_id));
}

static SCM
get_address_parameter(SCM parameter_smob)
{
	struct modify_ip_address_parameter *parameter;
	struct parameter *address_parameter;
	scm_t_uint16 address_parameter_length, address_parameter_total_length;

	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct modify_ip_address_parameter *) SCM_SMOB_DATA (parameter_smob);
	if ((ntohs(parameter->type) != ADD_IP_ADDRESS_PARAMETER_TYPE) &&
	    (ntohs(parameter->type) != DELETE_IP_ADDRESS_PARAMETER_TYPE) &&
	    (ntohs(parameter->type) != SET_PRIMARY_ADDRESS_PARAMETER_TYPE)) {
		scm_syserror_msg ("get-address-parameter", "incorrect parameter type", parameter_smob, 0);
	}
	if (ntohs(parameter->length) < 2 * PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH) {
		scm_syserror_msg ("get-address-parameter", "incorrect parameter length", parameter_smob, 0);
	}
	address_parameter = (struct parameter *)parameter->address;
	address_parameter_length = ntohs(address_parameter->length);
	if (address_parameter_length > ntohs(parameter->length) - PARAMETER_HEADER_LENGTH - CORRELATION_ID_LENGTH) {
		scm_syserror_msg ("get-address-parameter", "incorrect address parameter", parameter_smob, 0);
	}
	address_parameter_total_length = ADD_PADDING(address_parameter_length);
	address_parameter = (struct parameter *)scm_gc_malloc(address_parameter_total_length, "parameter");
	memset((void *) address_parameter, 0, address_parameter_total_length);
	memcpy((void *) address_parameter, (const void *) parameter->address, address_parameter_length);
	SCM_RETURN_NEWSMOB (parameter_tag, address_parameter);
}

static SCM
make_delete_ip_address_parameter(SCM s_correlation_id, SCM s_address_parameter)
{
	struct parameter *address_parameter;
	struct modify_ip_address_parameter *parameter;
	scm_t_uint32 correlation_id;
	scm_t_uint16 address_parameter_length, parameter_length, total_length;

	correlation_id = scm_to_uint32(s_correlation_id);
	scm_assert_smob_type(parameter_tag, s_address_parameter);

	address_parameter = (struct parameter *)SCM_SMOB_DATA(s_address_parameter);
	address_parameter_length = ntohs(address_parameter->length);
	parameter_length = PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH + address_parameter_length;
	total_length = ADD_PADDING(parameter_length);

	parameter = (struct modify_ip_address_parameter *)scm_gc_malloc(total_length, "parameter");
	memset((void *) parameter, 0, total_length);
	parameter->type = htons(DELETE_IP_ADDRESS_PARAMETER_TYPE);
	parameter->length = htons(parameter_length);
	parameter->correlation_id = htonl(correlation_id);
	memcpy((void *)parameter->address, (const void *)address_parameter, address_parameter_length);

	SCM_RETURN_NEWSMOB(parameter_tag, parameter);
}

static SCM
make_set_primary_address_parameter(SCM s_correlation_id, SCM s_address_parameter)
{
	struct parameter *address_parameter;
	struct modify_ip_address_parameter *parameter;
	scm_t_uint32 correlation_id;
	scm_t_uint16 address_parameter_length, parameter_length, total_length;

	correlation_id = scm_to_uint32(s_correlation_id);
	scm_assert_smob_type(parameter_tag, s_address_parameter);

	address_parameter = (struct parameter *)SCM_SMOB_DATA(s_address_parameter);
	address_parameter_length = ntohs(address_parameter->length);
	parameter_length = PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH + address_parameter_length;
	total_length = ADD_PADDING(parameter_length);

	parameter = (struct modify_ip_address_parameter *)scm_gc_malloc(total_length, "parameter");
	memset((void *) parameter, 0, total_length);
	parameter->type = htons(SET_PRIMARY_ADDRESS_PARAMETER_TYPE);
	parameter->length = htons(parameter_length);
	parameter->correlation_id = htonl(correlation_id);
	memcpy((void *)parameter->address, (const void *)address_parameter, address_parameter_length);

	SCM_RETURN_NEWSMOB(parameter_tag, parameter);
}

static SCM
make_adaption_layer_indication_parameter(SCM s_code_point)
{
	struct adaption_layer_indication_parameter *parameter;
	scm_t_uint32 code_point;
	scm_t_uint16 parameter_length, total_length;

	code_point = scm_to_uint32(s_code_point);
	parameter_length = PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH + CODE_POINT_LENGTH;
	total_length = ADD_PADDING(parameter_length);
	parameter = (struct adaption_layer_indication_parameter *)scm_gc_malloc(total_length, "parameter");
	memset((void *)parameter, 0, total_length);
	parameter->type = htons(ADAPTION_LAYER_INDICATION_PARAMETER_TYPE);
	parameter->length = htons(parameter_length);
	parameter->code_point = htonl(code_point);

	SCM_RETURN_NEWSMOB(parameter_tag, parameter);
}

static SCM
get_code_point(SCM parameter_smob)
{
	struct adaption_layer_indication_parameter *parameter;

	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct adaption_layer_indication_parameter *)SCM_SMOB_DATA(parameter_smob);
	if ((ntohs(parameter->type) != ADAPTION_LAYER_INDICATION_PARAMETER_TYPE)) {
		scm_syserror_msg ("get-code-point", "incorrect parameter type", parameter_smob, 0);
	}
	if (ntohs(parameter->length) != PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH) {
		scm_syserror_msg ("get-code-point", "incorrect parameter length", parameter_smob, 0);
	}
	parameter = (struct adaption_layer_indication_parameter *)SCM_SMOB_DATA(parameter_smob);
	return scm_from_uint32(ntohl(parameter->code_point));
}


static SCM
make_success_indication_parameter(SCM s_correlation_id)
{
	struct success_indication_parameter *parameter;
	scm_t_uint32 correlation_id;
	scm_t_uint16 parameter_length, total_length;

	correlation_id = scm_to_uint32(s_correlation_id);
	parameter_length = PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH;
	total_length = ADD_PADDING(parameter_length);
	parameter = (struct success_indication_parameter *)scm_gc_malloc(total_length, "parameter");
	memset((void *)parameter, 0, total_length);
	parameter->type = htons(SUCCESS_INDICATION_PARAMETER_TYPE);
	parameter->length = htons(parameter_length);
	parameter->correlation_id = htonl(correlation_id);

	SCM_RETURN_NEWSMOB (parameter_tag, parameter);
}

static SCM
make_error_cause_indication_parameter(SCM s_correlation_id, SCM s_causes)
{
	struct error_cause_indication_parameter *parameter;
	scm_t_uint32 correlation_id;
	scm_t_uint16 parameter_length, total_length, error_causes_length;

	correlation_id = scm_to_uint32(s_correlation_id);
	if (!SCM_UNBNDP(s_causes)) {
		SCM_ASSERT(scm_is_simple_vector(s_causes) , s_causes, SCM_ARG2, "make-error-cause-indication-parameter");
		error_causes_length = scan_tlv_list(s_causes, cause_tag, MAX_CAUSE_LENGTH - CORRELATION_ID_LENGTH);
		if (error_causes_length > MAX_CAUSE_LENGTH) {
			scm_syserror_msg ("make-error-cause-indication-chunk", "error causes too long", s_causes, 0);
		}
	} else {
		error_causes_length = 0;
	}

	parameter_length = PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH + error_causes_length;
	total_length = ADD_PADDING(parameter_length);
	parameter = (struct error_cause_indication_parameter *)scm_gc_malloc(total_length, "parameter");
	memset((void *)parameter, 0, total_length);
	parameter->type = htons(ERROR_CAUSE_INDICATION_PARAMETER_TYPE);
	parameter->length = htons(parameter_length);
	parameter->correlation_id = htonl(correlation_id);
	if (!SCM_UNBNDP(s_causes)) {
		put_tlv_list (parameter->error_causes, s_causes);
	}

	SCM_RETURN_NEWSMOB(parameter_tag, parameter);
}

static SCM
get_asconf_error_causes(SCM parameter_smob)
{
	struct error_cause_indication_parameter *parameter; 
	scm_t_uint16 error_causes_length;

	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct error_cause_indication_parameter *)SCM_SMOB_DATA(parameter_smob);
	if ((ntohs(parameter->type) != ERROR_CAUSE_INDICATION_PARAMETER_TYPE)) {
		/* FIXME */
		scm_syserror_msg("get-asconf-error-causes", "incorrect parameter type", parameter_smob, 0);
	}
	if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH + CORRELATION_ID_LENGTH) {
		/* FIXME */
		scm_syserror_msg("get-asconf-error-causes", "incorrect parameter length", parameter_smob, 0);
	}
	error_causes_length = ntohs(parameter->length) - PARAMETER_HEADER_LENGTH - CORRELATION_ID_LENGTH;
	return get_tlv_list(parameter->error_causes, error_causes_length, "cause", cause_tag);
}

static SCM
make_parameter(SCM s_type, SCM s_value)
{
	scm_t_uint16 type;

	type = scm_to_uint16(s_type);
	SCM_ASSERT(scm_is_simple_vector(s_value), s_value, SCM_ARG2, "make-parameter");

	return make_tlv_parameter(type, "make-parameter", s_value);
}

static SCM
get_parameter_type(SCM parameter_smob)
{
	struct parameter *parameter;
	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct parameter *)SCM_SMOB_DATA(parameter_smob);
	if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH) {
		/* FIXME */
		scm_syserror_msg("get-parameter-type", "incorrect parameter length", parameter_smob, 0);
	}
	return scm_from_uint16(ntohs(parameter->type));
}
  
static SCM
get_parameter_length(SCM parameter_smob)
{
	struct parameter *parameter;

	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct parameter *)SCM_SMOB_DATA(parameter_smob);
	if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH) {
		/* FIXME */
		scm_syserror_msg("get-parameter-length", "incorrect parameter length", parameter_smob, 0);
	}
	return scm_from_uint16(ntohs(parameter->length));
}

static SCM
get_parameter_value(SCM parameter_smob)
{
	struct parameter *parameter;
	SCM s_value;
	size_t i, parameter_length;

	scm_assert_smob_type(parameter_tag, parameter_smob);
	parameter = (struct parameter *)SCM_SMOB_DATA(parameter_smob);
	if (ntohs(parameter->length) < PARAMETER_HEADER_LENGTH) {
		parameter_length = 0;
	} else {
		parameter_length = (size_t)(ntohs(parameter->length) - PARAMETER_HEADER_LENGTH);
	}
	s_value = scm_c_make_vector(parameter_length, SCM_UNSPECIFIED);
	for (i = 0; i < parameter_length; i++) {
		SCM_SIMPLE_VECTOR_SET(s_value, i, scm_from_uint8(parameter->value[i]));
	}

	return s_value;
}

static SCM
parameter_p(SCM smob)
{
	if (SCM_SMOB_PREDICATE(parameter_tag, smob)) {
		return SCM_BOOL_T;
	} else {
		return SCM_BOOL_F;
	}
}

static SCM
mark_parameter(SCM parameter_smob)
{
	return SCM_BOOL_F;
}

static size_t
free_parameter(SCM parameter_smob)
{
	struct parameter *parameter = (struct parameter *)SCM_SMOB_DATA(parameter_smob);
	scm_t_uint16 total_length;

	total_length = ADD_PADDING(ntohs(parameter->length));
	scm_gc_free(parameter, total_length, "parameter");
	return 0;
}

static int
print_parameter(SCM parameter_smob, SCM port, scm_print_state *pstate)
{
	struct parameter *parameter = (struct parameter *)SCM_SMOB_DATA(parameter_smob);

	scm_puts("#<parameter: ", port);
	if (ntohs(parameter->length < PARAMETER_HEADER_LENGTH)) {
		scm_puts("bad formatted>", port);
	}else {
		scm_puts("type=", port);
		scm_display(scm_from_uint16(ntohs(parameter->type)), port);
		scm_puts(", length=", port);
		scm_display(scm_from_uint16(ntohs(parameter->length)), port);
		scm_puts (">", port);
	}
	return 1;
}

static SCM
equalp_parameter(SCM parameter_1_smob, SCM parameter_2_smob)
{
	scm_t_uint16 length;
	struct parameter *parameter_1 = (struct parameter *)SCM_SMOB_DATA(parameter_1_smob);
	struct parameter *parameter_2 = (struct parameter *)SCM_SMOB_DATA(parameter_2_smob);

	if (parameter_1->type != parameter_2->type) {
		return SCM_BOOL_F;
	}

	if (parameter_1->length != parameter_2->length) {
		return SCM_BOOL_F;
	}

	length = ntohs(parameter_1->length);

	if (memcmp((const void *) parameter_1->value,
	           (const void *) parameter_2->value, length - PARAMETER_HEADER_LENGTH)) {
		return SCM_BOOL_F;
	} else {
		return SCM_BOOL_T;
	}
}

void
init_parameters(void)
{
	parameter_tag = scm_make_smob_type("parameter", 0);

	scm_set_smob_mark(parameter_tag, mark_parameter);
	scm_set_smob_free(parameter_tag, free_parameter);
	scm_set_smob_print(parameter_tag, print_parameter);
	scm_set_smob_equalp(parameter_tag, equalp_parameter);

	scm_c_define_gsubr("make-parameter",                           2, 0, 0, make_parameter);
	scm_c_define_gsubr("parameter?",                               1, 0, 0, parameter_p);
	scm_c_define_gsubr("get-parameter-type",                       1, 0, 0, get_parameter_type);
	scm_c_define_gsubr("get-parameter-length",                     1, 0, 0, get_parameter_length);
	scm_c_define_gsubr("get-parameter-value",                      1, 0, 0, get_parameter_value);

	scm_c_define_gsubr("make-heartbeat-parameter",                 1, 0, 0, make_heartbeat_parameter);
	scm_c_define_gsubr("get-heartbeat-info",                       1, 0, 0, get_heartbeat_info);
	scm_c_define_gsubr("make-ipv4-address-parameter",              1, 0, 0, make_ipv4_address_parameter);
	scm_c_define_gsubr("get-ipv4-address",                         1, 0, 0, get_ipv4_address);
	scm_c_define_gsubr("make-ipv6-address-parameter",              1, 0, 0, make_ipv6_address_parameter);
	scm_c_define_gsubr("get-ipv6-address",                         1, 0, 0, get_ipv6_address);
	scm_c_define_gsubr("make-cookie-parameter",                    1, 0, 0, make_cookie_parameter);
	scm_c_define_gsubr("get-cookie-parameter-cookie",              1, 0, 0, get_cookie_parameter_cookie);
	scm_c_define_gsubr("make-unrecognized-parameter-parameter",    1, 0, 0, make_unrecognized_parameter_parameter);
	scm_c_define_gsubr("get-unrecognized-parameter",               1, 0, 0, get_unrecognized_parameter);
	scm_c_define_gsubr("make-cookie-preservative-parameter",       1, 0, 0, make_cookie_preservative_parameter);
	scm_c_define_gsubr("get-life-time",                            1, 0, 0, get_life_time);
	scm_c_define_gsubr("make-hostname-parameter",                  1, 0, 0, make_hostname_parameter);
	scm_c_define_gsubr("get-hostname",                             1, 0, 0, get_hostname);
	scm_c_define_gsubr("make-supported-address-type-parameter",    1, 0, 0, make_supported_address_type_parameter);
	scm_c_define_gsubr("get-supported-address-types",              1, 0, 0, get_supported_address_types);
	scm_c_define_gsubr("make-supported-extensions-parameter",      1, 0, 0, make_supported_extensions_parameter);
	scm_c_define_gsubr("get-supported-extensions",                 1, 0, 0, get_supported_extensions);
	scm_c_define_gsubr("make-ecn-capable-parameter",               0, 0, 0, make_ecn_capable_parameter);
	scm_c_define_gsubr("make-forward-tsn-supported-parameter",     0, 0, 0, make_forward_tsn_supported_parameter);
	scm_c_define_gsubr("make-add-ip-address-parameter",            2, 0, 0, make_add_ip_address_parameter);
	scm_c_define_gsubr("get-correlation-id",                       1, 0, 0, get_correlation_id);
	scm_c_define_gsubr("get-address-parameter",                    1, 0, 0, get_address_parameter);
	scm_c_define_gsubr("make-delete-ip-address-parameter",         2, 0, 0, make_delete_ip_address_parameter);
	scm_c_define_gsubr("make-set-primary-address-parameter",       2, 0, 0, make_set_primary_address_parameter);
	scm_c_define_gsubr("make-adaption-layer-indication-parameter", 1, 0, 0, make_adaption_layer_indication_parameter);
	scm_c_define_gsubr("get-code-point",                           1, 0, 0, get_code_point);
	scm_c_define_gsubr("make-success-indication-parameter",        1, 0, 0, make_success_indication_parameter);
	scm_c_define_gsubr("make-error-cause-indication-parameter",    1, 1, 0, make_error_cause_indication_parameter);
	scm_c_define_gsubr("get-asconf-error-causes",                  1, 0, 0, get_asconf_error_causes);
}
