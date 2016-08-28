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
 * There are two mailinglists available at http://www.sctp.de which should be
 * used for any discussion related to this implementation.
 *
 * Contact: tuexen@fh-muenster.de
 *
 */

unsigned short
scan_tlv_list (SCM s_tlvs, scm_t_bits tag, scm_t_uint16 max_length);

void
put_tlv_list (unsigned char *buffer, SCM s_tlvs);

SCM
get_tlv_list (unsigned char *list, scm_t_uint16 length, const char *type_name, scm_t_bits tag);
