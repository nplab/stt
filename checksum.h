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

scm_t_uint32
initialize_crc32c(void);

scm_t_uint32
update_crc32c(scm_t_uint32 res, const unsigned char* buf, scm_t_uint32 len);

scm_t_uint32
finalize_crc32c(scm_t_uint32 res);

scm_t_uint32
initialize_adler32(void);

scm_t_uint32 
update_adler32(scm_t_uint32 adler, const unsigned char *buf, scm_t_uint32 len);

scm_t_uint32
finalize_adler32(scm_t_uint32 res);
