/* utils.c	- various support functions 
 *
 * ipband - network bandwidth watchdog
 * By Andrew Nevynniy
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#include "ipband.h"


/* Delete next node matching ip_key from given slot */
int delete_next(hlist_t **ha_d, int hash, int ip_key) {

	hlist_t	*t_prev;
	hlist_t *t;
	data_t  *data;
	int	 subnet_src, subnet_dst;

	for(t=ha_d[hash]; t; t_prev=t, t=t->next) {

		 data = (data_t *) t->data;
		 subnet_src = data->subnet_src;
		 subnet_dst = data->subnet_dst;
		 if((subnet_src == ip_key) || (subnet_dst == ip_key)) {
		 	free(t->data);
			free(t->key);
			if (t == ha_d[hash]) ha_d[hash] = t->next;
			else t_prev->next = t->next;
			free((void *) t);
			return 1;
		 }
	}
	return 0;
}


/* Convert 8 byte hex string to dotted octet string */
char * hex2dot (char * str) {

	int i,ip;
	int p[4];
	static char buf[20];

	sscanf(str,"%08x",&ip);

	for (i=0;i<4;i++) {
		p[i] = ip & 0xff;
		ip >>= 8;
	}
	
	sprintf (buf, "%d.%d.%d.%d", p[3], p[2], p[1], p[0]);
	return buf;

}

/*  Return pointers to first two space delimited tokens,
    null terminating first token if necessary.
    If no first,second token then pointers point to '\0'
*/
void get_two_tok(char *str, char **tok1, char **tok2) {

	/*  Find start of first token  */
	str = find_nonspace(str);
	*tok1 = *tok2 = str;
	if (*str=='\0') return;

	/*  Find end of first token  */
	*tok2 = str = find_space (str);
	if (*str=='\0') return;

	/*  terminate first token  */
	*(str++) = '\0';

	/*  find second token   */
	*tok2 = find_nonspace(str);

	/*  Remove trailing space  */
	str = str + strlen(str) - 1;
	while (is_space(*str)) {
		str--;
	}
	*(++str) = '\0';
}
	
/*  Test for space *OR* equals sign
 *  (to allow shell scripts lines like TERM=vt1000 to be used as config
 *  files
 *  */
int is_space(char c) {
	return c==' ' || c=='\t' || c=='\n' || c=='\r' || c=='=';
}

/*  Find first non-space char */
char *find_nonspace (char *str) {
	while (*str && is_space(*str)) str++;
	return str;
}

/*  Find first space char */
char *find_space (char *str) {
	while (*str && !is_space(*str)) str++;
	return str;
}

/*  Compare two strings ignoring case  */
int strcmpi (char *a, char *b) {
	int equal = 1;
	char c,d;
	while (equal && *a) {
		c = *a++;
		d = *b++;
		if ('a'<=c && c<='z') c += 'A' - 'a';
		if ('a'<=d && d<='z') d += 'A' - 'a';
		equal = (c==d);
	}
	if (equal) return 0;
	if (c<d)   return -1;
	return 1;
}

/*  Return true of string is yes, on, ok ignoring case  */
int is_true_str (char *str) {
	return
		(! strcmpi("yes",str)) ||
		(! strcmpi("true",str)) ||
		(! strcmpi("on",str)) ||
		(! strcmpi("ok",str));
}

/* Argument to qsort() for sorting subnet detail hash table */
int compare_bytes (const void *a, const void *b) {

	data_t *dataa, *datab;

	const hlist_t **ta = (const hlist_t **) a;
	const hlist_t **tb = (const hlist_t **) b;

	dataa = (data_t *) (*ta)->data;
	datab = (data_t *) (*tb)->data;

	return (datab->nbyte) - (dataa->nbyte);
}


/*  Convert strings like "138.99.201.5" or "137.99.26" to int ip address  */
void str2ip (char *ipstr, int *ipout, int *mask) {
	int ip[4];
	int n = sscanf (ipstr, "%d.%d.%d.%d", ip, ip+1, ip+2, ip+3);
	int i;
	*ipout = 0;
	for (i=0;i<4;i++) {
		*ipout = *ipout<<8;
		if (i<n) *ipout |= (ip[i] & 0xff);
	}
	*mask = 0xffffffff >> (8*n);

	/* for reasons unknown 0xffffffff >> 32 -> -1, so set to 0  */
	if (*mask==-1)  *mask=0;
}


/* Reentrant string tokenizer.  Generic version.

   Slightly modified from: glibc 2.1.3

   Copyright (C) 1991, 1996, 1997, 1998, 1999 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
 */

char *strtok_r(char *s, const char *delim, char **save_ptr) {
  char *token;

  if (s == NULL)
    s = *save_ptr;

  /* Scan leading delimiters.  */
  s += strspn (s, delim);
  if (*s == '\0')
    return NULL;

  /* Find the end of the token.  */
  token = s;
  s = strpbrk (token, delim);
  if (s == NULL)
    /* This token finishes the string.  */
    *save_ptr = "";
  else {
    /* Terminate the token and make *SAVE_PTR point past it.  */
    *s = '\0';
    *save_ptr = s + 1;
  }

  return token;
}
