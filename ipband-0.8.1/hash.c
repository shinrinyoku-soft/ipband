/* hash.c
 *
 * hash.c - generic basic hash table functions
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


/*
------------------------------------------------------------------------
Include files
------------------------------------------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>			/* BSD u_char */
#include "hash.h"


/*
------------------------------------------------------------------------
Defines
------------------------------------------------------------------------
*/

#define U_CHAR unsigned char
#define UINT4  unsigned int

#define NRSEQ  256


/*
------------------------------------------------------------------------
Module variables
------------------------------------------------------------------------
*/

static int 	ntable_m=0;

/*
Random sequence table - source of random numbers.  The
hash routine 'amplifies' this 2**8 long sequence into
a 2**32 long sequence.
*/
static U_CHAR rseq_m[NRSEQ+3] =
{
 79,181, 35,147, 68,177, 63,134,103,  0, 34, 88, 69,221,231, 13,
 91, 49,220, 90, 58,112, 72,145,  7,  4, 93,176,129,192,  5,132,
 86,142, 21,148, 37,139, 39,169,143,224,251, 64,223,  1,  9,152,
 51, 66, 98,155,180,109,149,135,229,137,215, 42, 62,115,246,242,
118,160, 94,249,123,144,122,213,252,171, 60,167,253,198, 77,  2,
154,174,168, 52, 27, 92,226,233,205, 10,208,247,209,113,211,106,
163,116, 65,196, 73,201, 23, 15, 31,140,189, 53,207, 83, 87,202,
101,173, 28, 46,  6,255,237, 47,227, 36,218, 70,114, 22,100, 96,
182,117, 43,228,210, 19,191,108,128, 89, 97,153,212,203, 99,236,
238,141,  3, 95, 29,232,  8, 75, 57, 25,159, 24,131,162, 67,119,
 74, 30,138,214,240, 12,187,127,133, 18, 81,222,188,239, 82,199,
186,166,197,230,126,161,200, 40, 59,165,136,234,250, 44,170,157,
190,150,105, 84, 55,204, 56,244,219,151,178,195,194,110,184, 14,
 48,146,235,216,120,175,254, 50,102,107, 41,130, 54, 26,248,225,
111,124, 33,193, 76,121,125,158,185,245, 16,206, 71, 45, 20,179,
 32, 38,241, 80, 85,243, 11,217, 61, 17, 78,172,156,183,104,164,
 79,181, 35
};     


/*
------------------------------------------------------------------------
Local Function Prototypes
------------------------------------------------------------------------
*/
UINT4  foldkey (U_CHAR *key, int keylength);
UINT4  makehash( UINT4 );
double mrand ( UINT4 );


/*
------------------------------------------------------------------------
Exported Functions
------------------------------------------------------------------------
*/


hlist_t **hash_init () {

	int ntable = N_HASH_SLOTS;
	int nhashbit = 1;
	ntable--;
	while (ntable>>=1) nhashbit++;
	ntable_m = 1 << nhashbit;

	if (ntable_m<=0) return NULL;

	return calloc(ntable_m, sizeof(hlist_t *));

	}


int hash_finddata (hlist_t **ha, U_CHAR *key, int nkey, U_CHAR **data, int *ndata) {
	int hash;
	hlist_t *t;

	hash  = (int) ( ntable_m * mrand ( foldkey(key, nkey) ) );
	if (NULL==ha[hash]) {
		*data = NULL;
		*ndata = 0;
		return 0;
	}

	/*  Search list  */
	t = ha[hash];
	while (NULL!=t) {
		if (t->nkey==nkey && ! memcmp(t->key, key, nkey))  {
			*data  = t->data;
			*ndata = t->ndata;
			return 1;
		}
		t = t->next;
	}
	*data = NULL;
	*ndata = 0;
	return 0;
}


/* Delete note from the table */
int hash_delnode (hlist_t **ha, U_CHAR *key, int nkey) {

	int hash;
	hlist_t *t;
	hlist_t *t_prev;

	/*  Find hash  */
	hash  = (int) ( ntable_m * mrand ( foldkey(key, nkey) ) );
	
	/*  If table entry is blank, nothing to delete  */
	if (NULL==ha[hash]) return 0;

	/*  Search list  */
	for(t = ha[hash]; t; t_prev = t, t = t->next) {

		if (t->nkey==nkey && ! memcmp(t->key, key, nkey))  {

			if (t->data)  free(t->data);
			free(t->key);
			
			if (t == ha[hash]) ha[hash] = t->next; /* Was first */
			else t_prev->next = t->next;	  	/* Wasn't */

			free((void *) t);
			return 1;
		}
	}

	/* Not found even though slot wasn't empty ? */
	return 0;
}


/*  Add node to *front* of list  */
int hash_addnode (hlist_t **ha, U_CHAR *key, int nkey, U_CHAR *data, int ndata) {
	int hash;
	hlist_t **pt;
	hlist_t *t;
	hlist_t *next;

	/*  Find hash  */
	hash  = (int) ( ntable_m * mrand ( foldkey(key, nkey) ) );
	
	/*  If table entry is blank, make new entry  */
	if (NULL==ha[hash]) {
		pt = &(ha[hash]);

	/*  Search table for existing node  */
	} else {
		pt = &(ha[hash]);
		t  = *pt;
		while (NULL!=t) {

			/*  Existing node with same key, replace the data  */
			if ( t->nkey==nkey &&  ! memcmp(t->key,key,nkey) ) {
				if (t->data)  free(t->data);
				if (NULL==t->data || 0==t->ndata) {
					t->data  = NULL;
					t->ndata = 0;
				} else {
					t->data  = calloc(1, ndata);
					t->ndata = ndata;
					memcpy(t->data, data, ndata);	
				}
				return 0;
			}
			pt = &(t->next);
			t  = *pt;
		}
	}

	/*  If reached here then key not found  */

	/*  Make a new node (unattached to list)  */
	t        = calloc(1, sizeof(hlist_t));
	t->key   = calloc(1, nkey);
	t->data  = calloc(1, ndata);
	t->nkey  = nkey;
	t->ndata = ndata;
	t->next  = NULL;
	memcpy(t->key, key, nkey);
	memcpy(t->data, data, ndata);

	/*  Add node to list tail  */
	if (NULL==ha[hash])  {
		*pt = t;
	/*  Add node to list head  */
	} else {
		next = ha[hash];
		ha[hash] = t;
		t->next = next;
	}

	return 0;
}


/* Get count of nodes */
int hash_getcount (hlist_t **ha) {

	int count = 0;
	int hash;
	hlist_t *t;

	for (hash = 0; hash <ntable_m; hash++) {
	t = ha[hash];
		if ( t != NULL ) {
			while ( t != NULL ) {
			t = t->next;
			count++;
			}
		}
	}
	return count;
}

/* Get array of non-nodes and modify count of nodes */
hlist_t **hash_getlist (hlist_t **ha, int *cp) {

	int hash;
	hlist_t *t;
	hlist_t **list = NULL;

	*cp = 0;			/* number of nodes */

	for (hash = 0; hash <ntable_m; hash++) {
	t = ha[hash];
	    if ( t != NULL ) {
		  while ( t != NULL ) {
		  list = (hlist_t **) realloc(list,((*cp)+1)*sizeof(hlist_t *));
		  memcpy(list+(*cp),&t,sizeof(hlist_t *));
		  t = t->next;
		  (*cp)++;
		  }
	    }
	}
	return list;
}



/*  Find first existing node  */
hlist_t *hash_getfirst (hlist_t **ha, hiter_t *ti) {

	ti->index = (-1);
	ti->ptr   = NULL;
	return hash_getnext(ha,ti);

}


/*  Find next node  */
hlist_t *hash_getnext (hlist_t **ha, hiter_t *ti) {

	hlist_t *result;
	
	while((result = ti->ptr) == NULL) {
	   if( ++(ti->index) >= ntable_m ) return NULL;   /* Nothing left */
 	   ti->ptr = ha[ti->index];
	} 
	ti->ptr = result->next;

	return result;	
}



/*
------------------------------------------------------------------------
Local Functions
------------------------------------------------------------------------
*/

/*
'Folds' n-byte key into 4 byte key
*/
UINT4 foldkey(U_CHAR *key, int keylength)  {
	int   ikey;
	int   tkey;
	UINT4 fkey = 0;
	int   ishift = 0;
		
	/*  "fold" original key into four byte key  */
	for (ikey=0; ikey<keylength; ikey++) {
		tkey  = (int) key[ikey];
		fkey ^= (tkey << ishift);
		ishift += 8;
		if (ishift>=32) 
			ishift = 0;
	}
	return fkey;
}


/*
Hash function - performs a one to one mapping between
input integer and output integers, in other words, two different
input integers a_i, a_j will ALWAYS result in two different output
makehash(a_i) and makehash(a_j).

This hash function is designed so that a changing just one
bit in input 'a' will potentially affect the every bit in makehash(a),
and the correlation between succesive hashes is (hopefully) extremely
small (if not zero).

It can be used as a quick, dirty, portable and open source random
number generator that generates randomness on all 32 bits.
Use wrapper function mrand(n) to obtain floating point random
number r  0.0 <= r < 1.0

*/
UINT4 makehash(UINT4 a) {
   U_CHAR *c = (U_CHAR *) &a;
   U_CHAR  d[4] = {0, 0, 0, 0};
   int i;

   for (i=0;i<4;i++) {
      d[3] = rseq_m[c[0]  ] + rseq_m[c[1]+1] + rseq_m[c[2]+2] + rseq_m[c[3]+3];
      d[2] = rseq_m[c[1]  ] + rseq_m[c[2]+1] + rseq_m[c[3]+2];
      d[1] = rseq_m[c[2]  ] + rseq_m[c[3]+1];
      d[0] = rseq_m[c[3]  ];
      a = * (int *) &d[0];
   }

   return a;
}


/*  Map hash value into number  0.0<= n < 1.0  */
double mrand (UINT4 a) {

	static double f = 1.0/4294967296.0;

	return f * makehash(a);

}   
