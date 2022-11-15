#ifndef HASH_H__
#define HASH_H__

/*
------------------------------------------------------------------------
Defines
------------------------------------------------------------------------
*/
#define N_HASH_SLOTS 10000 


/*
------------------------------------------------------------------------
Type Definitions
------------------------------------------------------------------------
*/
/* Table node structure */
typedef struct hlist_s {
	struct hlist_s *next;
	u_char *key;
	int    nkey;
	u_char *data;
	int    ndata;
	}
	hlist_t;

/* Table iterator structure */
typedef struct hiter_s {
	int index;
	hlist_t *ptr;
	}
	hiter_t;

/*
------------------------------------------------------------------------
Function Prototypes
------------------------------------------------------------------------
*/
hlist_t **hash_init () ;
int       hash_finddata (hlist_t **, u_char *, int, u_char **, int *);
int 	  hash_delnode  (hlist_t **, u_char *, int);
int       hash_addnode  (hlist_t **, u_char *, int, u_char *, int) ;
int       hash_getcount	(hlist_t **);
hlist_t **hash_getlist	(hlist_t **, int *);
hlist_t  *hash_getnext  (hlist_t **, hiter_t *);
hlist_t  *hash_getfirst (hlist_t **, hiter_t *);

#endif	/* HASH_H__ */
