/* ipband.h
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

#ifndef IPBAND_H__
#define IPBAND_H__


/*
------------------------------------------------------------------------
Include Files
------------------------------------------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>

#ifndef AF_INET
#include <sys/socket.h>         /* BSD AF_INET */
#endif

#include <pcap.h>
#include "hash.h"

/*
------------------------------------------------------------------------
Defines
------------------------------------------------------------------------
*/

#define VERSION_STR "ipband 0.8.1"

#define DUMP
#undef  DUMP

/* Defaults */
#define CONFIG_DEF "/etc/ipband.conf"
#define MTASTR_DEF "/usr/sbin/sendmail -t -oi"
#define REPFILE_DEF "ipband.txt"
#define HTMLFILE_DEF "ipband.html"
#define HTMLTITLE_DEF "My bandwidth"

#define TRUE 1
#define FALSE 0
#define MAXLINE 4096 

/*  Length of saved packets  */
#define PLEN 68

/*  Length of packet headers */
#define POFF_ETH  14
#define POFF_PPP   4
#define POFF_RAW   0

#define U_CHAR unsigned char

/* Used for setting defaults */
#define FREE(P) if ((P)!=NULL) { free(P); (P)=NULL; }


/*
------------------------------------------------------------------------
Type Definitions
------------------------------------------------------------------------
*/

/*  Packet structure used by pcap library  */
typedef struct {
	U_CHAR src[6];
	U_CHAR dst[6];
	U_CHAR ptype[2];     /*  ==0x800 if ip  */
	} eth_struct_t;

typedef struct {
	U_CHAR version[1];
	U_CHAR service[1];
	U_CHAR length[2];
	U_CHAR id[2];
	U_CHAR flag[2];
	U_CHAR ttl[1];
	U_CHAR prot[1];
	U_CHAR chksum[2];
	U_CHAR srcip[4];
	U_CHAR dstip[4];
	U_CHAR srcpt[2];
	U_CHAR dstpt[2];
	} ip_struct_t;


/*  Subnet detail data */
typedef struct {
	double       nbyte;
	/* These 2 are keys for deleting detail data for a given subnet */
	int	   subnet_src;
	int        subnet_dst;
} data_t;


/*  Per subnet aggregate data  */
typedef struct {
	double       nbyte;
	/*
	 *   Non-zero value in logtime means: a) we started detailed
	 *   logging for this subnet; b) we keep logging on next cycle
	 *   and don't spin off another logging; c) we only zero byte
	 *   counters for this subnet and don't delete this subnet from
	 *   hash table; d) we check if bandwidth goes _below_ limit to
	 *   stop logging and create a report.
	 */
	time_t	   logtime;
	/*
	 *    Number of seconds threshold was exceeded since we started
	 *    detailed logging
	 */
	int	   exc_time;
	/*
	 *    For pre-loaded subnets we store their bandwidth
	 *    threshold value
	 */
	float	   band;
	/*
	 *    Accumulated threshold exceed time in seconds since
	 *    ipband started. Only makes sense for preloaded subnets
	 *    as otherwise subnet data is deleted when usage drops.
	 */
	unsigned int exc_accum;

} aggr_data_t;


/* Linked list for tcp and udp services cache */
typedef struct ll_srvc_s {
	struct ll_srvc_s *next;
	int port;
	char *sname;
	}
	ll_srvc_t;


/*
------------------------------------------------------------------------
Global variables
------------------------------------------------------------------------
*/

/* Externals */
extern char pcap_version[];

/* Internal use */
int    isig_m; 			/* Interupt flag for capture loop */
int    preload_m;		/* Subnets are preloaded flag */
char   *pcapdev_m;		/* Device to listen to */
pcap_t *pcapfile_m;		/* Pcap input file descriptor */
int    pcapoffset_m;		/* IP header offset */
time_t started_m;		/* Time when we started */

ll_srvc_t *ll_tcp_cache;	/* Resolved tcp services cache */
ll_srvc_t *ll_udp_cache;	/* Resolved udp services cache */


/* Variables holding option values */
int    debug_m; 		/* Debug option */
int    do_html;			/* Generate HTML output */
char   *filtercmd_m;		/* Pcap filter string */
char   *repfname_m; 		/* Subnet report output file */
char   *htmlfname_m; 		/* HTML report output file */
char   *htmltitle_m;		/* HTML Title */
int    mask_m;			/* Network aggregation mask bits */
int    cycle_m;			/* Number of sec to average data */
int    rcycle_m;		/* How long in sec bandwidth
				   threshold may be exceeded */
float  thresh_m;		/* Bandwidth threshold in kBps */
int    fork_m;			/* Fork flag */
int    top_m;			/* No of top connections in report */
char   *config_m;		/* Config file name */
char   *mailto_m;		/* E-mail address for reporting */
char   *mailfoot_m;		/* Footer file for e-mail report */
char   *mtastring_m;		/* MTA command string */
int    report_aggr_m;		/* Flag to report aggr exceed time */
int    promisc_m;		/* Use promiscious mode? */
int    *iplist_m;		/* List of local networks */
int    niplist_m;		/* Number of local networks */
int    lenadj_m;		/* IP packet length adjustment in bytes */


/*
------------------------------------------------------------------------
Local Function Prototypes
------------------------------------------------------------------------
*/

/* error.c */
void err_msg(const char *, ...);
void err_quit(const char *, ...);
void err_ret(const char *, ...);
void err_sys(const char *, ...);

/* init.c */
void print_usage ();
void read_options (int argc, char *argv[]);
void dump_options();
void ihandler (int);
int  read_config (char *);
void check_invalues();
int  parse_subnets (char *, hlist_t **);
void preload_subnets(char *, hlist_t **);
void set_defaults();
void parse_ip_range (char *, int **, int *);
int  in_iprange (int, int *, int);

/* packets.c */
void storepkt (struct pcap_pkthdr *, ip_struct_t *, hlist_t **, hlist_t **);
void proc_aggr (hlist_t **, hlist_t **);
void detail_cleanup(hlist_t **, U_CHAR *);

/* pcapfunc.c */
void open_interface (int);
void print_datalink ();
int  get_packetoffset (int);

/* popen.c */
FILE *sec_popen(const char *, const char *);
int   sec_pclose(FILE *);
int   open_max(void);

/* reports.c */
void subnet_report (hlist_t **, U_CHAR *,float, int, unsigned int);
void va_report(char *,...);
void html_report(char *,...);
char *get_service(int, int);

/* utils.c */
int  delete_next(hlist_t **, int, int);
char *hex2dot (char *);
void get_two_tok(char *, char **, char **);
int  is_space(char);
char *find_nonspace (char *);
char *find_space (char *);
int  strcmpi (char *, char *);
int  is_true_str (char *);
int  compare_bytes (const void *, const void *);
void str2ip (char *, int *, int *);
#ifdef strtok_r
#undef strtok_r
#endif
char *strtok_r(char *, const char *, char **);

#endif		/* IPBAND_H__ */

