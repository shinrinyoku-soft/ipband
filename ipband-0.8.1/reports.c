/* reports.c	reporting functions
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


/* Print detail report for given subnet */
void subnet_report (hlist_t **ha_d, U_CHAR *key, float thresh,
		    int exc_time, unsigned int exc_aggr)
{

	hlist_t **conn = NULL;
	int 	nconn, j, count;
	hlist_t *t;
	data_t  *data;
	char    ip1[16], ip2[16], uprots[4];
	int     pt1, pt2, prot;
	double	kbytes;
	time_t  now = time(NULL);
	int	i;
	int	ip_src = 0;
	int	ip_dst = 0;
	int 	ip_key = 0;
	int	max_conn;
	char	*srvcs;			/* Service name */
	char    *prots;			/* Protocol name */
	struct  protoent *prot_s;	/* IP protocol structure */
	struct  netent   *net_s;	/* Resolved network name sructure */
	int	ikey;			/* key as integer */


	/* Get array of pointers to data and number of connections */
	nconn = 0;
       	conn = hash_getlist(ha_d,&nconn);

	/* Sort array descending by byte count */
	qsort(conn,nconn,sizeof(hlist_t *),compare_bytes);

	/* Get network name if available */
	sscanf(key,"%08x",&ikey);
	net_s = getnetbyaddr(ikey,AF_INET);

	/* Print e-mail subject to include subnet info */
	if(net_s) va_report("Subject: Bandwidth report for %s <%s>\n\n",hex2dot(key),net_s->n_name);
	else va_report("Subject: Bandwidth report for %s\n\n",hex2dot(key));

	/* Print header */
	va_report("\nDate:   %s", ctime(&now));
	if(top_m) va_report("Showing top %d connections\n",top_m);
	va_report("Network: %s", hex2dot(key));
	if(net_s) va_report(" <%s>",net_s->n_name);
	va_report("\n");
	va_report("Bandwidth threshold: %.2f kBps, exceeded for: %.2f min\n",thresh,(float) exc_time/60.0);

	/* Total accumulated time and percentage would not apply
	 * if subnets are not pre-loaded as they would be deleted
	 * once bandwidth usage dropped below threshold */
	if(report_aggr_m && preload_m) {
	  char *exc_str;
	  size_t lastch;
	  float elapsed;

	  exc_str = ctime(&started_m);
	  lastch = strlen(exc_str) - 1;
	  if (exc_str[lastch] == '\n') exc_str[lastch] = '\0';

           /* How many secs passed since we started? */
          elapsed = (float) difftime(time(NULL),started_m);

	  va_report("Threshold exceeded time since %s: %.2f min (%4.2f%%)\n",exc_str, (float) exc_aggr/60.0, exc_aggr*100.0/elapsed);
	}

	va_report("===============================================================================\n");
	va_report("FROM            < PORT>     TO              < PORT>  PROT      KBYTES  SERVICE\n");
	va_report("-------------------------------------------------------------------------------\n");

	/* Walk hash table */
	max_conn = (top_m && top_m < nconn) ? top_m : nconn;
	for(j=0, count=0; j<nconn && count<max_conn; j++){

		t=conn[j];
		data = (data_t *) t->data;

		for(i=3; i>=0; i--) {
		ip_src += t->key[i] << (8*i);
		ip_dst += t->key[i+4] << (8*(i+4));
		}

		/* Skiping subnets other than our */
		ip_src = data->subnet_src;
		ip_dst = data->subnet_dst;
		sscanf(key,"%08x",&ip_key);
		if ( !(ip_src == ip_key || ip_dst == ip_key) ) continue;

		/* Inreasing loop counter only after other subnets are
		   skipped */
		count++;

		/*  Get ip addresses and ports  */
		sprintf (ip1, "%u.%u.%u.%u",
			t->key[0], t->key[1], t->key[2], t->key[3]);
		sprintf (ip2, "%u.%u.%u.%u",
			t->key[4], t->key[5], t->key[6], t->key[7]);
		pt1  = (int) t->key[ 8]*256 + t->key[ 9];
		pt2  = (int) t->key[10]*256 + t->key[11];
		prot = t->key[12];


		/* For tcp or udp we try to resolve service name */
		if (6 == prot) {                /* tcp */
		srvcs = get_service(pt1,prot);
		if (!strlen(srvcs)) srvcs = get_service(pt2,prot);
		prots = "tcp";

		} else if (17 == prot ) {       /* udp */
		srvcs = get_service(pt1,prot);
		if (!strlen(srvcs)) srvcs = get_service(pt2,prot);
		prots = "udp";

		} else {                        /* not tcp or udp */
		   if ( (prot_s = getprotobynumber(prot)) ) {
		   prots = prot_s->p_name;
		   } else {
		   snprintf(uprots, 4, "%u",prot);
		   prots = uprots;
	 	   }
		srvcs = "";
		}


		/*  Print key info  */
		va_report("%-15s <%5u> <-> %-15s <%5u> %4s",
			   ip1,  pt1,      ip2,   pt2, prots);

		/* Total bytes, time and service */
		kbytes = (data->nbyte)/1024.0;
		va_report(" %12.2f",kbytes);
		if (srvcs) va_report("  %.11s",srvcs);
		va_report("\n");

	}	/* End looping through connections */

	va_report("===============================================================================\n");

	/* Close report file handles */
	va_report(NULL);

	/* Free array of pointers */
	if( NULL != conn ) free(conn);

}


/* Get service name by tcp or udp port number and store in cache */
char *get_service(int port, int prot) {

	ll_srvc_t *p;
	char *srvcs;
	char *prots;

	struct servent  *srvc_s;
	struct protoent *prot_s;
	int found = 0;
	srvcs = "";

	/* For tcp or udp we try to resolve service name */
	if (6 == prot) {		/* tcp */

	/* Check service name in cache */
	   p = ll_tcp_cache;
 	   while (p) {
	   	if (port == p->port) {
			found = 1;
			srvcs = p->sname;
		}
	   p = p->next;
	}

	/* Not in cache? Put there */
	if( !found) {

	   /* Resolve name */
	   if ((srvc_s = getservbyport(htons(port),"tcp")))
	        srvcs = srvc_s->s_name;

	   /* Insert name in front of tcp cache linked list */
	   if( (p = (ll_srvc_t *) malloc(sizeof(*p))) ){
	  	   p->port = port;
		   p->sname = strdup(srvcs);
		   p->next = ll_tcp_cache;
		   ll_tcp_cache = p;
	   }
	}


	} else if (17 == prot ) {	/* udp */

	  if ( (prot_s = getprotobynumber(prot)) ) {
		prots = prot_s->p_name;
	  }

	/* Check service name in cache */
	   p = ll_udp_cache;
 	   while (p) {
	   	if (port == p->port) {
			found = 1;
			srvcs = p->sname;
		}
	   p = p->next;
	}

	/* Not in cache? Put there */
	if( !found) {

	   /* Resolve name */
	   if ((srvc_s = getservbyport(htons(port),prots)))
	        srvcs = srvc_s->s_name;

	   /* Insert name in front of udp cache linked list */
	   if( (p = (ll_srvc_t *) malloc(sizeof(*p))) ){
	 	   p->port = port;
		   p->sname = strdup(srvcs);
		   p->next = ll_udp_cache;
		   ll_udp_cache = p;
	   }

	}

	}

	return srvcs;
}


/* Use variable length arguments to output reports to multiple facilities */
void va_report(char *cp,...) {

	va_list va;
	static FILE 	*sendmail;	/* static to persist across calls */
	static FILE 	*repfile;	/* static to persist across calls */
	FILE 		*ffoot = NULL;
	char 		buffer[512];
	char 		*str;

	if (!cp){ 	/* Cleanup when called with NULL format string */

		if (repfile) {
			if (repfile != stdout) fclose(repfile);
			repfile = NULL;
			}

		if (sendmail && mailto_m) {
			/* Append mail footer if needed */
			if (mailfoot_m) {
			   if ( (ffoot = fopen (mailfoot_m, "r")) ){
		              while ( (str=fgets(buffer, 512, ffoot)) )
			      fputs(str,sendmail);
			      fclose (ffoot);
			   }
			}
			/* Close handle */
			sec_pclose(sendmail);
			sendmail = NULL;
			}

	} else {		/* Get handles and print */

	if (!repfile) {

		if (! repfname_m) repfname_m = strdup(REPFILE_DEF);
		if (strcmp("-",repfname_m)) repfile = fopen (repfname_m, "a");
		else			    repfile = stdout;

			if (NULL==repfile) {
			err_quit("ERROR:  Cannot open output file <%s>\n", repfname_m);
			}
	}

	if (mailto_m) {		/* If e-mail option is set */

	   /* Open pipe to MTA */
	   if(!sendmail) {
		
		sendmail = sec_popen(mtastring_m,"w");
		if (NULL==sendmail) {
		err_quit("ERROR:  error opening %s\n",mtastring_m);
		}
		/* Sendmail headers */
		fprintf(sendmail,"To: %s\n",mailto_m);
		fprintf(sendmail,"From: IP bandwdth watchdog <>\n");
	   }

	}

	if (strncmp(cp,"Subject:",8)) {		/* Skip mail subject line */
	   va_start(va,cp);
	   if( repfile) vfprintf(repfile,cp,va);
	   va_end(va);
	}

	if (mailto_m) {
	   va_start(va,cp);
	   if( sendmail) vfprintf(sendmail,cp,va);
	   va_end(va);
	}
	
	}
}

/* HTML reports */
void html_report(char *cp,...) {

	va_list va;
	static FILE 	*htmlfile;	/* static to persist across calls */

	if (!cp) { 	/* Cleanup when called with NULL format string */
		if (htmlfile) {
				if (htmlfile != stdout) {
					fclose(htmlfile);
				}
				htmlfile = NULL;
			}
	} else {		/* Get handles and print */

		if (!htmlfile) {

			if (! htmlfname_m) {
				htmlfname_m = strdup(HTMLFILE_DEF);
			}
			
			if (strcmp("-",htmlfname_m)) {
				htmlfile = fopen (htmlfname_m, "w");
			} else {
				htmlfile = stdout;
			}

			if (NULL==htmlfile) {
				err_quit("ERROR:  Cannot open output file <%s>\n", htmlfname_m);
			}
		}

		va_start(va,cp);
		
		if (htmlfile) {
			vfprintf(htmlfile,cp,va);
		}
		
		va_end(va);
	}
}
