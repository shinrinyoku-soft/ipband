/* packets.c	routines for packets processing
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


/*
Store packet info in aggregate hash table, keyed by subnet
Store packet info in detail table if subnet is being logged
*/

void storepkt (struct pcap_pkthdr *pkthdr, ip_struct_t *ip,
	       hlist_t **ha, hlist_t **ha_d) {

	U_CHAR     	key_src[9];  /*  src subnet as hex string  */
	U_CHAR     	key_dst[9];  /*  dst subnet as hex string  */
        U_CHAR     	key[13];     /*  detail logging key */
	aggr_data_t     *data,    idata;
	data_t		*data_d,  idata_d;
	int        	ndata,    ndata_d;
	int        	datasize, datasize_d;
	int        	keysize,  keysize_d;
	int	   	ip_src, ip_dst;
	int        	length;
	int 	   	i;
	int		detail_flag = FALSE;

	/* Calculate data packet length */
	length = pkthdr->len + lenadj_m;

	/* Get ip src and dst ip address and convert to integers */
	ip_src = ip_dst = 0;
	for(i=0; i<4; i++){
	   ip_src = ip_src<<8;
	   ip_dst = ip_dst<<8;
	   ip_src |= (int) ip->srcip[i];
	   ip_dst |= (int) ip->dstip[i];
	}

	/* Apply mask and get our key - network number */
	ip_src &= mask_m;
	ip_dst &= mask_m;
	sprintf(key_src,"%08x",ip_src);
	sprintf(key_dst,"%08x",ip_dst);

	/* Store length of this packet */
	idata.nbyte = (double) length;

	/* Set logtime to zero (when adding the key first time)
	   meaning that we don't start detailed logging of this subnet yet */
	idata.logtime = (time_t) 0;

	/* Initialize exceed time counters */
	idata.exc_time = 0;
	idata.exc_accum = 0;
	
	/* Set bandwidth threshold to zero if we don't have preloaded nets */
	idata.band = 0.0;

	/*  Set size of data structures  */
	datasize = sizeof(aggr_data_t);
	keysize  = sizeof(key_src);

		#ifdef DUMP
		printf("Hash table key: ");
		printf("src %s - dst %s len - %d\n",key_src,key_dst,length);
		#endif


   /*********************************************************************/
   /*    If preload_m is set, we only update and do not add new nodes   */
   /*********************************************************************/

   		/* Processing source network */
	
   /* If local ip range specified and src network is not in that range,
    * don't process this network */
   if (!iplist_m || (iplist_m && in_iprange(ip_src,iplist_m,niplist_m))){
	
        /* Add first instance of source key to table */
	if (! hash_finddata(ha,(U_CHAR *)&key_src,keysize,
			       (U_CHAR **)&data,&ndata)){
	   if ( !preload_m ) {
	   datasize = sizeof(idata);
	   hash_addnode(ha,(U_CHAR *)&key_src,keysize,
			   (U_CHAR *)&idata,datasize);
	   }

        /* Key already present, update info */
        } else  {
           /* Update byte count */
           data->nbyte += idata.nbyte;
           /* Do we log packet to detail table? */
           if ( data->logtime != 0 ) detail_flag = TRUE;
        }
   }		/* End of processing source network */

   		/* Processing destination network */

   /* If local ip range specified and dst network is not in that range,
    * don't process this network */
   if (!iplist_m || (iplist_m && in_iprange(ip_dst,iplist_m,niplist_m))) {

        /* If src and dst on same subnet don't log connection twice */
        if ( ip_src != ip_dst ) {

           /* Add first instance of destination key to table */
	   if (! hash_finddata(ha,(U_CHAR *)&key_dst,keysize,
				  (U_CHAR **)&data,&ndata)){

		if ( !preload_m ) {
		   datasize = sizeof(idata);
		   hash_addnode(ha,(U_CHAR *)&key_dst,keysize,
				   (U_CHAR *)&idata,datasize);
		}

           /* Key already present, update info */
           } else  {
              /* Update byte count */
              data->nbyte += idata.nbyte;
              /* Do we log packet to detail table? */
              if ( data->logtime != 0 ) detail_flag = TRUE;
           }

        } 	/* End of if not on the same subnet */

   }		/* End of processing destination network */


   /*********************************************************************/
   /*      If this packet should be logged to subnet detail table       */
   /*********************************************************************/

   if( detail_flag ) {

	/* Make key - order so smallest ip first store data */
	if (memcmp(ip->srcip, ip->dstip, 4) < 0) {
	   memcpy (key+ 0, ip->srcip, 4);
	   memcpy (key+ 4, ip->dstip, 4);
	   memcpy (key+ 8, ip->srcpt, 2);
	   memcpy (key+10, ip->dstpt, 2);
	} else {
	   memcpy (key+ 0, ip->dstip, 4);
	   memcpy (key+ 4, ip->srcip, 4);
	   memcpy (key+ 8, ip->dstpt, 2);
	   memcpy (key+10, ip->srcpt, 2);
	}

	   memcpy (key+12, ip->prot,  1);
	   idata_d.nbyte = (double) length;
	   /* Fill in subnets this packet belongs to for easier deleting */
	   idata_d.subnet_src = ip_src;
	   idata_d.subnet_dst = ip_dst;

	/*  Set size of data structures  */
	datasize_d = sizeof(data_t);
	keysize_d  = sizeof(key);

       /* Add first instance of this key to table */
        if (! hash_finddata(ha_d,(U_CHAR *)&key,     keysize_d,
				 (U_CHAR **)&data_d, &ndata_d) )
	{
	datasize_d = sizeof(idata_d);
	hash_addnode(ha_d,(U_CHAR *)&key,     keysize_d,
			  (U_CHAR *)&idata_d, datasize_d);
				
	/* Key already present, update info */
	} else  {
	data_d->nbyte += idata_d.nbyte;
	}

   }   /* End logging to subnet detail table */

}


/* Process per-subnet aggregate hash table */
void proc_aggr (hlist_t **ha, hlist_t **ha_d) {
	hlist_t 	*t;
	aggr_data_t  	*data;
	FILE    	*outfile_m = stdout;
	double		kbytes;
	float		kBps;
	float		thresh;
	int 		exc_time;
	hiter_t		ti;		/* table iterator */

	
	if (do_html) {
		time_t generated;
		time (&generated);
		
		if (! htmltitle_m) {
			htmltitle_m = strdup(HTMLTITLE_DEF);
		}

		html_report("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\n");
		html_report("\n");
		html_report("<html>\n");
		html_report("<head>\n");
		html_report("     <title>%s</title>\n", htmltitle_m);
		html_report("     <meta http-equiv=\"Refresh\" content=\"%d\">\n", cycle_m);
		html_report("     <meta http-equiv=\"Pragma\" content=\"no-cache\">\n");
		html_report("     <meta http-equiv=\"Cache-Control\" content=\"no-cache\">\n");
		html_report("     <link href=\"styles.css\" rel=\"stylesheet\" type=\"text/css\">\n");
		html_report("</head>\n");
		html_report("\n");
		html_report("<body>\n");
		html_report("\n");
		html_report("<table width=\"100\%\" border=\"0\" align=\"center\">\n");
		html_report("<tr><td align=\"center\" nowrap class=\"subject\">%s</td></tr>\n", htmltitle_m);
		html_report("<tr><td align=\"center\" nowrap class=\"date\">Date: %s</td></tr>\n", ctime(&generated));
		html_report("<tr><td><br></td></tr>\n");
		html_report("<tr>\n");
		html_report("	<td align=\"center\">\n");
		html_report("		<table border=\"0\" cellspacing=\"2\" cellpadding=\"2\">\n");
		html_report("		<tr><td nowrap class=\"text\"><b>IP address</b></td><td>&nbsp;</td><td align=\"right\" nowrap class=\"text\"><b>Bandwidth</b></td></tr>\n");
		html_report("		<tr><td colspan=\"3\"><hr class=\"line\"></td></tr>\n");
	}
	
	/* Walk hash table */
	for(t=hash_getfirst(ha,&ti); t; t = hash_getnext(ha,&ti)){

		data = (aggr_data_t *) t->data;

		/* What is bandwidth threshold for this subnet */
		thresh = (data->band) ? data->band : thresh_m;

		/* Total bytes and bandwidth */
		kbytes = (data->nbyte)/1024.0;
		kBps = (float) kbytes/cycle_m;

		/* If detailed logging for this subnet in progress */
		if ( (long) data->logtime != 0 ){

		   /* Usage still high */
		   if ( kBps >= thresh ) {

	            /* How long threshold has been exceeded this cycle? */
	            exc_time = (int) difftime(time(NULL),data->logtime);

		       /* Is it time to cry out loud? */
		       if ( exc_time >= rcycle_m ){

	                 /* How long threshold has been exceeded so far? */
	                 data->exc_time += exc_time;

			 /* Accumulated exceed time since app started */
			 if (report_aggr_m) data->exc_accum += exc_time;

		         subnet_report(ha_d,t->key,thresh,
				       data->exc_time,
				       data->exc_accum);
	          	 data->logtime = 0;

		       }
		
		   /* If bandwidth dropped below limit we stop
		      detailed logging */
		   } else {

		       /* Delete subnet entries from detail log */
		       detail_cleanup(ha_d,t->key);
		
		       /* Unset detail logging flag for this subnet */
		       data->logtime = 0;

		       /* Clear exc_time for subnet */
		       data->exc_time = 0;
		   }

		} /* End if detailed logging in progress */


		/* if bandwidth threshold is exceeded for the first time
		   we start detailed logging for this subnet
		   setting logtime value in aggr_data_t structure to
		   current time */
		if ( kBps >= thresh && 0 == (long) data->logtime ) {
		data->logtime = time(NULL);
		}
		
		if (do_html) {
			html_report("		<tr><td nowrap class=\"text\">%s</td><td>&nbsp;</td>", hex2dot(t->key));
			html_report("<td align=\"right\" nowrap class=\"text\">%.2f kBps</td></tr>\n",kBps);
		}

		if (2==debug_m) {
		/*  Print subnet table  */
		   if ( kBps > thresh && (long) data->logtime != 0)
			fprintf (outfile_m, "*");
		   else
			fprintf (outfile_m, " ");
		fprintf (outfile_m, "%-15s", hex2dot(t->key));
		fprintf (outfile_m, " %7.2f kB ",kbytes);
		fprintf (outfile_m, " %7.2f/%6.2f kBps",kBps,thresh);
		fprintf (outfile_m, "\n");
		}

		/* Clean-up */
		/* If subnet is being logged - zero counters */
		if ( (long) data->logtime != 0 ){
		data->nbyte = 0;
		} else {
		   /*
		   If not - delete it. But *only* if
		   we are NOT working with preloaded subnets!
		    */
		   if (! preload_m ) {
			hash_delnode(ha, t->key, t->nkey);
		   /* For preloaded subnets - just clear counters */
		   } else {
		     data->nbyte = 0;
		   }
		}

	} /* End of walking table */
	
	if (do_html) {
		html_report("		</table>\n");
		html_report("	</td>\n");
		html_report("</tr>\n");
		html_report("</table>\n");
		html_report("</body>\n");
		html_report("</html>\n");
		html_report(NULL);
	}
	
	if (2==debug_m) {
	fprintf(outfile_m,"************************************************\n");
	}

}

/*
Delete entries for specific subnet from detail hash table when bandwidth
usage for that subnet drops below limit.
This is a hash table function but not generic to be put in hash.c.
*/

void detail_cleanup (hlist_t **ha_d, U_CHAR *key) {
	
	int 	ip_key;
	int 	hash;
	int 	result;

	/* Get size of hash table */
	int slots = N_HASH_SLOTS; 	/* from hash.h */
	int ntable;
	int nhashbit = 1;
	slots--;
	while (slots>>=1) nhashbit++;
	ntable = 1 << nhashbit;

	/* Get subnet number in int */
	sscanf(key,"%08x",&ip_key);

	/* Walk table */
	for (hash = 0; hash < ntable; hash++) {

	   if (NULL == ha_d[hash]) continue;
	
	   result = TRUE;
	   while (result) result = delete_next(ha_d,hash,ip_key);

	} 	/* end of walk table loop */
}

