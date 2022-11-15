/* init.c 	initialization routines
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


void print_usage(void) {
   printf("\nUsage: ipband [OPTIONS] interface\n");
   printf("  -a            -  Averaging period in seconds. ");
   printf(		     "Default is 60.\n");
   printf("  -A            -  Include accumulated threshold exceeded time\n");
   printf("                   since ipband start in the report.\n");
   printf("  -b kBps       -  Default bandwidth threshold in kBytes.\n");
   printf("                   per sec. Default is 7 kBps i.e 56 kbps.\n");
   printf("  -c filename   -  Read configuration file. Default is ");
   printf(                   "/etc/ipaband.conf.\n");
   printf("  -C            -  Ignore configuration file\n");
   printf("  -d level      -  Debug level: 0 - no debuging; 1 - summary;\n");
   printf("                   2 - subnet stats; 3 - all packets captured.\n");
   printf("  -f filterstr  -  Use pcap filters (see tcpdump).\n");
   printf("  -F            -  Fork and run in background.\n");
   printf("  -h            -  Print this help.\n");
   printf("  -J number     -  Packet length adjustment in bytes.\n");
   printf("  -l filename   -  E-mail report footer file.\n");
   printf("  -L ip-range   -  Range of local ip addresses.\n");
   printf("  -m maskbuts   -  Set number of network mask bits (1-32)\n");
   printf("                   for subnet traffic aggregation.\n");
   printf("                   Default is 24 (255.255.255.0).\n");
   printf("  -M email addr -  Mail report to given addresses.\n");
   printf("  -o filename   -  Subnet report output file. Default is\n");
   printf("                   ipband.txt in current directory.\n");
   printf("  -w filename   -  HTML report output file. Default is\n");
   printf("                   ipband.html in current directory.\n");
   printf("  -P            -  Don't use promiscuous mode on network interface.\n");
   printf("  -r            -  Reporting period - number of seconds\n");
   printf("                   banwidth threshold may be exceeded before\n");
   printf("                   it should be reported. Default is 300.\n");
   printf("  -t number     -  Limit report to a given number of connections\n");
   printf("                   with highest byte count. Default is no limit.\n");
   printf("  -T string     -  MTA command string for mailing reports. Default is\n");
   printf("                   \"/usr/sbin/sendmail -t -oi\".\n");
   printf("  -v            -  Print version and exit.\n");

   printf("\nExample:\n");
   printf("  ipband eth0 -f \"net 10.10.0.0/16\" -m 24 -a 300 -r 900\n");
   printf("\tWill capture packets from/to ip addresses matching\n");
   printf("\t10.10.0.0/255.255.0.0, tally traffic by the third octet,\n");
   printf("\tcalculate bandwidth utilization every 5 minutes and report\n");
   printf("\tper host traffic every 15 minutes.\n\n");
}


/*  Read options from command line  */
void read_options (int argc, char *argv[]) {

     int optchar;
     while(-1 != (optchar=getopt(argc,argv,"a:Ab:c:Cd:Ff:hJ:l:L:m:M:o:w:Pr:t:T:v")))
     {
		switch (optchar) {
		case '?':
			exit(1);
		/*  Get averaging period in seconds */
		case 'a':
			cycle_m = atoi(optarg);
			break;
		/* Include total exceed time in the report */
		case 'A' :
			report_aggr_m = TRUE;
			break;
		/*  Bandwidth threshold in kBps  */
		case 'b':
			thresh_m = (float) atof(optarg);
			break;
		/*  Read config file */
		case 'c':
			set_defaults();
			config_m = strdup(optarg);
			read_config(config_m);
			break;
		/* Ignore config file */
		case 'C' :
			set_defaults();
			break;
		/*  Debugging option  */
		case 'd':
			debug_m = atoi(optarg);
			break;
		/*  Do we fork?  */
		case 'F':
			fork_m = TRUE;
			break;
		/*  Get pcap filter string  */
		case 'f':
			filtercmd_m = strdup (optarg);
			break;
		/*  Print help  */
		case 'h':
			print_usage();
			exit(0);
			break;
		/*  Frame length adjustment */
		case 'J':
			lenadj_m = atoi(optarg);
			break;
		/*  Get number of subnet mask bits  */
		case 'm':
			mask_m = atoi(optarg);
			break;
		/*  Get e-mail footer file name  */
		case 'l':
			mailfoot_m = strdup (optarg);
			break;
		/* Get range of local networks */
		case 'L':
			 parse_ip_range (optarg, &iplist_m, &niplist_m);
                         break;
		/*  Get address to mail reports to  */
		case 'M':
			mailto_m = strdup (optarg);
			break;
		/* Output file name */
		case 'o':
			repfname_m = strdup(optarg);
			break;
		/* HTML file name */
		case 'w':
			htmlfname_m = strdup(optarg);
			do_html = TRUE;
			break;
		/* Don't use promiscuous mode */
		case 'P':
			promisc_m = FALSE;
			break;
		/*  Get reporting period in seconds */
		case 'r':
			rcycle_m = atoi(optarg);
			break;
		/* Top traffic */
		case 't':
			top_m = atoi(optarg);
			break;
		/* MTA command string */
		case 'T':
			mtastring_m = strdup(optarg);
			break;
		/* Print version */
		case 'v':
			printf ("%s (compiled %s)\n", VERSION_STR, __DATE__);
			printf ("libpcap version %s\n", pcap_version);
			exit(0);
		default:
			exit(1);
		}
	}
}


/* Print options in use for debug purposes */
void dump_options () {
	

printf("\n%s (compiled %s)\n", VERSION_STR, __DATE__);
printf("libpcap version %s\n", pcap_version);
printf("started %s",ctime(&started_m));
printf("\nOption values:\n");
printf("\tDebug level: %d\n",debug_m);
printf("\tPromiscuous mode: %s\n",promisc_m?"yes":"no");
printf("\tConfiguration file: %s\n",config_m);
printf("\tAveraging period (sec): %d\n",cycle_m);
printf("\tReporting peroid (sec): %d\n",rcycle_m);
printf("\tBandwidth threshold (kBps): %g\n",thresh_m);
printf("\tPcap filter string: %s\n",filtercmd_m);
printf("\tSubnet mask bits: %d\n",mask_m);
printf("\tReport output file: %s\n",repfname_m?repfname_m:"ipband.txt");
printf("\tHTML output file: %s\n",htmlfname_m?htmlfname_m:"ipband.html");
printf("\tReport mail to: %s\n",mailto_m);
printf("\tReport mail footer file: %s\n",mailfoot_m);
printf("\tMTA string: %s\n",mtastring_m);
printf("\tReport top connections: %d\n",top_m);
printf("\tFrame length adjustment: %d\n",lenadj_m);
printf("\n");

/*  Print local network ranges  */
if(iplist_m) {
	int i;
	static char buf1[20], buf2[20];
	printf ("Local IP range:\n");
	for (i=0;i<niplist_m;i++) {
	sprintf(buf1,"%08x",iplist_m[2*i  ]);
	sprintf(buf2,"%08x",iplist_m[2*i+1]);
		printf ("\t%-15s ", hex2dot(buf1));
		printf ("- %-15s\n",hex2dot(buf2));
		}
	printf ("\n");
	}

}

/* Interupt handler (called when program recieves operating system signal */
void ihandler (int cursig) {

	/*  Set flag to terminate main() polling loop
	 *  when excution reaches bottom  */
	isig_m = 1;

	/*  FLUSH BUFFERS  */
	fflush (stdout);

	/*  RE-INSTALL SIGNAL HANDLER  */
	signal (cursig, SIG_DFL);

	if (debug_m) {
	time_t seconds;
	time (&seconds);

	err_msg("ipband received signal number <%i> ", cursig);
	err_msg("on %s",ctime(&seconds));
	}
	
	/* Explain why pipe broke */
	if (cursig == SIGPIPE)
	err_msg("SIGPIPE is received when writing to %s\n",mtastring_m);

}


/* Parse config file */
int read_config (char *filename) {
	FILE *fin = NULL;
	char buffer[512];
	char *str;
	char *key, *val;

	fin = fopen (filename, "r");
	if (NULL==fin)  return errno;

        while ( (str=fgets(buffer, 512, fin)) ) {

	get_two_tok(str, &key, &val);

	/*  Test for comment or empty line  */
	if (*key=='#' || *key=='\0') continue;

	/* Test for valid options */
	if (!strcmpi("debug",key)) {
		debug_m = atoi(val);

	} else if (!strcmpi("filter",key)) {
		filtercmd_m = strdup(val);	

	} else if (!strcmpi("fork",key)) {
		fork_m = is_true_str(val);	

	} else if (!strcmpi("outfile",key)) {
		repfname_m = strdup(val);

	} else if (!strcmpi("htmlfile",key)) {
		htmlfname_m = strdup(val);
		do_html = TRUE;

	} else if (!strcmpi("htmltitle",key)) {
		htmltitle_m = strdup(val);

	} else if (!strcmpi("interface",key)) {
		pcapdev_m = strdup(val);

	} else if (!strcmpi("promisc",key)) {
		promisc_m = is_true_str(val);

	} else if (!strcmpi("average",key)) {
		cycle_m = atoi(val);

	} else if (!strcmpi("bandwidth",key)) {
		thresh_m = (float) atof(val);

	} else if (!strcmpi("accumulate",key)) {
		report_aggr_m = is_true_str(val);	

	} else if (!strcmpi("report",key)) {
		rcycle_m = atoi(val);

	} else if (!strcmpi("localrange",key)) {
		parse_ip_range (val, &iplist_m, &niplist_m);

	} else if (!strcmpi("mailto",key)) {
		mailto_m = strdup(val);

	} else if (!strcmpi("mailfoot",key)) {
		mailfoot_m = strdup(val);

	} else if (!strcmpi("mtastring",key)) {
		mtastring_m = strdup(val);

	    /* Strip double-quotes that might be in the config file */
	    if( *mtastring_m == '\"' && mtastring_m[strlen(mtastring_m)-1] == '\"' ){
		mtastring_m++;
		mtastring_m[strlen(mtastring_m)-1] = '\0';	
	    }

	} else if (!strcmpi("maskbits",key)) {
		mask_m = atoi(val);

	} else if (!strcmpi("top",key)) {
		top_m = atoi(val);

	} else if (!strcmpi("lenadj",key)) {
		lenadj_m = atoi(val);

	} else if (!strcmpi("subnet",key)) {

		/* Set preload flag - we are now limited to specified nets
		   Will process option(s) later when subnet mask is known
		   for sure */
		preload_m = TRUE;

	} else {
		err_msg("ipband: Error reading ipband config file. ");
		err_msg("  Unrecognized option: \"%s\"", key);

	} /* End of test for options */

	} /* End of while () looping through config file */

	fclose(fin);

	return 1;
}


/* Process subnet options in config file */
int parse_subnets (char *filename, hlist_t **ha) {
	FILE *fin = NULL;
	char *str;
	char *key, *val;
	char buff[512];

	fin = fopen (filename, "r");
	if (NULL==fin)  return errno;

        while ( (str=fgets(buff, 512, fin)) ) {

	get_two_tok(str, &key, &val);

	/* Find subnet options and load it into hash table */
	if (!strcmpi("subnet",key)) preload_subnets(val,ha);

	}

	fclose(fin);

	return 1;

}


/* Build hash table for subnets to be monitored */
void preload_subnets(char *str, hlist_t **ha){

        U_CHAR 		key[9];     	/* Subnet key as hex string */
	aggr_data_t     *data,    idata;
	int        	datasize, keysize;
	int		ndata;
	float  		bwidth = 0.0;
	int    		p[4];
	int    		netip  = 0;
	char   		*buf   = (char *) malloc(strlen(str)+1);
	int    		i;

	/*  Break subnet option string into ip/bandwidth */
	if (6 != sscanf(str,"%d.%d.%d.%d%s%f",&p[0],&p[1],&p[2],&p[3], buf,&bwidth) ) {
	  err_msg("ipband: Error parsing subnet option in config file: %s\n",str);
	  free(buf);
	  return;
	}

	free(buf);

	/* Convert network address to integer */
	for(i=0; i<4; i++){
	   netip = netip<<8;
	   netip |= p[i];
	}

	/* Apply mask */
	netip &= mask_m;

	sprintf(key,"%08x",netip);

	/* Set bandwidth threshold for this net */
	idata.band = bwidth;

	/* Initialize all other fields */
	idata.nbyte = 0;
	idata.logtime = (time_t) 0;
	idata.exc_time = 0;
	idata.exc_accum = 0;

	/*  Set size of data structures  */
	datasize = sizeof(aggr_data_t);
	keysize  = sizeof(key);

	/* Add first instance to table */
	if(!hash_finddata(ha,(U_CHAR *)&key,keysize,(U_CHAR **)&data,&ndata)){
	datasize = sizeof(idata);
	hash_addnode(ha,(U_CHAR *)&key,keysize,(U_CHAR *)&idata,datasize);

	/* Key already present, update bandwidth */
	} else  {
	data->band = bwidth;
	}
}


/*  Set all options to default values */
void set_defaults(void) {

	debug_m       = FALSE;
	preload_m     = FALSE;
	report_aggr_m = FALSE;
	do_html       = FALSE;
	isig_m	      = 0;
	pcapoffset_m  = 0;

	started_m     = (time_t) 0;
	
	mask_m	      = 24;
	cycle_m	      = 60;
	rcycle_m      = 300;
	thresh_m      = 7.0;
	fork_m	      = FALSE;
	top_m	      = 0;
	promisc_m     = TRUE;
	niplist_m     = 0;
	lenadj_m      = 0;

	/* These were malloc'ed by strdup and can be freed */
	FREE(config_m);
	FREE(pcapdev_m);
	FREE(pcapfile_m);
	FREE(filtercmd_m);
	FREE(repfname_m);
	FREE(htmlfname_m);
	FREE(htmltitle_m);
	FREE(mailto_m);
	FREE(mailfoot_m);
	FREE(iplist_m);

	/* Reset MTA string to the default */
	FREE(mtastring_m);
	mtastring_m = strdup(MTASTR_DEF);

}


/* Get list of local networks */
void parse_ip_range (char *arg_in, int **iplist, int *niplist) {
	char *arg_cpy = (char *) malloc (strlen(arg_in)+1);
	char *ipstr   = (char *) malloc (strlen(arg_in)+1);
	char *netstr  = (char *) malloc (strlen(arg_in)+1);
	char *range1  = NULL;
	char *range2  = NULL;
	int  mask;
	int  net;
	int  ip1, ip2;
	int  n;
	char *p;

	*iplist = NULL;

	/*  Count number of ranges (equals number of : + 1 )  */
	p = arg_in;
	n = 1;
	while (*p++) {
		if (*p==':') n++;
	}

	/*  allocate storage  */
	*iplist = (int *) malloc (2 * n * sizeof(int));
	if (*iplist==NULL) {
		*niplist = 0;
		return;
	}

	strcpy  (arg_cpy, arg_in);
	range2 = arg_cpy;

	/*  break string into separate ranges  */
	*niplist = 0;
	while (NULL!=range2) {

		/*  Break arg into (1st range):(remaining ranges)  */
		range1 = range2;
		range2 = strchr(range1, ':');
		if (NULL!=range2) *range2++ = '\0';


		/*  Look for range expressed as (lo ip)-(hi ip)  */
	 	if (2==sscanf (range1, "%[0-9.]-%[0-9.]", ipstr, netstr)) {
			str2ip(ipstr,  &ip1, &mask);
			str2ip(netstr, &ip2, &mask);

		/*  break range into (ip)/(net)  */
		} else if (2==sscanf (range1, "%[0-9.]/%[0-9]", ipstr, netstr)) {

			/*  read ip address  */
			str2ip (ipstr, &ip1, &mask);

			net = atoi(netstr);
			if (net<0) net=0;
			else if (net>32) net=32;
			mask = 0xffffffff >> net;
			if (mask==-1) mask = 0;
			ip2 = ip1 | mask;

		/*  Look for single ip address  */
		} else if (sscanf (range1, "%[0-9.].%[0-9].", ipstr, netstr)) {
			str2ip (ipstr, &ip1, &mask);
			ip2 = ip1 | mask;

		/*  Bad input format  */
		} else {
		err_msg("ERROR:  Cannot read network range argument (-l option).\n");
		err_msg("  Program continues with using default network range.\n");
		*niplist = 0;
		if (NULL!=*iplist) free (*iplist);
		return;
		}

		/* Store results  */
		(*iplist)[(*niplist)++] = ip1;
		(*iplist)[(*niplist)++] = ip2;
	}

	free (netstr);
	free (ipstr);
	free (arg_cpy);

	/*  Correct double counting of niplist  */
	*niplist /= 2;

}

/*  Determine if ip addresse is within one of the ranges in iplist  */
int in_iprange (int ip, int *iplist, int niplist) {
	int i;
	for (i=0;i<2*niplist;i+=2)
	   if (ip>=iplist[i] && ip<=iplist[i+1])   return 1;
	return 0;
}


/* Check option values seem reasonable */
void check_invalues () {

	if( cycle_m < 1 ) 
	 err_quit("ERROR: Averaging period  must be positive integer\n");

	if( thresh_m < 0.0 ) 
	  err_quit("ERROR: Negative banwidth threshold\n");

	if( (mask_m < 0) || (mask_m > 32)) 
	   err_quit("ERROR: invalid number of mask bits\n");

	if( rcycle_m < cycle_m ) 
	   err_quit("ERROR: reporting period cannot be less then averaging period\n");

	if( (top_m < 0) ) 
	   err_quit("ERROR: negative per-host connection report limit\n");

}
