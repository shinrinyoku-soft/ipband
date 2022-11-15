/* main.c
 *
 * ipband - network bandwidth watchdog
 * By Andrew Nevynniy
 *
 * Much of the code is based on ipaudit by Jon Rifkin <jon.rifkin@uconn.edu>
 *
 * Thanks to Nic Bellamy for promisc mode on/off and variable type correction
 * patch.
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


/* Initialize here and not in set_defaults() in case the latter called
   _after_ the structures are created */
ll_srvc_t *ll_tcp_cache = NULL;         /* Resolved tcp services cache */
ll_srvc_t *ll_udp_cache = NULL;         /* Resolved udp services cache */



int main (int argc, char *argv[]) {

        struct pcap_pkthdr pkthdr;
	U_CHAR *raw_pkt_save  = NULL;
        U_CHAR *raw_pkt       = NULL;
        hlist_t **hconn       = NULL;	/* subnet aggreg connection table */
        hlist_t **hconn_d     = NULL;	/* subnet detail connection table */
	fd_set rdfs;
	int fd;
	int retval;
	pid_t pid;
	eth_struct_t *eth_pkt = NULL;
	ip_struct_t  *ip_pkt  = NULL;
	time_t t0, t1;
	char *config_name_def = CONFIG_DEF;

	/*  Initialize global variables */
	set_defaults();

        /*  Initialize aggregate and detail hash tables  */
	hconn   = hash_init();
        hconn_d = hash_init();

	/*  Read default config file */
	config_m = strdup(config_name_def);
	read_config(config_m);

	/*  Read command line options (override config file) and interface */
	read_options(argc, argv);

	/*  Check if option values are reasonable */
	check_invalues();

	/*  Record application start time */
	started_m = time(NULL);

	/* Print all options for debug */
	if (debug_m) dump_options();

	/*  Check for interface  */
	if( 1 == (argc-optind) ) {
	pcapdev_m = strdup(argv[optind]);
	}
	if( !pcapdev_m) {
	print_usage();
	return(1);
	}

	/* Try to fork */
	if (fork_m) {
	   switch (pid = fork()) {
	     case 0:			/* Child */

		setsid();       	/* Become session leader */
		chdir("/");     	/* Don't hold on to current dir */

		{               	/* Close all file descriptors */
			int fd = 0;
			int maxfd = open_max();
			while (fd < maxfd) close(fd++);
		}
		/* New descriptors for stdin, stdout & stderr */
		open("/dev/null",O_RDWR);
		dup(0); dup(0);
		     
		break;
	     case -1:
		printf("Couldn't run in background, exiting...\n");
		exit(1);
	     default:			/* Parent */
		/* printf("Running in background...%d\n",(int) pid); */
		exit(0);
	   }
	}

	/* Convert number of mask bits to mask in hex */
	if (mask_m == 32) { 		/* Ugly */
		mask_m = 0xffffffff;
	} else {
		mask_m = 0xffffffff >> mask_m;
		mask_m ^= 0xffffffff;
	}

	/*  If subnet option was specified in config file we will now
	    read config file one more time and add subnet data to the table.
	    We couldn't do this before since there was no guarantee that
	    subnet mask appeared before subnets list in the file */
	if (preload_m) parse_subnets(config_m,hconn);

	/*  Open pcap file  */
        open_interface(promisc_m);

	/*  Print datalink type as returned by pcap */
	if (debug_m) print_datalink();

	/*  Now we have MAC frame size and can check it against frame size
	 *  adjustment option value */
	if( -lenadj_m > pcapoffset_m )
	err_quit("ERROR: absolute value of frame length adjustment is greater then layer 2 frame size for the interface\n");

        /*  Allocate room for saved raw packet  */
        raw_pkt_save = (U_CHAR *) malloc (PLEN);
	
        /*  Install interupt handler */
        signal (SIGINT,    ihandler);   /*  intercepts ^C           */
        signal (SIGTERM,   ihandler);   /*  intercepts ^kill <PID>  */
        signal (SIGPIPE,   ihandler);   /*  intercepts broken pipe  */

	/*  Initialize info for select(). Using select here as we might
	    add multiple interfaces later */
	FD_ZERO (&rdfs);
        fd = pcap_fileno(pcapfile_m);
        FD_SET (fd, &rdfs);

	/*  Record cycle start time */
	t0 = time(NULL);

        /*  Read packets until interupt signal */
        while (isig_m == 0) {

        /*  Wait for packet on one of the interfaces  */
        retval = select (fd+1, &rdfs, NULL, NULL, NULL);

	/*  If user interupt caught during select() call, retval will
	    be <0.  By continuing we re-test isig_m which should now
	    be set by the interupt handler
	 */
	if (retval<0) continue;

	/*  Read packet */
	raw_pkt = (U_CHAR *) pcap_next (pcapfile_m, &pkthdr);
        if (raw_pkt==NULL) continue;

	/*  Skip this packet if ethernet and not ip  */
	if (pcapoffset_m==POFF_ETH) {
	   eth_pkt = (eth_struct_t *) raw_pkt;
	   if (! (eth_pkt->ptype[0]==8 && eth_pkt->ptype[1]==0) ) continue;
	}

	/*  Find pointer to ip packet  */
	ip_pkt = (ip_struct_t *) (raw_pkt + pcapoffset_m);

	/*  Dump packet contents if debugging */
	if (3==debug_m) {
	unsigned int ibyte;
	int iwidth;
	printf ("Raw packet length %d ", pkthdr.len);
	if (lenadj_m) {
	   printf ("(%d after adjustment)", pkthdr.len + lenadj_m);
	}
	printf ("\n");
	printf ("Captured bytes (%d) ...\n", pkthdr.caplen);
	iwidth=0;
	for (ibyte=0;ibyte<pkthdr.caplen;ibyte++) {
		printf (" %03d", raw_pkt[ibyte]);
		if (++iwidth==16) {
			printf ("\n");
			iwidth=0;
			}
		}
		printf ("\n\n");
	}

 	/*  Set ports to 0 if not UDP or TCP  */
	if ( ip_pkt->prot[0]!=0x11 && ip_pkt->prot[0]!=0x06 ) {
		if (ip_pkt->prot[0]==1) {
			memset (ip_pkt->dstpt, 0, 2);
		} else {
			memset (ip_pkt->srcpt, 0, 2);
			memset (ip_pkt->dstpt, 0, 2);
        	}
	}

	/*  Dump packet ip data if debugging */
	if (3==debug_m) {
	printf ("*%03d.%03d.%03d.%03d -> %03d.%03d.%03d.%03d  %3d %5d %5d\n\n",
	ip_pkt->srcip[0],ip_pkt->srcip[1],ip_pkt->srcip[2],ip_pkt->srcip[3],
	ip_pkt->dstip[0],ip_pkt->dstip[1],ip_pkt->dstip[2],ip_pkt->dstip[3],
	ip_pkt->prot[0],
	ip_pkt->srcpt[0]*256+ip_pkt->srcpt[1],
	ip_pkt->dstpt[0]*256+ip_pkt->dstpt[1]);
	}

	/*  Store packets in the hash tables */
	storepkt(&pkthdr, ip_pkt, hconn, hconn_d);

	/* In the end of the loop check if it's time to check aggregate
	   table for bandwidth usage, reset the table and start
	   logging individual subnets */
	t1 = time(NULL);
	if ( (int) difftime(t1,t0) >= cycle_m) {
	   t0 = t1;
	   proc_aggr(hconn, hconn_d); 		/*  Process aggregate table  */
	 }


	} 	/* end of main loop (isig_m == 0) */


	/*  Close files  */
	pcap_close(pcapfile_m);

	/*  Clear error if breaking during pcap call  */
	errno = 0;


exit(0);

}

