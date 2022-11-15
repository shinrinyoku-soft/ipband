/* pcapfunc.c		pcap related routines
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


void open_interface (int promisc) {

	struct bpf_program  fcode;
	char   ebuf[PCAP_ERRBUF_SIZE];

	pcapfile_m = pcap_open_live(pcapdev_m, PLEN, promisc, 1000, ebuf);

	if (pcapfile_m==NULL) {
	printf("ipband: Trouble opening <%s>, msg=\"%s\"\n",
			pcapdev_m, ebuf);
	exit(1);
	}

	/*  Find IP header offset  */
	pcapoffset_m = get_packetoffset(pcap_datalink(pcapfile_m));
	
	/*  Apply user requested packet filter code */
	if (pcap_compile(pcapfile_m, &fcode, filtercmd_m, 0, 0) < 0)
		printf("compile: %s", pcap_geterr(pcapfile_m));
	if (pcap_setfilter(pcapfile_m, &fcode) < 0)
		printf("setfilter:  %s", pcap_geterr(pcapfile_m));

	/*  Problem with pcap_setfilter?  Sets error, unset here  */
	errno = 0;

}

/* Return IP header offset depending on the interface type */
int get_packetoffset (int DataLinkType) {

	int PacketOffset;
	
	switch (DataLinkType) {
		case DLT_EN10MB:
		case DLT_IEEE802:
			PacketOffset = POFF_ETH;
			break;
		case DLT_PPP:
			PacketOffset = POFF_PPP;
			break;
		case DLT_RAW:
			PacketOffset = POFF_RAW;
			break;
		/* For others we guess  */
		default:
			PacketOffset = 0;
		}

	return PacketOffset;
}

/* Prints datalink type */
void print_datalink() {

printf ("Interface (%s) ", pcapdev_m);
switch (pcap_datalink(pcapfile_m)) {
case DLT_EN10MB:      printf ("DataLinkType = %s\n", "DLT_EN10MB"); break;
case DLT_IEEE802:     printf ("DataLinkType = %s\n", "DLT_IEEE802"); break;
case DLT_SLIP:        printf ("DataLinkType = %s\n", "DLT_SLIP"); break;
case DLT_SLIP_BSDOS:  printf ("DataLinkType = %s\n", "DLT_SLIP_BSDOS"); break;
case DLT_PPP:         printf ("DataLinkType = %s\n", "DLT_PPP"); break;
case DLT_PPP_BSDOS:   printf ("DataLinkType = %s\n", "DLT_PPP_BSDOS"); break;
case DLT_FDDI:        printf ("DataLinkType = %s\n", "DLT_FDDI"); break;
case DLT_NULL:        printf ("DataLinkType = %s\n", "DLT_NULL"); break;
case DLT_RAW:         printf ("DataLinkType = %s\n", "DLT_RAW"); break;
case DLT_ATM_RFC1483: printf ("DataLinkType = %s\n", "DLT_ATM_RFC1483"); break;
default:              printf ("DataLinkType = %d\n", pcap_datalink(pcapfile_m));
}

printf("\n");

}


