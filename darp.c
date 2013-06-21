/*
 * darp
 * Dave's ARP cmd
 * Very similar with the famous Linux arp cmd
 * Reference: busybox
 * http://git.busybox.net/busybox/tree/networking/arp.c
 * daveti@cs.uoregon.edu
 * http://daveti.blog.com
 * June 20, 2013
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_LEN	128

/*
 * Global variables
 */
static int debug_flag = 0;
static int socket_fd;
static char default_device[BUFFER_LEN] = "em1";

/*
 *  * Debug dump
 *   */
static void darp_debug_dump(char *s)
{
        if (debug_flag == 1)
        {
                printf("debug: %s\n", s);
        }
}

/*
 * Display the usage of darp
 */
static void darp_display_usage()
{
	printf("darp -a:\n");
	printf("\tdisplay all the entries within the ARP cache\n");
	printf("darp -v:\n");
	printf("\tenable/disable verbose mode\n");
	printf("darp -i <interface>:\n");
	printf("\tchange the default name of network interface\n");
	printf("darp -d <IP>:\n");
	printf("\tremove the entry with this IP address\n");
	printf("darp -g <IP>:\n");
	printf("\tget the entry with this IP address\n");
	printf("darp -s <IP> <MAC>:\n");
	printf("\tadd an entry into the ARP cache with this IP and MAC addresses\n");
	printf("darp -h:\n");
	printf("\tdisplay the usage menu\n");
}

/*
 * Enable/disable the verbose mode
 */
static void darp_debug()
{
	/* Enable the debugging */
	debug_flag = 1;
}

/*
 * Change the default device
 * On Fedora 18, the default device is 'em1';
 * however, 'eth0' may be much more common...
 */
static void darp_change_device(char *device)
{
	snprintf(default_device, sizeof(default_device), "%s", device);
}

/*
 * Convert the string based MAC address into unsigned char array
 */
static void darp_mac_aton(char *mac, unsigned char *dst)
{
	int i;
	int rtn;
	unsigned int p[6];

	rtn = sscanf(mac, "%x:%x:%x:%x:%x:%x",
			&p[0], &p[1], &p[2],
			&p[3], &p[4], &p[5]);
	if (rtn != 6)
	{
		fprintf(stderr, "parsing MAC failure: %s\n", mac);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < 6; i++)
	{
		dst[i] = (unsigned char)p[i];
	}
}

/*
 * Display all the entries within the ARP cache
 * by reading '/proc/net/arp'
 * The output is similar with 'arp -a'
 */
static void darp_display_all()
{
	struct sockaddr_in sa;
	int hw_type;
	int flags;
	char ip_addr[BUFFER_LEN];
	char hw_addr[BUFFER_LEN];
	char mask[BUFFER_LEN];
	char device[BUFFER_LEN];
	char line[BUFFER_LEN*2];
	char hostname[BUFFER_LEN];
	char hardname[BUFFER_LEN];
	char service[BUFFER_LEN];
	FILE *fp;
	int rtn;
	int omitMac;

	/* Open the file */
	fp = fopen("/proc/net/arp", "r");
	
	/* Bypass the header */
	fgets(line, sizeof(line), fp);
	darp_debug_dump(line);

	/* Read the entries from the proc */
	while (fgets(line, sizeof(line), fp))
	{
		/* Init all the buffers */
		memset(ip_addr, 0, sizeof(ip_addr));
		memset(hw_addr, 0, sizeof(hw_addr));
		memset(mask, 0, sizeof(mask));
		memset(device, 0, sizeof(device));
		memset(hostname, 0, sizeof(hostname));
		memset(hardname, 0, sizeof(hardname));
		memset(service, 0, sizeof(service));
		memset(&sa, 0, sizeof(sa));
		omitMac = 0;

		/* Read it, Man! */
		rtn = sscanf(line, "%s 0x%x 0x%x %s %s %s\n",
				ip_addr, &hw_type, &flags, hw_addr, mask, device);

		/* Get the hostname from the IP address */
		sa.sin_family = AF_INET;
		inet_pton(AF_INET, ip_addr, &(sa.sin_addr));
		getnameinfo((struct sockaddr *)&sa, sizeof(sa), hostname, sizeof(hostname),
				service, sizeof(service), 0);
		darp_debug_dump(hostname);
		darp_debug_dump(service);

		/*
 		 * There should be a way to get the device name from the hw_type
 		 * Maybe the rtnetlink.....
 		 * Right now, hard code it!
 		 */

		/* Fill the hardware name from the ARP flags */
		if (!(flags & ATF_COM))
		{
			if (flags & ATF_PUBL)
			{
				snprintf(hardname, sizeof(hardname), "\%s", "*");
			}
			else
			{
				snprintf(hardname, sizeof(hardname), "%s", "<incomplete>");
			}
			omitMac = 1;
		}
		else
		{
			/* Hard code the hardware name here */
			snprintf(hardname, sizeof(hardname), "%s", "[ether]");
		}

		/*
 		 * NOTE: we do not handle mask here - probably in future...
 		 */

		if (omitMac == 1)
		{
			printf("%s (%s) at %s on %s\n",
				hostname, ip_addr, hardname, device);
		}
		else
		{
			printf("%s (%s) at %s %s on %s\n",
				hostname, ip_addr, hw_addr, hardname, device);
		}
	}

	fclose(fp);
}

/*
 * Remove the entry with the IP address
 */
static int darp_delete_entry(char *ip)
{
	int rtn;
	struct arpreq arpReq;
	struct sockaddr_in *sa;
	sa = (struct sockaddr_in *)&(arpReq.arp_pa);

	/* Init the ARP request */
	memset(&arpReq, 0, sizeof(arpReq));
	sa->sin_family = AF_INET;
	inet_pton(AF_INET, ip, &(sa->sin_addr));
	strncpy(arpReq.arp_dev, default_device, sizeof(arpReq.arp_dev)-1);
	darp_debug_dump(arpReq.arp_dev);

	/* Issue the ARP request to the kernel */
	rtn = ioctl(socket_fd, SIOCDARP, &arpReq);
	if (rtn < 0)
	{
		fprintf(stderr, "delete ARP entry failure: %s\n", strerror(errno));
	}
	
	return 0;
}

/*
 * Get the entry with the IP address
 */
static int darp_get_entry(char *ip)
{
	int rtn;
	unsigned char *mac;
	struct arpreq arpReq;
	struct sockaddr_in *sa;
	sa = (struct sockaddr_in *)&(arpReq.arp_pa);

	/* Init the ARP request */
	memset(&arpReq, 0, sizeof(arpReq));
	sa->sin_family = AF_INET;
	inet_pton(AF_INET, ip, &(sa->sin_addr));
	strncpy(arpReq.arp_dev, default_device, sizeof(arpReq.arp_dev)-1);
	darp_debug_dump(arpReq.arp_dev);

	/* Issue the ARP request to the kernel */
	rtn = ioctl(socket_fd, SIOCGARP, &arpReq);
	if (rtn < 0)
	{
		fprintf(stderr, "get ARP entry failure: %s\n", strerror(errno));
	}
	else
	{
		/* Retrive the hardware address (MAC) for this IP */
		if (arpReq.arp_flags & ATF_COM)
		{
			mac = (unsigned char *)arpReq.arp_ha.sa_data;
			printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		}
		else
		{
			printf("MAC: incomplete\n");
		}

		/*
 		 * NOTE: other flags checking is omitted here...
 		 */
	}
	
	return 0;
}

/*
 * Set/add an entry with the IP and MAC addresses
 */
static int darp_set_entry(char *ip, char *mac)
{
	int rtn;
	struct arpreq arpReq;
	struct sockaddr_in *sa;
	sa = (struct sockaddr_in *)&(arpReq.arp_pa);

	/* Init the ARP request */
	memset(&arpReq, 0, sizeof(arpReq));
	sa->sin_family = AF_INET;
	inet_pton(AF_INET, ip, &(sa->sin_addr));
	strncpy(arpReq.arp_dev, default_device, sizeof(arpReq.arp_dev)-1);
	darp_debug_dump(arpReq.arp_dev);

	/* Set the MAC address and the flags */
	darp_mac_aton(mac, arpReq.arp_ha.sa_data);
	arpReq.arp_flags = ATF_PERM | ATF_COM;

	/* Issue the ARP request to the kernel */
	rtn = ioctl(socket_fd, SIOCSARP, &arpReq);
	if (rtn < 0)
	{
		fprintf(stderr, "set ARP entry failure: %s\n", strerror(errno));
	}

	return 0;
}

/*
 * darp - main function
 */
int main(int argc, char **argv)
{
	int isInsert = 0;
	char *ip;
	int opt;

	/* Set the socket */
	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_fd < 0)
	{
		fprintf(stderr, "socket open failure: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Process the arguments */
	while ((opt = getopt(argc, argv, "vhai:g:d:s:")) != -1)
	{
		switch (opt)
		{
			case 'v':
				darp_debug();
				break;
			case 'h':
				darp_display_usage();
				break;
			case 'i':
				darp_debug_dump(optarg);
				darp_change_device(optarg);
				break;
			case 'a':
				darp_display_all();
				break;
			case 'g':
				darp_debug_dump(optarg);
				darp_get_entry(optarg);
				break;
			case 'd':
				darp_debug_dump(optarg);
				darp_delete_entry(optarg);
				break;
			case 's':
				/* NOTE: for option s, need to hack here
 				 * and always assume this is the last option
 				 */
				darp_debug_dump(optarg);
				isInsert = 1;
				ip = optarg;
				break;	
			default:
				isInsert = 0;
				fprintf(stderr, "getopt failure: please run 'darp -h' for the usage\n");
				break;
		}
	}

	/* Get the extra argument for MAC address */
	if (isInsert == 1)
	{
		darp_debug_dump(argv[optind]);
		darp_set_entry(ip, argv[optind]);
	}

	/* Exit gracefully */
	close(socket_fd);
	return 0;
}
