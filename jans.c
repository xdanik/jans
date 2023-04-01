/* released under GPLv2 by folkert@vanheusden.com */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "error.h"

#define NTP_EPOCH            (86400U * (365U * 70U + 17U))
#define NTP_PORT             123

int verbose = 0;
struct timeval start_ts;
long int secs_random, fraq_random;

typedef enum { tt_real, tt_constant, tt_constant_w_noise, tt_random, tt_backwards } tt_t;

struct gen_header
{
        unsigned char mode : 3;
        unsigned char vn : 3;
        unsigned char li : 2;
};

struct sntp_datagram
{
        unsigned char mode : 3;
        unsigned char vn : 3;
        unsigned char li : 2;
	/* data */
        unsigned char stratum;
        char poll;
        char precision;
        u_int32_t root_delay;
        u_int32_t root_dispersion;
        u_int32_t reference_identifier;
        u_int32_t reference_timestamp_secs;
        u_int32_t reference_timestamp_fraq;
        u_int32_t originate_timestamp_secs;
        u_int32_t originate_timestamp_fraq;
        u_int32_t receive_timestamp_seqs;
        u_int32_t receive_timestamp_fraq;
        u_int32_t transmit_timestamp_secs;
        u_int32_t transmit_timestamp_fraq;
};

struct ntp_control_datagram
{
        unsigned char mode : 3;
        unsigned char vn : 3;
        unsigned char li : 2;
	/* data */
	unsigned char operation_code : 5;
	unsigned char more_bit : 1;
	unsigned char error_bit : 1;
	unsigned char response_bit : 1;
        u_short sequence;               /* sequence number of request */
        u_short status;                 /* status word for association */
        u_short associd;              /* association ID */
        u_short offset;                 /* offset of this batch of data */
        u_short count;                  /* count of data in this packet */
        unsigned char data[0]; /* data + auth */
};

void print_time(char *msg, u_int32_t secs, u_int32_t fraq)
{
	char *str, *dummy;
	time_t when;

	printf("%s", msg);

	when = ntohl(secs) - NTP_EPOCH;
	str = ctime(&when);
	dummy = strchr(str, '\n');
	if (dummy)
		*dummy = 0x00;
	printf("%s.%f\n", str, ((double)ntohl(fraq)) / (4295.0 * 1000000.0));
}

int myrandom_limit(int max)
{
	int value = lrand48() % max;

	return value;
}

int myrandom()
{
	return lrand48() &0xffffffff;
}

void set_time(u_int32_t *secs, u_int32_t *fraq, tt_t time_type)
{
	struct timeval ts;

	if (time_type == tt_real)
	{
		if (gettimeofday(&ts, NULL) == -1)
			error_exit("gettimeofday() failed");

		*secs = htonl(ts.tv_sec + NTP_EPOCH);
		*fraq = htonl(ts.tv_usec * 4295);
	}
	else if (time_type == tt_constant || time_type == tt_constant_w_noise)
	{
		*secs = htonl(start_ts.tv_sec + NTP_EPOCH);

		if (time_type == tt_constant)
			*fraq = htonl(start_ts.tv_usec * 4295);
		else
			*fraq = htonl(start_ts.tv_usec * 4295 + myrandom_limit(32768) - 16384);
	}
	else if (time_type == tt_random)
	{
		*secs = secs_random;
		*fraq = fraq_random;
	}
	else if (time_type == tt_backwards)
	{
		*secs = htonl(start_ts.tv_sec + NTP_EPOCH);
		*fraq = htonl(start_ts.tv_usec * 4295);
	}
}

void loop(int fd, int stratum, int precision, tt_t time_type, int poll_interval, double backwards, char *refid, int root_delay, int root_dispersion)
{
	char *mode[] = { "RESERVED", "symmetric", "?", "client", "server", "broadcast", "NTP control message", "?" };
	char *li[] = { "no warning", "last minute has 61 seconds", "last minute has 59 seconds", "alarm (clock not synced)" };
	char *operation[] = { "reserved", "read status", "read variables", "write variables", "read clock variables", "write clock variables", "set trap address/port command/response", "trap response", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31" };

	for(;;)
	{
		int loop;
		char identifier[5];
		char msgbufferin[512], msgbufferout[512];
		struct sntp_datagram *msgin = NULL, msgout;
		struct gen_header *header;
		struct ntp_control_datagram *ncdin;
		struct sockaddr_in from;
		socklen_t fromlen = sizeof(from);
		ssize_t msglen;

		memset(&msgout, 0x00, sizeof(msgout));
		memset(msgbufferin, 0x00, sizeof(msgbufferin));

		/**** RECEIVE MESSAGE ***/
		msglen = recvfrom(fd, msgbufferin, sizeof(msgbufferin), 0, (struct sockaddr *)&from, &fromlen);
		if (msglen == -1)
		{
			if (errno == EINTR)
				continue;
			error_exit("recv failed");
		}

		header = (struct gen_header *)msgbufferin;

		if (verbose)
		{
			printf("%s:%d (%d bytes)\n", inet_ntoa(from.sin_addr), from.sin_port, msglen);
			printf(" mode: %d (%s), vn: %d, li: %d (%s)\n", header -> mode, mode[header -> mode], header -> vn, header -> li, li[header -> li]);
		}

		if (header -> mode == 1 || header -> mode == 3 || header -> mode == 5)	/* requesting time & broadcasts */
		{
			msgin = (struct sntp_datagram *)msgbufferin;

			set_time(&msgout.receive_timestamp_seqs, &msgout.receive_timestamp_fraq, time_type);

			if (verbose)
			{
				printf(" stratum: %d, poll: %d, precision: %d\n", msgin -> stratum, msgin -> poll, msgin -> precision);
				identifier[4] = 0x00;
				memcpy(identifier, &msgin -> reference_identifier, 4);
				for(loop=0; loop<4; loop++)
				{
					if (identifier[loop] < 32 || identifier[loop] > 126)
						identifier[loop] = ' ';
				}
				printf(" delay: %d, dispersion: %d, identifier: '%s' (%s)\n", msgin -> root_delay, msgin -> root_dispersion, identifier, msgin -> stratum == 1 ? "valid" : "not valid");
				print_time(" reference: ", msgin -> reference_timestamp_secs, msgin -> reference_timestamp_fraq);
				print_time(" originate: ", msgin -> originate_timestamp_secs, msgin -> originate_timestamp_fraq);
				print_time(" receive: ", msgin -> receive_timestamp_seqs, msgin -> receive_timestamp_fraq);
				print_time(" transmit: ", msgin -> transmit_timestamp_secs, msgin -> transmit_timestamp_fraq);
			}
		}
		else if (header -> mode == 6)			/* ntp control message */
		{
			int index, count;

			ncdin = (struct ntp_control_datagram *)msgbufferin;

			printf(" response: %d, error: %d, more: %d, operation: %d (%s)\n", ncdin -> response_bit, ncdin -> error_bit, ncdin -> more_bit, ncdin -> operation_code, operation[ncdin -> operation_code]);
			count = ntohs(ncdin -> count);
			printf(" sequence: %d, status: %d, association id: %d, offset: %d, count: %d\n", ntohs(ncdin -> sequence), ntohs(ncdin -> status), ntohs(ncdin -> associd), ntohs(ncdin -> offset), count);
			if (count)
				printf(" data:\n ");
			for(index=0; index<count; index++)
			{
				unsigned char cur = (ncdin -> data)[index];

				if (cur < 33 || cur > 126)
					printf(". %02x, ", cur);
				else
					printf("%c %02x, ", cur, cur);

				if (index % 15 == 0)
					printf("\n ");
			}
			if (index % 15)
				printf("\n");
		}

		/**** SEND REPLY ****/
		if (header -> mode == 1 || header -> mode == 3) /* 1: symmetric, 3: client */
		{
			if (verbose) printf("Send reply\n");

			/* send */
			msgout.li = 0;
			msgout.mode = msgin -> mode == 1 ? 1 : 4; /* 4: server */
			msgout.vn = 3;
			msgout.precision = precision;
			msgout.stratum = stratum;
			msgout.root_delay = root_delay;
			msgout.root_dispersion = root_dispersion;
			msgout.poll = poll_interval;
			memcpy(&msgout.reference_identifier, refid, 4);
			msgout.originate_timestamp_secs = msgin -> transmit_timestamp_secs;
			msgout.originate_timestamp_fraq = msgin -> transmit_timestamp_fraq;
			set_time(&msgout.reference_timestamp_secs, &msgout.reference_timestamp_fraq, time_type);
			set_time(&msgout.transmit_timestamp_secs, &msgout.transmit_timestamp_fraq, time_type);

			if (sendto(fd, &msgout, sizeof(msgout), 0, (struct sockaddr *)&from, sizeof(from)) == -1)
				fprintf(stderr, "Failed sending reply: %s\n", strerror(errno));

			if (time_type == tt_random)
			{
				secs_random = myrandom();
				fraq_random = myrandom();
			}
			else if (time_type == tt_backwards)
			{
				double cur = (((double)start_ts.tv_sec) + ((double)start_ts.tv_usec)/1000000.0);
				cur -= backwards;
				start_ts.tv_sec = (int)cur;
				start_ts.tv_usec = (suseconds_t)((cur - (double)start_ts.tv_sec) * 1000000.0);
			}
		}
		else if (header -> mode == 6)	/* NTP control message */
		{
			int len, datalen = 0;
			struct ntp_control_datagram *ncdout = (struct ntp_control_datagram *)msgbufferout;

			ncdout -> mode = 6;
			ncdout -> vn = 3;
			ncdout -> li = 0;

			ncdout -> response_bit = 1;
			ncdout -> error_bit = 0;
			ncdout -> more_bit = 0;
			ncdout -> operation_code = ncdin -> operation_code;
			ncdout -> sequence = ncdin -> sequence;
			ncdout -> associd = ncdin -> associd;
			ncdout -> offset = 0;

			if (ncdin -> operation_code == 1)	/* read status */
			{
				((short *)ncdout -> data)[0] = htons(1);	/* only association value available */
				((short *)ncdout -> data)[1] = htons(0xffff);	/* bits */
				datalen = 4;
			}
			else if (ncdin -> operation_code == 2)	/* read variables */
			{
				if (ntohs(ncdout -> associd) == 1)
				{
					sprintf(ncdout -> data, "srcadr=127.127.8.0, srcport=123, dstadr=127.0.0.1, dstport=123, leap=0, stratum=0, precision=-23, rootdelay=0.000, rootdisp=0.000, refid=POEP, reftime=0xd0190943.00000000, rec=0xd0190943.468980ec, reach=0xff, unreach=0, hmode=3, pmode=4, hpoll=6, ppoll=10, headway=0, flash=0x0, keyid=0, ttl=0, offset=-16.908, delay=0.000, dispersion=1.658, jitter=0.548");
					datalen = strlen(ncdout -> data) + 1;
				}
			}
			else
			{
				memcpy(ncdout -> data, "poep is vies\n", 12);
				datalen = 12;
			}

			ncdout -> count = htons(datalen);

			len = sizeof(struct ntp_control_datagram) + datalen;
			if (verbose) printf("Send reply (%d bytes)\n", len);
			if (sendto(fd, ncdout, len, 0, (struct sockaddr *)&from, sizeof(from)) == -1)
				fprintf(stderr, "Failed sending reply: %s\n", strerror(errno));
		}
	}
}

int create_socket(char *adapter, int port)
{
	struct sockaddr_in lsa;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd == -1)
		error_exit("failed creating socket");

	memset((char *)&lsa, '\0', sizeof(lsa));
	lsa.sin_family = AF_INET;
	if (inet_aton(adapter, &lsa.sin_addr) == 0)
		error_exit("%s is not a valid ip-address of an adapter to listen on", adapter);
	lsa.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *)&lsa, sizeof(struct sockaddr)) == -1)
		error_exit("bind failed");

	return fd;
}

void version(void)
{
	fprintf(stderr, "Jans v" VERSION ", (C) 2010 by folkert@vanheusden.com\n\n");
}

void help(void)
{
	fprintf(stderr, "-I adapter   adapter to listen on (default is all)\n");
	fprintf(stderr, "-P port      port to listen on. default is 123\n");
	fprintf(stderr, "-s x         set advertised stratum (default is 5, set to 0 for a \"kiss-of-death\" (KoD))\n");
	fprintf(stderr, "-R x         ASCII string (max 4 characters) defining the \"reference identifier\" field. NTPd will only assume this field to be a string if the stratum is 1, see RFC4330 for a list of proposed strings\n");
	fprintf(stderr, "-p x         set advertised precision (default is -6)\n");
	fprintf(stderr, "-d x         root delay\n");
	fprintf(stderr, "-D x         root dispersion\n");
	fprintf(stderr, "-t x         what type of time to server:\n");
	fprintf(stderr, "             - real: current system time\n");
	fprintf(stderr, "             - constant: the time this program started\n");
	fprintf(stderr, "             - constant_noise: the time this program started with a little noise in the fraction\n");
	fprintf(stderr, "             - random\n");
	fprintf(stderr, "             - backwards: time going backwards, starting at program start timestamp\n");
	fprintf(stderr, "-b x         how many seconds per poll to step the time backwards\n");
	fprintf(stderr, "-i x         set poll-interval. 6 means 2^6 = 64 seconds\n");
	fprintf(stderr, "-V           show version & exit\n");
	fprintf(stderr, "-h           this help\n");
	fprintf(stderr, "-v           increase verbosity\n");
}

int main(int argc, char *argv[])
{
	char *adapter = "0.0.0.0";
	int port = NTP_PORT;
	int fd;
	int stratum = 5;
	int precision = -6;
	int c;
	char fork = 0;
	tt_t time_type = tt_real;
	int poll_interval = 6;
	double backwards = 0.1;
	char refid[4] = { 0x00, 0x06, 0x06, 0x06 };
	int root_delay = 369098752;	/* arbitrary */
	int root_dispersion = 369098752;	/* arbitrary */

	while((c = getopt(argc, argv, "d:D:R:b:I:P:t:s:i:p:hVv")) != -1)
	{
		switch(c)
		{
			case 'd':
				root_delay = atoi(optarg);
				break;

			case 'D':
				root_dispersion = atoi(optarg);
				break;

			case 'R':
				memset(refid, 0x00, sizeof(refid));
				memcpy(refid, optarg, strlen(optarg));
				break;

			case 'b':
				backwards = atof(optarg);
				break;

			case 'i':
				poll_interval = atoi(optarg);
				break;

			case 't':
				if (strcasecmp(optarg, "real") == 0)
					time_type = tt_real;
				else if (strcasecmp(optarg, "constant") == 0)
					time_type = tt_constant;
				else if (strcasecmp(optarg, "constant_noise") == 0)
					time_type = tt_constant_w_noise;
				else if (strcasecmp(optarg, "random") == 0)
					time_type = tt_random;
				else if (strcasecmp(optarg, "backwards") == 0)
					time_type = tt_backwards;
				else
					error_exit("Time-type '%s' is not understood", optarg);
				break;

			case 's':
				stratum = atoi(optarg);
				break;

			case 'p':
				precision = atoi(optarg);
				break;

			case 'I':
				adapter = optarg;
				break;

			case 'P':
				port = atoi(optarg);
				break;

			case 'v':
				verbose++;
				break;

			case 'h':
				help();
				return 0;

			case 'V':
				version();
				return 0;

			default:
				version();
				help();
				return 1;
		}
	}

	if (verbose)
		version();

	gettimeofday(&start_ts, NULL);

	srand48(start_ts.tv_sec ^ start_ts.tv_usec);

	fd = create_socket(adapter, port);

	if (fork)
	{
		if (daemon(-1, -1) == -1)
			error_exit("Failed forking into background");
	}

	loop(fd, stratum, precision, time_type, poll_interval, backwards, refid, root_delay, root_dispersion);

	return 0;
}
