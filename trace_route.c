// almost final submission - removed all unnecessary printfs
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>


#define SEQ "NetProgSEQ"	// Last domain

#define L_PORT 4400		// Listen Port
int L_FD;			// Listen FD
int C_FD;			// FD for client
int RQ;				// Request number of each request
#define MAX_TTL 30
#define PACKET_SIZE 512
int my_num = 0;

#define	MAXPACKET	65535	
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN	64
#endif

#ifndef FD_SET
#define NFDBITS         (8*sizeof(fd_set))
#define FD_SETSIZE      NFDBITS
#define FD_SET(n, p)    ((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define FD_CLR(n, p)    ((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define FD_ISSET(n, p)  ((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)      bzero((char *)(p), sizeof(*(p)))
#endif

#define Fprintf (void)fprintf
#define Sprintf (void)sprintf
#define Printf (void)printf


struct opacket {
	struct ip ip;
	struct udphdr udp;
	u_char seq;		
	u_char ttl;		
	struct timeval tv;	
};

struct func_args{
	int ttl;
	int tos;
	char** argv;
	pthread_mutex_t* life_mtx;
	char* packet;
	int* s;
	struct sockaddr_in* from;
	
	
	pthread_cond_t* cond;
	pthread_mutex_t* share_mtx;
	int* var_read;
};


int wait_for_reply(int sock, struct sockaddr_in* from, u_char packet[], int packet_size);
void send_probe(int seq, int ttl, struct sockaddr* addr, int sndsock, struct opacket *outpacket);
double deltaT __P((struct timeval *, struct timeval *));
int packet_ok __P((u_char *, int, struct sockaddr_in *, int));
void print(u_char* buf, int cc, struct sockaddr_in* from, int ttl, int probe);
void tvsub __P((struct timeval *, struct timeval *));
char *inetname __P((struct in_addr));
void usage __P(());
void* one_ttl(void* args);

		
struct timezone tz;		

struct Result{
	int RQ;
	char result[500][16];
};
	
int datalen;			

char *source = 0;
char *hostname;

int nprobes = 3;
int max_ttl = MAX_TTL;
u_short ident;
u_short port = 32768+666;	
int options;			
int verbose;
int waittime = 1;		
int nflag;
int seq = 0;
int already_printed = 0;
pthread_mutex_t seq_mtx = PTHREAD_MUTEX_INITIALIZER;
struct Result result;
int last_ttl = MAX_TTL;
int done = 0;


void sig_alarm(int x)
 	{ printf("--\n"); }

int main(int argc, char *argv[]){
	signal(SIGALRM, sig_alarm);

	extern char *optarg;
	extern int optind;
	int ch, i, on, tos, ttl;

	on = 1;
	tos = 0;
		
	argc -= optind;
	argv += optind;

	printf("\n---------------- TRACEROUTE SEVER INITIALIZING ----------------\n\n");
	
	printf("SERVER: Opening up listening port at:   port <-> %d\n", L_PORT);
	if( (L_FD = socket(AF_INET, SOCK_STREAM, 0))==-1)
	{
		perror("SERVER: Socket error");
		exit(0);
	}

	struct sockaddr_in conn;
	bzero(&conn, sizeof(conn));	
	conn.sin_family       =  AF_INET;
	conn.sin_addr.s_addr  =  htonl(INADDR_ANY);
    	conn.sin_port         =  htons(L_PORT);


	if ( (bind(L_FD, (struct sockaddr *)&conn, sizeof(conn))) != 0 ) 
	{
		perror("SERVER: Error binding"); 
		exit(0);
	}


	if ( (listen(L_FD, 100)) != 0 ) 
	{
		perror("SERVER: Error listening"); 
		exit(0);
	}	
	
	printf("SERVER: Server PORT bound and now listening\n");
	
	
	printf("\n----------------------- CLIENT CONNECT ------------------------\n\n");
	printf("SERVER: Connecting to   pathfinder.c   .... \n");

	C_FD = accept(L_FD, NULL, NULL);

	if(C_FD==-1)
	{
		printf("SERVER: Accept error");
		exit(0);
	}
	
	printf("SERVER: Connect successful\n");	
	printf("SYNC:  Sending TTl and Number of probe values...\n");

	char buff[6];

	sprintf(buff, "%d", max_ttl);
	write(C_FD, &buff, sizeof(buff));	
	
	sprintf(buff, "%d", nprobes);
	write(C_FD, &buff, sizeof(buff));	
	

	printf("SYNC:  Sent\n");


	printf("\n----------------------- RECIEVING REQUESTS ------------------------\n\n");

	printf("RECIEVE: Recieving requests from findLongestCommonPath.c...\n");

	char buff2[25];
	RQ=1;
	while(1)
	{
		read(C_FD,buff2,sizeof(buff2));

		if(strcmp(buff2,SEQ)==0)
		{
			usleep(5000);
			printf("SERVER: All %d requests read\n",RQ-1);
			while(1);

		}
		
		my_num += 1;

		if(fork()==0)
		{
			*argv = buff2;
			printf("RQ - %d\tIP - %s\tProcess started\n\n", RQ, *argv);
			break;
		}
		RQ++;

	}


	pthread_t thread_id[max_ttl];
	struct func_args args[max_ttl];
	pthread_mutex_t life_mtx[max_ttl];
	struct sockaddr_in from[max_ttl];
	int last_created_thread;
	u_char packet[max_ttl][PACKET_SIZE];
	int s[max_ttl];
	
	pthread_cond_t cond[max_ttl];
	pthread_mutex_t share_mtx[max_ttl];
	int var_read[max_ttl];
	
	for(ttl = 0; ttl < max_ttl; ++ttl){
		pthread_mutex_init(&life_mtx[ttl], NULL);
		pthread_mutex_init(&share_mtx[ttl], NULL);
		pthread_cond_init(&cond[ttl], NULL);
		var_read[ttl] = 0;
	}
	
	for (ttl = 1; ttl <= max_ttl; ++ttl) {
		args[ttl-1].ttl = ttl;
		args[ttl-1].argv = argv;
		args[ttl-1].tos = tos;
		args[ttl-1].life_mtx = &life_mtx[ttl-1];
		args[ttl-1].packet = packet[ttl-1];
		args[ttl-1].s = &s[ttl-1];
		args[ttl-1].from = &from[ttl-1];
		
		args[ttl-1].cond = &cond[ttl-1];
		args[ttl-1].share_mtx = &share_mtx[ttl-1];
		args[ttl-1].var_read = &var_read[ttl-1];

		
		if(done == 1 && ttl > last_ttl)
			break;
		
		pthread_mutex_lock(&life_mtx[ttl-1]);
		pthread_create(&thread_id[ttl-1], NULL, &one_ttl, &args[ttl-1]);// fork
		last_created_thread = ttl;
	}

	for(int z = 1; z<=last_created_thread;){
		for(ttl = 1; ttl <= last_created_thread; ++ttl){
			if(pthread_mutex_trylock(&life_mtx[ttl-1]) == 0){
				pthread_join(thread_id[ttl-1], NULL);
				++z;
			}	
		}
	}


	printf("RQ - %d\tIP - %s\tResults calculated\n\n", RQ, *argv);
		
	result.RQ = RQ;
	strcpy(result.result[last_ttl*nprobes], "");
		
	while(write(C_FD, &result, sizeof(result)) == -1);
	printf("RQ - %d\tIP - %s\tResult Sent\n\n", RQ, *argv);
	
//	sleep(5);
//	printf("RQ - %d\tGoing to Exit\n\n", RQ);
	
	sleep(1);
	printf("\t");
	exit(0);
}


void* one_ttl(void* args){
	struct func_args* args_ = (struct func_args*)args;
	struct opacket	*outpacket;

	u_char *packet = args_->packet;
	int ttl = args_->ttl;
	char** argv = args_->argv;
	int tos = args_->tos;
	int*s = args_->s;
	
	
	pthread_cond_t* cond = args_->cond;
	pthread_mutex_t* share_mtx = args_->share_mtx;
	int* var_read = args_->var_read;
	
	*var_read = 1;
	pthread_mutex_lock(share_mtx);

	if(done == 1 && ttl > last_ttl){
		pthread_mutex_unlock(args_->life_mtx);
		return NULL;
	}

	int on = 1;
	struct sockaddr_in *from = args_->from;
	struct sockaddr_in *to;
	struct hostent *hp;
	struct protoent *pe;
	struct sockaddr whereto;
	int sndsock;
	to = (struct sockaddr_in *)&whereto;


	setlinebuf (stdout);

	(void) bzero((char *)&whereto, sizeof(struct sockaddr));
	to->sin_family = AF_INET;
	to->sin_addr.s_addr = inet_addr(*argv);
	if (to->sin_addr.s_addr != -1)
		hostname = *argv;
	else {
		hp = gethostbyname(*argv);
		if (hp) {
			to->sin_family = hp->h_addrtype;
			bcopy(hp->h_addr, (caddr_t)&to->sin_addr, hp->h_length);
			hostname = hp->h_name;
		} else {
			(void)fprintf(stderr,
			    "traceroute: unknown host %s\n", *argv);
			exit(1);
		}
	}
	if (*++argv)
		datalen = atoi(*argv);
	if (datalen < 0 || datalen >= MAXPACKET - sizeof(struct opacket)) {
		Fprintf(stderr,
		    "traceroute: packet size must be 0 <= s < %ld.\n",
		    MAXPACKET - sizeof(struct opacket));
		exit(1);
	}
	datalen += sizeof(struct opacket);
	outpacket = (struct opacket *)malloc((unsigned)datalen);
	if (! outpacket) {
		perror("traceroute: malloc");
		exit(1);
	}
	(void) bzero((char *)outpacket, datalen);
	outpacket->ip.ip_dst = to->sin_addr;
	outpacket->ip.ip_tos = tos;
	outpacket->ip.ip_v = IPVERSION;
	outpacket->ip.ip_id = 0;

	ident = (getpid() & 0xffff) | 0x8000;

	if ((pe = getprotobyname("icmp")) == NULL) {
		Fprintf(stderr, "icmp: unknown protocol\n");
		exit(10);
	}
	if ((*s = socket(AF_INET, SOCK_RAW, pe->p_proto)) < 0) {
		perror("traceroute: icmp socket");
		exit(5);
	}
	if (options & SO_DEBUG)
		(void) setsockopt(*s, SOL_SOCKET, SO_DEBUG,
				  (char *)&on, sizeof(on));
	if (options & SO_DONTROUTE)
		(void) setsockopt(*s, SOL_SOCKET, SO_DONTROUTE,
				  (char *)&on, sizeof(on));

	if ((sndsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("traceroute: raw socket");
		exit(5);
	}
#ifdef SO_SNDBUF
	if (setsockopt(sndsock, SOL_SOCKET, SO_SNDBUF, (char *)&datalen,
		       sizeof(datalen)) < 0) {
		perror("traceroute: SO_SNDBUF");
		exit(6);
	}
#endif
#ifdef IP_HDRINCL
	if (setsockopt(sndsock, IPPROTO_IP, IP_HDRINCL, (char *)&on,
		       sizeof(on)) < 0) {
		perror("traceroute: IP_HDRINCL");
		exit(6);
	}
#endif
	if (options & SO_DEBUG)
		(void) setsockopt(sndsock, SOL_SOCKET, SO_DEBUG,
				  (char *)&on, sizeof(on));
	if (options & SO_DONTROUTE)
		(void) setsockopt(sndsock, SOL_SOCKET, SO_DONTROUTE,
				  (char *)&on, sizeof(on));

	if (source) {
		(void) bzero((char *)from, sizeof(struct sockaddr));
		from->sin_family = AF_INET;
		from->sin_addr.s_addr = inet_addr(source);
		if (from->sin_addr.s_addr == -1) {
			Printf("traceroute: unknown host %s\n", source);
			exit(1);
		}
		outpacket->ip.ip_src = from->sin_addr;
#ifndef IP_HDRINCL
		if (bind(sndsock, (struct sockaddr *)from, sizeof(struct sockaddr_in)) < 0) {
			perror ("traceroute: bind:");
			exit (1);
		}
#endif
	}

	if(already_printed == 0){
		(void) fflush(stderr);
		already_printed = 1;
	}
	

	
	
	u_long lastaddr = 0;
	int got_there = 0;
	int unreachable = 0;

	if(done == 1 && ttl > last_ttl){
		pthread_mutex_unlock(args_->life_mtx);
		return NULL;
	}

	fflush(stdout);
	for (int probe = 0; probe < nprobes; ++probe) {
		int cc, i;
		
		pthread_mutex_lock(&seq_mtx);
		int seq_ = ++seq;
		pthread_mutex_unlock(&seq_mtx);
		
		struct timeval t1, t2;
		struct timezone tz;
		struct ip *ip;

		(void) gettimeofday(&t1, &tz);
		
		send_probe(seq_, ttl, &whereto, sndsock, outpacket);
		while (cc = wait_for_reply(*s, from, packet, PACKET_SIZE)) {
			(void) gettimeofday(&t2, &tz);
			if ((i = packet_ok(packet, cc, from, seq_))) {
				
				{
					print(packet, cc, from, ttl, probe);
				}
				
				switch(i - 1) {
				case ICMP_UNREACH_PORT:
#ifndef ARCHAIC
					ip = (struct ip *)packet;
					if (ip->ip_ttl <= 1)
						Printf(" !");
#endif
					++got_there;
					break;
				case ICMP_UNREACH_NET:
					++unreachable;
					Printf(" !N");
					break;
				case ICMP_UNREACH_HOST:
					++unreachable;
					Printf(" !H");
					break;
				case ICMP_UNREACH_PROTOCOL:
					++got_there;
					Printf(" !P");
					break;
				case ICMP_UNREACH_NEEDFRAG:
					++unreachable;
					Printf(" !F");
					break;
				case ICMP_UNREACH_SRCFAIL:
					++unreachable;
					Printf(" !S");
					break;
				}
				break;
			}
			
			if(done == 1 && ttl > last_ttl){
				pthread_mutex_unlock(args_->life_mtx);
				return NULL;
			}
			
		}
		if (cc == 0){
			strcpy(result.result[ttl*3 + probe - 3], "*");
		}
		(void) fflush(stdout);
	}
	
	if (got_there || unreachable >= nprobes-1){

		last_ttl = last_ttl<ttl?last_ttl:ttl;
		done = 1;

	}
	
	pthread_mutex_unlock(args_->life_mtx);

	return NULL;
}

int call_icmp(pthread_cond_t* cond, pthread_mutex_t* share_mtx, int* var_read){
	*var_read = 1;
	pthread_cond_wait(cond, share_mtx);
}


int wait_for_reply(int sock, struct sockaddr_in* from, u_char packet[], int packet_size){
	fd_set fds;
	struct timeval wait;
	int cc = 0;
	int fromlen = sizeof (*from);

	FD_ZERO(&fds);
	FD_SET(sock, &fds);
	wait.tv_sec = waittime; wait.tv_usec = 0;

	if (select(sock+1, &fds, (fd_set *)0, (fd_set *)0, &wait) > 0)
		cc=recvfrom(sock, (char *)packet, packet_size, 0,
			    (struct sockaddr *)from, &fromlen);

	return(cc);
}

void send_probe(int seq, int ttl, struct sockaddr* addr, int sndsock, struct opacket *outpacket){
	struct opacket *op = outpacket;
	struct ip *ip = &op->ip;
	struct udphdr *up = &op->udp;
	int i;

	ip->ip_off = 0;
	ip->ip_hl = sizeof(*ip) >> 2;
	ip->ip_p = IPPROTO_UDP;
	ip->ip_len = datalen;
	ip->ip_ttl = ttl;
	ip->ip_v = IPVERSION;
	ip->ip_id = htons(ident+seq);

	up->uh_sport = htons(ident);
	up->uh_dport = htons(port+seq);
	up->uh_ulen = htons((u_short)(datalen - sizeof(struct ip)));
	up->uh_sum = 0;

	op->seq = seq;
	op->ttl = ttl;
	(void) gettimeofday(&op->tv, &tz);

	i = sendto(sndsock, (char *)outpacket, datalen, 0, addr,
		   sizeof(struct sockaddr));
	if (i < 0 || i != datalen)  {
		if (i<0)
			perror("sendto");
		(void) fflush(stdout);
	}
}


double deltaT(struct timeval* t1p, struct timeval* t2p){
	register double dt;

	dt = (double)(t2p->tv_sec - t1p->tv_sec) * 1000.0 +
	     (double)(t2p->tv_usec - t1p->tv_usec) / 1000.0;
	return (dt);
}



char* pr_type(u_char t){
	static char *ttab[] = {
	"Echo Reply",	"ICMP 1",	"ICMP 2",	"Dest Unreachable",
	"Source Quench", "Redirect",	"ICMP 6",	"ICMP 7",
	"Echo",		"ICMP 9",	"ICMP 10",	"Time Exceeded",
	"Param Problem", "Timestamp",	"Timestamp Reply", "Info Request",
	"Info Reply"
	};

	if(t > 16)
		return("OUT-OF-RANGE");

	return(ttab[t]);
}


int packet_ok(u_char* buf, int cc, struct sockaddr_in* from, int seq){
	register struct icmp *icp;
	u_char type, code;
	int hlen;
#ifndef ARCHAIC
	struct ip *ip;

	ip = (struct ip *) buf;
	hlen = ip->ip_hl << 2;
	if (cc < hlen + ICMP_MINLEN) {
		if (verbose)
			Printf("packet too short (%d bytes) from %s\n", cc,
				inet_ntoa(from->sin_addr));
		return (0);
	}
	cc -= hlen;
	icp = (struct icmp *)(buf + hlen);
#else
	icp = (struct icmp *)buf;
#endif
	type = icp->icmp_type; code = icp->icmp_code;
	if ((type == ICMP_TIMXCEED && code == ICMP_TIMXCEED_INTRANS) ||
	    type == ICMP_UNREACH) {
		struct ip *hip;
		struct udphdr *up;

		hip = &icp->icmp_ip;
		hlen = hip->ip_hl << 2;
		up = (struct udphdr *)((u_char *)hip + hlen);
		if (hlen + 12 <= cc && hip->ip_p == IPPROTO_UDP &&
		    up->uh_sport == htons(ident) &&
		    up->uh_dport == htons(port+seq))
			return (type == ICMP_TIMXCEED? -1 : code+1);
	}
#ifndef ARCHAIC
	if (verbose) {
		int i;
		u_long *lp = (u_long *)&icp->icmp_ip;

		for (i = 4; i < cc ; i += sizeof(long))
			Printf("%2d: x%8.8lx\n", i, *lp++);
	}
#endif
	return(0);
}


void print(u_char* buf, int cc, struct sockaddr_in* from, int ttl, int probe){
	struct ip *ip;
	int hlen;

	result.RQ = RQ;

	ip = (struct ip *) buf;
	hlen = ip->ip_hl << 2;
	cc -= hlen;


	if (nflag){
		strcpy(result.result[ttl*3 + probe - 3], inet_ntoa(from->sin_addr));
	}
	else{
		strcpy(result.result[ttl*3 + probe - 3], inet_ntoa(from->sin_addr));
	}

	if (verbose){
	}
}


#ifdef notyet

u_short in_cksum(u_short* addr, int len){
	register int nleft = len;
	register u_short *w = addr;
	register u_short answer;
	register int sum = 0;

	
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	
	if (nleft == 1)
		sum += *(u_char *)w;

	
	sum = (sum >> 16) + (sum & 0xffff);	
	sum += (sum >> 16);			
	answer = ~sum;				
	return (answer);
}
#endif


void tvsub(register struct timeval* out, register struct timeval*  in){
	if ((out->tv_usec -= in->tv_usec) < 0)   {
		out->tv_sec--;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}



char* inetname(struct in_addr in){
	register char *cp;
	static char line[50];
	struct hostent *hp;
	static char domain[MAXHOSTNAMELEN + 1];
	static int first = 1;

	if (first && !nflag) {
		first = 0;
		if (gethostname(domain, MAXHOSTNAMELEN) == 0 &&
		    (cp = index(domain, '.')))
			(void) strcpy(domain, cp + 1);
		else
			domain[0] = 0;
	}
	cp = 0;
	if (!nflag && in.s_addr != INADDR_ANY) {
		hp = gethostbyaddr((char *)&in, sizeof (in), AF_INET);
		if (hp) {
			if ((cp = index(hp->h_name, '.')) &&
			    !strcmp(cp + 1, domain))
				*cp = 0;
			cp = hp->h_name;
		}
	}
	if (cp)
		(void) strcpy(line, cp);
	else {
		in.s_addr = ntohl(in.s_addr);
#define C(x)	((x) & 0xff)
		Sprintf(line, "%u.%u.%u.%u", C(in.s_addr >> 24),
	
			C(in.s_addr >> 16), C(in.s_addr >> 8), C(in.s_addr));
	}
	return (line);
}
