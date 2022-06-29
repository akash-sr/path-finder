#include <sys/param.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/msg.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#define MAX_TTL 30
#define MAX_DOMAINS 1000
#define BUF_SIZE 1500
#define IP_SIZE 100
#define NPROBES 3
#define WAITTIME 2
#define MS_ID 'b'

extern int errno;
extern int gotalarm;

int numcompletd = 0;

// structure to handle ipv4 and ipv6
typedef struct proto{
  const char* (*icmpcode)(int);
  int (*recv)(int, int , struct proto*, int, struct timeval*);
  struct sockaddr *sasend;
  struct sockaddr *sarecv;
  struct sockaddr *salast;
  struct sockaddr *sabind;
  socklen_t salen;
  int icmpproto;
  int ttllevel;
  int ttloptname;
}proto;

typedef struct rec{
  u_short rec_seq;
  u_short rec_ttl;
  struct timeval recv_tv;
}rec;

int recv_v4(int, int, proto*, int, struct timeval*);
int recv_v6(int, int, proto*, int, struct timeval*);
const char *icmpcode_v4(int);
const char *icmpcode_v6(int);

proto proto_v4 = {
  icmpcode_v4,
  recv_v4,
  NULL,
  NULL,
  NULL,
  NULL,
  0,
  IPPROTO_ICMP,
  IPPROTO_IP,
  IP_TTL
};
proto proto_v6 = {
  icmpcode_v6,
  recv_v6,
  NULL,
  NULL,
  NULL,
  NULL,
  0,
  IPPROTO_ICMPV6,
  IPPROTO_IPV6,
  IPV6_UNICAST_HOPS
};

typedef struct args{
  proto* pr;
  struct addrinfo *ai;
  char* url;
  int ttl;
  pthread_mutex_t* life_mtx;
  pthread_cond_t* cond;
  int sendfd;
  int recvfd;
  int urlInd;
}args;

#define MSGQ_PATH "."

typedef struct MSG{
  long mtype; // urlInd
  int ttl;
  int probe;
  double rtt;
  char ip[IP_SIZE];
  int code;
}Message;

struct result{
  char ip[NI_MAXHOST];
  double rtt;
  int code;
}result[MAX_DOMAINS][MAX_TTL][NPROBES];

int datalen = sizeof(rec); //bytes of data following ICMP header
char urls[MAX_DOMAINS][50];



args params[MAX_TTL];
int done = 0;
int seq = 0;
int last_ttl = -1;
u_short dport = 32768+666;

pthread_mutex_t seq_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t compl_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ttl_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mq_lock = PTHREAD_MUTEX_INITIALIZER;


int compute_hash(char* s) {
    const int p = 31;
    const int m = 1e9 + 9;
    long long hash_value = 0;
    long long p_pow = 1;
    for (int i=0;i<strlen(s);i++) {
        char c = s[i];
        hash_value = (hash_value + (c - 'a' + 1) * p_pow) % m;
        p_pow = (p_pow * p) % m;
    }
    return hash_value;
}

void find_longest_common_path(int urlCnt){
  char paths[urlCnt][MAX_TTL][50];
  int plen[urlCnt];
  int len = 0;
  for(int i=0;i<urlCnt;i++){
    int ind = 0;
    char* lastip=NULL;
    for(int ttl=1;ttl<=MAX_TTL;ttl++){
      for(int probe=1;probe<=NPROBES;probe++){
        if(result[i][ttl-1][probe-1].code >=0)
          continue;

        if(strcmp(result[i][ttl-1][probe-1].ip, "*") && (lastip==NULL || strcmp(result[i][ttl-1][probe-1].ip, lastip))){
          strcpy(paths[i][ind], result[i][ttl-1][probe-1].ip);
          lastip = paths[i][ind];
          ind++;
        }

      }
    }
    if(ind<MAX_TTL){
      strcpy(paths[i][ind],"!");
    }
    plen[i] = ind;
    len = len>ind?len:ind;

  }

  int taken[len];
  int indexes[urlCnt];
  memset(&taken, 1, sizeof(taken));
  memset(&indexes, 0, sizeof(indexes));
  for(int ind=0;ind<plen[0];ind++){

    int flag = 1;
    for(int i=1;i<urlCnt;i++){
      int it = indexes[i];
      for(;it<plen[i];it++){
        if(!strcmp(paths[0][ind], paths[i][it])){
          indexes[i] = it+1;
          break;
        }
      }
      if(it==plen[i]){
        flag = 0;
      }
    }
    if(!flag)
      taken[ind] = 0;
  }

  printf("Longest Common Path is ");
  int flag = 1;
  for(int i=0;i<plen[0];i++){
    if(taken[i]){
      flag = 0;
      printf("->[%s]", paths[0][i]);
    }
  }
  if(flag){
    printf("(null)");
  }
  printf("\n");
}

const char * icmpcode_v4(int code)
{
	static char errbuf[100];
	switch (code) {
	case  0:	return("network unreachable");
	case  1:	return("host unreachable");
	case  2:	return("protocol unreachable");
	case  3:	return("port unreachable");
	case  4:	return("fragmentation required but DF bit set");
	case  5:	return("source route failed");
	case  6:	return("destination network unknown");
	case  7:	return("destination host unknown");
	case  8:	return("source host isolated (obsolete)");
	case  9:	return("destination network administratively prohibited");
	case 10:	return("destination host administratively prohibited");
	case 11:	return("network unreachable for TOS");
	case 12:	return("host unreachable for TOS");
	case 13:	return("communication administratively prohibited by filtering");
	case 14:	return("host recedence violation");
	case 15:	return("precedence cutoff in effect");
	default:	sprintf(errbuf, "[unknown code %d]", code);
				return errbuf;
	}
}

const char *icmpcode_v6(int code)
{

	static char errbuf[100];
	switch (code) {
	case  ICMP6_DST_UNREACH_NOROUTE:
		return("no route to host");
	case  ICMP6_DST_UNREACH_ADMIN:
		return("administratively prohibited");

	case  ICMP6_DST_UNREACH_ADDR:
		return("address unreachable");
	case  ICMP6_DST_UNREACH_NOPORT:
		return("port unreachable");
	default:
		sprintf(errbuf, "[unknown code %d]", code);
		return errbuf;
	}

}

char * sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
    static char str[128];		/* Unix domain is largest */

	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in	*sin = (struct sockaddr_in *) sa;

		if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
			return(NULL);
		return(str);
	}

	case AF_INET6: {
		struct sockaddr_in6	*sin6 = (struct sockaddr_in6 *) sa;

		if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL)
			return(NULL);
		return(str);
	}

	case AF_UNIX: {
		struct sockaddr_un	*unp = (struct sockaddr_un *) sa;

		if (unp->sun_path[0] == 0)
			strcpy(str, "(no pathname bound)");
		else
			snprintf(str, sizeof(str), "%s", unp->sun_path);
		return(str);
	}


	default:
		snprintf(str, sizeof(str), "sock_ntop_host: unknown AF_xxx: %d, len %d",
				 sa->sa_family, salen);
		return(str);
	}
    return (NULL);
}

int recv_v4(int recvfd, int sport, proto* pr, int seq, struct timeval *tv){
    fd_set fds;
    struct timeval wait;
    FD_ZERO(&fds);
    FD_SET(recvfd, &fds);
    wait.tv_sec = WAITTIME;
    wait.tv_usec = 0;


    socklen_t len;
    int recvsize = 0;
    char recvbuf[BUF_SIZE];
    int hlen1, hlen2, icmplen, ret=-3;

    struct ip *ip, *hip;
    struct icmp *icmp;
    struct udphdr *udp;

    clock_t start = clock();
    int rdes = 0;
    while((rdes = select(recvfd+1, &fds, NULL, NULL, &wait))>0){

      len = pr->salen;
      recvsize = recvfrom(recvfd, recvbuf, sizeof(recvbuf),0, pr->sarecv, &len);
      if(recvsize<0){
        if(errno == EINTR)
          continue;
        else{
          perror("recvfrom");
          // pthread_exit(0);
          break;
        }
      }
      ip = (struct ip*) recvbuf; //start of IP header
      hlen1 = ip->ip_hl <<2; // length of IP header;
      icmp = (struct icmp*) (recvbuf+hlen1); // start of icmp header;
      if((icmplen = recvsize-hlen1)<8){
        printf("not enough icmp data to look at\n");
        continue;
      }

      if(icmp->icmp_type == ICMP_TIMXCEED && icmp->icmp_code == ICMP_TIMXCEED_INTRANS){
        if(icmplen < 8 + sizeof(struct ip)){
          printf("not enough inner ip data to look at\n");
          continue;
        }
        hip = (struct ip*) (recvbuf+hlen1+8);
        hlen2 = hip->ip_hl << 2;
        if(icmplen<8+hlen2+4){
          printf("not enough udp port data to look at\n");
          continue;
        }

        udp = (struct udphdr*) (recvbuf+hlen1+8+hlen2);
        if(hip->ip_p == IPPROTO_UDP && udp->uh_sport == htons(sport) && udp->uh_dport == htons(dport+seq)){
          ret = -2;
          break; // we hit an interim router
        }
      }
      else if(icmp->icmp_type == ICMP_UNREACH){
        if(icmplen < 8 + sizeof(struct ip)){
          printf("not enough inner ip data to look at\n");
          continue;
        }
        hip = (struct ip*) (recvbuf+hlen1+8);
        hlen2 = hip->ip_hl << 2;
        if(icmplen<8+hlen2+4){
          printf("not enough udp port data to look at\n");
          continue;
        }

        udp = (struct udphdr*) (recvbuf+hlen1+8+hlen2);
        if(hip->ip_p == IPPROTO_UDP && udp->uh_sport == htons(sport) && udp->uh_dport == htons(dport+seq)){
          if(icmp->icmp_code == ICMP_UNREACH_PORT){
            // printf("destination reached\n");
            ret = -1; // we have reached destination
          }
          else
            ret = icmp->icmp_code;
          break;
        }
      }

    }
    gettimeofday(tv, NULL);
    return ret;
}

int recv_v6(int recvfd, int sport, proto* pr, int seq, struct timeval *tv){
  // not implemented
  return 0;
}



int fill_urls(char* filePath){
  FILE* fp = fopen(filePath,"r");
  if(fp==NULL){
    perror("fopen");
    return 0;
  }
  int urlCnt=0;
  while(!feof(fp)){
    fscanf(fp,"%s",urls[urlCnt]);

    urls[urlCnt][strlen(urls[urlCnt])]='\0';
    urlCnt++;
  }
  fclose(fp);


  return urlCnt-1;
}

void sock_set_port(struct sockaddr *sa, socklen_t salen, int port)
{
	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in	*sin = (struct sockaddr_in *) sa;

		sin->sin_port = port;
		return;
	}


	case AF_INET6: {
		struct sockaddr_in6	*sin6 = (struct sockaddr_in6 *) sa;

		sin6->sin6_port = port;
		return;
	}

	}

    return;
}

int sock_cmp_addr(const struct sockaddr *sa1, const struct sockaddr *sa2, socklen_t salen)
{
	if (sa1->sa_family != sa2->sa_family)
		return(-1);

	switch (sa1->sa_family) {
	case AF_INET: {
		return(memcmp( &((struct sockaddr_in *) sa1)->sin_addr,
					   &((struct sockaddr_in *) sa2)->sin_addr,
					   sizeof(struct in_addr)));
	}
	case AF_INET6: {
		return(memcmp( &((struct sockaddr_in6 *) sa1)->sin6_addr,
					   &((struct sockaddr_in6 *) sa2)->sin6_addr,
					   sizeof(struct in6_addr)));
	}


	case AF_UNIX: {
		return(strcmp( ((struct sockaddr_un *) sa1)->sun_path,
					   ((struct sockaddr_un *) sa2)->sun_path));
	}

    return (-1);
}
}

void* func(void* argv){
  args* func_args = (args*) argv;
  proto* pr = func_args->pr;
  struct addrinfo *ai = func_args->ai;
  char* url = func_args->url;
  int ttl = func_args->ttl;
  pthread_mutex_t* life_mtx = func_args->life_mtx;
  pthread_cond_t* cond = func_args->cond;

  rec* recvdata;
  char sendbuf[BUF_SIZE];
  char recvbuf[BUF_SIZE];
  struct timeval tvrecv;
  double rtt;



  pthread_mutex_lock(&compl_lock);
  pthread_mutex_lock(&ttl_lock);
  if(done==1 && ttl>last_ttl){
    pthread_mutex_unlock(func_args->life_mtx);
    // printf("%s ho gya\n", url);
    pthread_mutex_unlock(&ttl_lock);
    pthread_mutex_unlock(&compl_lock);
    return NULL;
  }
  pthread_mutex_unlock(&ttl_lock);
  pthread_mutex_unlock(&compl_lock);

  func_args->recvfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);

  if(pr->sasend->sa_family == AF_INET6){
    struct icmp6_filter myfilt;
    ICMP6_FILTER_SETBLOCKALL(&myfilt);
    ICMP6_FILTER_SETPASS(ICMP6_TIME_EXCEEDED, &myfilt);
    ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &myfilt);
    setsockopt(func_args->recvfd, IPPROTO_IPV6, ICMP6_FILTER, &myfilt, sizeof(myfilt));
  }

  func_args->sendfd = socket(pr->sasend->sa_family, SOCK_DGRAM, 0);

  pr->sabind->sa_family = pr->sasend->sa_family;
  int sport = (getpid()&0xffff)|0x8000;
  sock_set_port(pr->sabind, pr->salen, htons(sport));
  bind(func_args->sendfd, pr->sabind, pr->salen);

  setsockopt(func_args->sendfd, pr->ttllevel, pr->ttloptname, &ttl, sizeof(int));
  bzero(pr->salast, pr->salen);

  int code = 0;
  int msqid;
  key_t key;

  if((key = ftok(MSGQ_PATH, MS_ID))<0){
    perror("ftok");
    exit(1);
  }
  if((msqid = msgget(key, IPC_CREAT | 0664))<0){
    perror("msgget");
    exit(1);
  }

  for(int probe = 0; probe<NPROBES;probe++){

    Message msg;

    msg.mtype = func_args->urlInd+1;
    msg.ttl = ttl;
    msg.probe = probe;

    msg.rtt = 0.0;
    msg.code = -5;

    strcpy(msg.ip, "---");
    recvdata = (struct rec*) sendbuf;
    pthread_mutex_lock(&seq_lock);
    recvdata->rec_seq = seq;
    seq++;
    pthread_mutex_unlock(&seq_lock);
    recvdata->rec_ttl = ttl;
    gettimeofday(&recvdata->recv_tv, NULL);
    sock_set_port(pr->sasend, pr->salen, htons(dport+seq));
    ssize_t datasent = 0;
    if((datasent = sendto(func_args->sendfd, sendbuf, datalen, 0, pr->sasend, pr->salen))<0){
      perror("sendto");
      break;
    }
    if((code = (*pr->recv)(func_args->recvfd, sport, pr, seq, &tvrecv))==-3){
      strcpy(msg.ip, "*");
      msg.code = -3;
    }
    else{
      char str[NI_MAXHOST];

        const char* ipaddr = sock_ntop_host(pr->sarecv, pr->salen);
        strcpy(msg.ip, ipaddr);
        memcpy(pr->salast, pr->sarecv, pr->salen);

      tvrecv.tv_sec-=recvdata->recv_tv.tv_sec;
      tvrecv.tv_usec-=recvdata->recv_tv.tv_usec;
      rtt = tvrecv.tv_sec*1000.0 + tvrecv.tv_usec/1000.0;


      msg.rtt = rtt;
      msg.code = code;
      if(code == -1){
        pthread_mutex_lock(&compl_lock);

        done = 1;
        pthread_mutex_unlock(&compl_lock);
      }
      else if(code >=0){
        // some other icmp message
      }

    }
    pthread_mutex_lock(&mq_lock);

    if(msgsnd(msqid, &msg, sizeof(msg),0)<0){

    }
    pthread_mutex_unlock(&mq_lock);

  }

  pthread_mutex_unlock(func_args->life_mtx);
  return (NULL);
}

void sig_chld(int signo){

  wait(NULL);

  return;
}


void print_results(int urlCnt){
  for(int i=0;i<urlCnt;i++){
    printf("%s results...\n", urls[i]);
    char col2[]="IP";
    char col3[]="RTT";
    char col4[]="IP";
    char col5[]="RTT";
    char col6[]="IP";
    char col7[]="RTT";
    printf("[ttl]\t%-20s %-10s\t%-20s %-10s\t%-20s %-10s\n", col2, col3, col4, col5, col6, col7);
    for(int ttl=1;ttl<=MAX_TTL;ttl++){
      printf("[%d]\t",ttl);
      for(int probe=1;probe<=NPROBES;probe++){
        if(result[i][ttl-1][probe-1].code >=0)
          continue;
        printf("%-20s %-10lf", result[i][ttl-1][probe-1].ip?result[i][ttl-1][probe-1].ip:"(null)", result[i][ttl-1][probe-1].rtt);
        printf("\t");
      }
      printf("\n");
    }
  }
}

int main(int argc, char* argv[]){
  if(argc!=2){
    printf("usage: ./pathfinder <input file name>\n");
    return 0;
  }


  signal(SIGCHLD, sig_chld);
  int msqid;
  key_t key;

  if((key = ftok(MSGQ_PATH, MS_ID))<0){
    perror("ftok");
    exit(1);
  }
  if((msqid = msgget(key, IPC_CREAT | 0664))<0){
    perror("msgget");
    exit(1);
  }

  int urlCnt = fill_urls(argv[1]);

  char* url = NULL;
  int urlInd = 0;
  for(;urlInd<urlCnt;urlInd++){
    if(fork()==0){
      url = urls[urlInd];
      printf("[%d] starting traceroute for %s\n",urlInd+1, url);
      break;
    }
  }
  if(urlInd == urlCnt){

    sleep(1);

    Message msg;
    int child = 0;

    while(child<urlCnt){
      if(msgrcv(msqid, &msg, sizeof(msg), 0,0)<=0){
        continue;
      }
      printf(".");
      fflush(stdout);

      if(msg.code==-4){
        child++;
        if(child==urlCnt)
          break;
      }

      else{
        result[msg.mtype-1][msg.ttl][msg.probe].rtt = msg.rtt;
        strcpy(result[msg.mtype-1][msg.ttl][msg.probe].ip, msg.ip);
        result[msg.mtype-1][msg.ttl][msg.probe].code = msg.code;
      }
      bzero(&msg, sizeof(msg));
    }
    printf("\n");

    if(msgctl(msqid,IPC_RMID,NULL)<0){
      perror("msgctl");
    }

    wait(NULL);

    print_results(urlCnt);
    find_longest_common_path(urlCnt);
    return 0;
  }

  if(url==NULL)
    exit(0);


  struct addrinfo *ai;
  proto* pr;

  pid_t pid = getpid();
  struct addrinfo hints;
  bzero(&hints, sizeof(struct addrinfo));
  hints.ai_flags = AI_CANONNAME;
  if(getaddrinfo(url, NULL, &hints, &ai)!=0){
    perror("getaddrinfo");
    exit(errno);
  }

  if(ai->ai_family == AF_INET){
    pr = &proto_v4;
  }
  else if(ai->ai_family == AF_INET6){
    pr = &proto_v6;
    if(IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6*)ai->ai_addr)->sin6_addr))){
      printf("cannot traceroute IPv4-mapped IPv6 address\n");
      exit(0);
    }
  }
  else{
    printf("unknown address family %d\n", ai->ai_family);
    exit(0);
  }

  pr->sasend = ai->ai_addr;
  pr->sarecv = calloc(1, ai->ai_addrlen);
  pr->salast = calloc(1, ai->ai_addrlen);
  pr->sabind = calloc(1, ai->ai_addrlen);
  pr->salen = ai->ai_addrlen;

  pthread_t thread_id[MAX_TTL];
  pthread_mutex_t life_mtx[MAX_TTL];
  pthread_cond_t cond[MAX_TTL];
  int completed[MAX_TTL];

  memset(&completed,0, sizeof(completed));
  int last_created_thread = 0;
  for(int ttl = 0; ttl < MAX_TTL; ++ttl){
		pthread_mutex_init(&life_mtx[ttl], NULL);

		pthread_cond_init(&cond[ttl], NULL);

	}
  for(int ttl = 1; ttl<=MAX_TTL;ttl++){
    params[ttl-1].url = url;
    params[ttl-1].ttl = ttl;
    params[ttl-1].life_mtx = &life_mtx[ttl-1];
    params[ttl-1].cond = &cond[ttl-1];
    params[ttl-1].ai = ai;
    params[ttl-1].pr = pr;
    params[ttl-1].urlInd = urlInd;

    pthread_mutex_lock(&compl_lock);
    if(done==1){
      pthread_mutex_unlock(&compl_lock);
      break;
    }
    pthread_mutex_unlock(&compl_lock);
    pthread_mutex_lock(&ttl_lock);
    last_ttl = ttl;
    pthread_mutex_unlock(&ttl_lock);
    pthread_mutex_lock(&life_mtx[ttl-1]);
    pthread_create(&thread_id[ttl-1], NULL, &func, &params[ttl-1]);
    last_created_thread = ttl;
  }

  int flag = 0;
  while(flag<last_created_thread){

    for(int ttl=1;ttl<=last_created_thread;ttl++){
      if(!completed[ttl-1] && pthread_mutex_trylock(&life_mtx[ttl-1])==0){
        flag++;

        completed[ttl-1] = 1;
        pthread_join(thread_id[ttl-1],NULL);
      }
    }
  }

  Message msg;
  bzero(&msg, sizeof(msg));
  msg.mtype = urlCnt;
  msg.code = -4;
  msg.ttl = 0;
  msg.probe = 0;
  msg.rtt = 0.0;
  strcpy(msg.ip, "-^-");
  pthread_mutex_lock(&mq_lock);
  if(msgsnd(msqid, &msg, sizeof(msg), 0)<0){

    perror("msgsnd");

  }
  pthread_mutex_unlock(&mq_lock);
  return 0;
}
