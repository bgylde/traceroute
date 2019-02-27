#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#include "traceroute.h"
#include "cJSON.h"
// #include "proxylog.h"
// #include "common.h"
// #include "informer.h"

#define p_return_if_fail(expr)      do{           \
    if (expr) { } else                         \
    {                                \
        pri_warning ("now return for illegal operation\n");                \
        return;                            \
    };               }while(0)

#define p_return_val_if_fail(expr,val)  do{           \
     if (expr) { } else                     \
       {                                \
     pri_warning ("now return for illegal operation\n");              \
     return (val);                          \
       };               }while(0)

#define pri_warning printf
#define pri_debug printf
#define pri_error printf

void free_print_list(print_ctrl_t * print_obj)
{
    print_node_t * print_node_temp = print_obj->head;

    while(print_node_temp != NULL)
    {
        print_node_t * print_node_next = print_node_temp->next;
        free(print_node_temp);
        print_node_temp = print_node_next;
    }

    free(print_obj);
}

#if 0
int traceroute_info_insert(char *info)
{
    DIAGNO_HANDLE  handle = NULL;
    int ret = -1;


    pri_debug("net_diagno_client_sqlite_insert begin\n");
    handle = net_diagno_client_get_handle();
    ret = net_diagno_client_sqlite_insert(handle, E_TABLE_TRACEROUTE,  info);
    if (ret < 0)
    {
        pri_debug("net_diagno_client_sqlite_insert end, E_TABLE_TRACEROUTE failed\n");
        return ret;
    }

    pri_debug("net_diagno_client_sqlite_insert end, E_TABLE_TRACEROUTE ok\n");

    ret = 0;

    return ret;
}
#endif
char * load_traceroute_json(print_ctrl_t * print_obj)
{
    char * json_out = NULL;

    p_return_val_if_fail(print_obj != NULL, NULL);

    json_out = create_json_string_of_traceroute(print_obj);
    if (NULL == json_out)
    {
        return NULL;
    }

    //informer_post_system_status(json_out);
    //traceroute_save(json_out);
    //traceroute_info_insert(json_out);

    return json_out;
}

#if 0
int main(int argc, char** argv)
{
    if(argc == 2)
    {
        return traceroute_report(argv[1]);
    }
    else
    {
        return 0;
    }
}
#endif

char * traceroute_report(const char * host)
{
    int sockfd = -1;
    int ttl = 1;
    int ret = -1;
    char * traceroute_out = NULL;
    unsigned int size_data = 64;
    struct sockaddr_in from;
    struct addrinfo wanted_addr;
    struct addrinfo *to = NULL;
    struct addrinfo *parse_addr = NULL;
    struct ping_icmp_param ping_param;
    struct sockaddr_in destination;
    struct timespec time_before;
    char name_dest[INET6_ADDRSTRLEN];
    unsigned char buffer[MAXPACKET];
    u_int32_t adresses[MAXJUMP];

    p_return_val_if_fail (host != NULL, traceroute_out);

    print_ctrl_t * print_obj = (print_ctrl_t *)malloc(sizeof(print_ctrl_t));
    print_obj->head = NULL;
    print_obj->current_node = NULL;
    print_obj->size = 0;

    ping_param.sockfd = &sockfd;
    ping_param.size_data = &size_data;
    ping_param.destination = &destination;
    ping_param.time_bef = &time_before;
    ping_param.pid = getpid();
    ping_param.seq = 0;

    memset(&adresses, 0, MAXJUMP * sizeof(*adresses));
    memset(&wanted_addr, 0, sizeof(struct addrinfo));

    wanted_addr.ai_family = AF_INET;
    wanted_addr.ai_socktype = SOCK_RAW;
    wanted_addr.ai_protocol = IPPROTO_ICMP;

    if((ret = getaddrinfo(host, NULL, &wanted_addr, &to)) != 0)
    {
        pri_debug("getaddrinfo error: %s\n", gai_strerror(ret));
        return traceroute_out;
    }

    for(parse_addr = to; parse_addr != NULL; parse_addr = parse_addr->ai_next)
    {
        sockfd = socket(parse_addr->ai_family,
            parse_addr->ai_socktype, parse_addr->ai_protocol);
        if(sockfd >  0)
        {
            memcpy(&destination, parse_addr->ai_addr,
                sizeof(struct sockaddr_in));
            break;
        }
        else
        {
            pri_error("create socket error: %s\n", strerror(errno));
            goto EXIT_TRACEROUTE;
        }
    }

    if (sockfd < 0)
    {
      pri_debug("$$$$$$$$$$ create socket error $$$$$$$$$$\n");
      goto EXIT_TRACEROUTE;
    }



    if(parse_addr == NULL)
    {
        pri_debug("traceroute, unknown host %s\n", host);
        goto EXIT_TRACEROUTE;
    }

    inet_ntop(destination.sin_family, &destination.sin_addr,
        name_dest, INET6_ADDRSTRLEN);

    pri_debug("traceroute to %s (%s)\n", host, name_dest);

    socklen_t from_len = sizeof(from);
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));

    int maxfds = sockfd + 1;
    fd_set rset;
    int try_cnt = 0;
    struct timeval timeout;

    while(ttl <= MAXJUMP)
    {
        int len;

        FD_ZERO(&rset);
        FD_SET(sockfd, &rset);
        timeout.tv_sec  = 1;
        timeout.tv_usec = 0;

        from_len = sizeof(from);
        pinger_icmp(&ping_param);

        int res = select(maxfds, &rset, NULL, NULL, &timeout);
        if(res < 0)
        {
            pri_debug("select error: %s\n", strerror(errno));
            goto EXIT_TRACEROUTE;
        }

        if(res == 0)
        {
            if(try_cnt == MAXTRY)
            {
                show_asterisk(ttl, print_obj);
                ttl++;
                try_cnt = 0;
                setsockopt(sockfd, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));
                continue;
            }

            try_cnt++;
            continue;
        }
        else
        {
            if((len = recvfrom(sockfd, buffer, MAXPACKET, 0,
                (struct sockaddr*) &from, &from_len)) <= 0)
            {
                pri_debug("recvfrom error: %s\n", strerror(errno));
				   goto EXIT_TRACEROUTE;
            }

            if(check_recv_packet(buffer, &ping_param) == 0)
            {
                if(from.sin_addr.s_addr == destination.sin_addr.s_addr)
                {
                    tracert_icmp(buffer, (unsigned int) len, &from, ttl,
                        ping_param.time_bef, print_obj);

                    pri_debug("traceroute completed\n");
                    break;
                }

                if(0 == host_has_arrived(from.sin_addr.s_addr, adresses))
                {
                    adresses[ttl - 1] = from.sin_addr.s_addr;
                    tracert_icmp(buffer, (unsigned int) len, &from, ttl,
                        ping_param.time_bef, print_obj);

                    ttl++;
                    try_cnt = 0;
                    setsockopt(sockfd, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));
                    continue;
                }

            }

            if(try_cnt == MAXTRY)
            {
                show_asterisk(ttl, print_obj);
                ttl++;
                try_cnt = 0;
                setsockopt(sockfd, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));
                continue;
            }

            try_cnt++;
        }
    }

    traceroute_out = load_traceroute_json(print_obj);

EXIT_TRACEROUTE:
    if (NULL != to)
    {
        freeaddrinfo(to);
    }

    if (sockfd > 0)
    {
        close(sockfd);
    }

    if (NULL != print_obj)
    {
        free_print_list(print_obj);
    }

    return traceroute_out;
}

struct timespec time_diff(struct timespec* begin, struct timespec* end)
{
    struct timespec tp;

    tp.tv_sec = end->tv_sec - begin->tv_sec;
    tp.tv_nsec = end->tv_nsec - begin->tv_nsec;

    if(tp.tv_nsec < 0)
    {
        tp.tv_sec -= 1;
        tp.tv_nsec += 1000000000;
    }

    return tp;
}

void tracert_icmp(unsigned char * buf, unsigned int size,
    struct sockaddr_in* doctorWho, int ttl, struct timespec *tbef,
    print_ctrl_t * print_obj)
{
    struct ip* ip;
    struct timespec tnow;
    struct timespec diff;

    unsigned int ipheaderlen;
    double timems;
    char host[50];

    clock_gettime(CLOCK_REALTIME, &tnow);
    ip = (struct ip*) buf;
    ipheaderlen = ip->ip_hl << 2; // passage de bits en octets (*32/8)==> *4 ==> <<2 EZ
    if(size < ipheaderlen + ICMP_MINLEN)
    {
        pri_debug("Vodoo magic happened, the size of the packet must be %d a minima\n", ipheaderlen + ICMP_MINLEN);
        return;
    }

    diff = time_diff(tbef, &tnow);
    timems = diff.tv_sec * 1000 + (diff.tv_nsec / 1000000.0);

    if(getnameinfo((struct sockaddr*) doctorWho, sizeof(struct sockaddr_in),
        host, 50, NULL, 0, 0) < 0)
    {
        pri_debug("genameinfo: %s\n", strerror(errno));
    }

    print_node_t * print_node = (print_node_t *)malloc(sizeof(print_node_t));

    snprintf(print_node->ip, sizeof(print_node->ip), "%s",
        inet_ntoa(doctorWho->sin_addr));
    snprintf(print_node->delay, sizeof(print_node->delay), "%.3f ms", timems);
    snprintf(print_node->ttl, sizeof(print_node->ttl), "%d", ttl);
    print_node->next = NULL;

    if(print_obj->head == NULL)
    {
        print_obj->head = print_node;
        print_obj->current_node = print_node;
        print_obj->size = 1;
    }
    else
    {
        print_obj->current_node->next = print_node;
        print_obj->current_node = print_node;
        print_obj->size++;
    }

    pri_debug("%d %s (%s) time %.3fms\n",
        ttl, host, inet_ntoa(doctorWho->sin_addr), timems);

}

void pinger_icmp(struct ping_icmp_param * papram)
{
    int nbs;

    unsigned int i;
    unsigned char packet[MAXPACKET];
    unsigned char *data = &packet[8];

    struct icmp *icmp_packet = (struct icmp*) packet;

    memset(packet, 0, MAXPACKET);

    icmp_packet->icmp_type = ICMP_ECHO;
    icmp_packet->icmp_code = 0;
    icmp_packet->icmp_cksum = 0;
    icmp_packet->icmp_seq = htons(++papram->seq);
    icmp_packet->icmp_id = htons(papram->pid);

    for(i = 0; i < *papram->size_data; i++)
    {
        *data++ = i;
    }

    clock_gettime(CLOCK_REALTIME, papram->time_bef);
    icmp_packet->icmp_cksum = check_sum((unsigned short*)icmp_packet,
        8 + *papram->size_data);
    nbs = sendto(*papram->sockfd, packet, 8 + *papram->size_data, 0,
        (struct sockaddr*) papram->destination, sizeof(struct sockaddr));

    if(nbs < 0 || (unsigned int)nbs < 8 + *papram->size_data)
    {
        if(nbs < 0)
        {
            pri_debug("sendto : %s\n", strerror(errno));
        }

        pri_debug("ping : sendto %s %d chars, achieve %d\n",
            inet_ntoa((*papram->destination).sin_addr),
            8 + *papram->size_data,
            nbs);
    }
}

u_int16_t check_sum(u_int16_t* icmp, int totalLength)
{
    u_int32_t checksumm = 0;
    while(totalLength > 1)
    {
        checksumm = checksumm + *icmp++;
        totalLength = totalLength - sizeof(u_int16_t);
    }

    if(totalLength > 0)
        checksumm = checksumm + *(unsigned char*)icmp;

    checksumm = (checksumm >> 16) + (checksumm & 0xffff);
    checksumm = checksumm + (checksumm >> 16);

    return (u_int16_t)(~checksumm); // complement a 1
}

int check_recv_packet(unsigned char * recv_buff, struct ping_icmp_param * papram)
{
    struct ip *reply = (struct ip *) recv_buff;

	if(reply->ip_p != IPPROTO_ICMP)
	{
        return FAILURE;  // Check packet's protocol (if it's ICMP)
	}

	struct icmp *icmpHeader = (struct icmp *) (recv_buff + reply->ip_hl*4);  // we "extract" the ICMP header from the IP packet
	if(icmpHeader->icmp_type != ICMP_ECHOREPLY &&
	  !(icmpHeader->icmp_type == ICMP_TIME_EXCEEDED && icmpHeader->icmp_code == ICMP_EXC_TTL))
	{
        return FAILURE;
	}

	if(icmpHeader->icmp_type == ICMP_TIME_EXCEEDED)
	{
	    icmpHeader = (struct icmp *) (icmpHeader->icmp_data + ((struct ip *) (icmpHeader->icmp_data))->ip_hl*4);
	}

    if(ntohs(icmpHeader->icmp_id) != papram->pid)
    {
        return FAILURE;
    }

    if(papram->seq != ntohs(icmpHeader->icmp_seq))
    {
        return FAILURE;
    }

    return SUCCESS;
}

int host_has_arrived(u_int32_t ip, u_int32_t *tab)
{
    int i;
    int trouve = 0;
    for(i = 0; i < MAXJUMP && !trouve; i++)
    {
        trouve = trouve || tab[i] == ip;
    }

    return trouve;
}

void show_asterisk(int i, print_ctrl_t * print_obj)
{
    print_node_t * print_node = (print_node_t *)malloc(sizeof(print_node_t));

    snprintf(print_node->ip, sizeof(print_node->ip), "%s", "*");
    snprintf(print_node->delay, sizeof(print_node->delay), "%s", "*");
    snprintf(print_node->ttl, sizeof(print_node->ttl), "%d", i);
    print_node->next = NULL;

    if(print_obj->head == NULL)
    {
        print_obj->head = print_node;
        print_obj->current_node = print_node;
        print_obj->size = 1;
    }
    else
    {
        print_obj->current_node->next = print_node;
        print_obj->current_node = print_node;
        print_obj->size++;
    }

    pri_debug("%d * * * \n", i);
}

#if 0
int get_sockaddr(struct sockaddr_in * sockad, char * iface)        //get local address
{
    char buf[512];
    int i = 0;
    int  ret = -1;

    struct ifconf ifconf;           //local address information
    struct ifreq *ifreq;

    ifconf.ifc_len = 512;
    ifconf.ifc_buf = buf;

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
    {
        pri_debug("get_sockaddr socket error: %s\n", strerror(errno));
        return ret;
    }

    if(ioctl(sockfd, SIOCGIFCONF, &ifconf) == -1)
    {
        pri_debug("ioctl error: %s\n", strerror(errno));
        goto get_sockaddr_exit;
    }

    ifreq = (struct ifreq*)buf;
    for(i = (ifconf.ifc_len / sizeof(struct ifreq)); i > 0; i--)
    {
        if(ifreq->ifr_flags == AF_INET)                 //for ipv4
        {
            if(iface != NULL && (strcmp(ifreq->ifr_name, iface) == 0))
            {
                memcpy(sockad, &ifreq->ifr_addr, sizeof(struct sockaddr_in));
                ret = 0;
                break;
            }
            else
            {
                if(strcmp(ifreq->ifr_name, "lo") == 0)
                {
                    ifreq++;
                    continue;
                }

                memcpy(sockad, &ifreq->ifr_addr, sizeof(struct sockaddr_in));
                ret = 0;
                break;
            }
        }
    }

 get_sockaddr_exit:
   if (sockad > 0)
    {
      close(sockad);
    }

   return ret;

}
#endif
char* create_json_string_of_traceroute(print_ctrl_t *list)
{
    cJSON * root;
    cJSON *json_array, *json_obj;
    char  * out = NULL;
    print_node_t *ptmp = NULL;

    p_return_val_if_fail (list != NULL, NULL);

    root = cJSON_CreateObject();
    if(root)
    {
        struct timeval curr_time;

        gettimeofday(&curr_time, NULL );
        cJSON_AddNumberToObject (root, "timestamp", curr_time.tv_sec);

        json_array = cJSON_CreateArray();
        cJSON_AddItemToObject (root, "ip_traceroute", json_array);
        for(ptmp = list->head; NULL != ptmp; ptmp = ptmp->next)
        {
            json_obj = cJSON_CreateObject();
            cJSON_AddItemToArray (json_array, json_obj);
            cJSON_AddStringToObject (json_obj, "ip", ptmp->ip);
            cJSON_AddStringToObject (json_obj, "delay", ptmp->delay);
            cJSON_AddNumberToObject (json_obj, "ttl", atoi(ptmp->ttl));
        }

        out = cJSON_PrintUnformatted (root);
        if(out)
        {
            pri_debug("traceroute report: %s\n", out);
        }

        cJSON_Delete (root);
    }

    return out;
}
