#ifndef __TRACEROUTE_H
#define __TRACEROUTE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <netinet/in.h>

#ifdef __APPLE__
#include <netinet/ip.h>
#define ICMP_EXC_TTL IP_RECVTTL
#define ICMP_TIME_EXCEEDED ICMP_TIMXCEED
#endif

#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <string.h>
#include <ctype.h>

#define MAXJUMP 20      /**<Le nombre de saut max pour traceroute */
#define MAXTRY 4        /**<Le nombre max d'essays avant de passer au saut suivant */
#define MAXPACKET 4096  /**<La taille maximale */
#define SIZE_OPTION 8   /**<Option de taille des paquets a envoyer */
#define TIME_OPTION 16  /**<Option de temps entre chaque paquets envoye */
#define PORT_OPTION 32  /**<Option de sPort a utiliser */

#ifdef __ANDROID__
#define ICMP_EXC_TTL 0
#define ICMP_TIME_EXCEEDED 11
#endif

#define FAILURE -1
#define SUCCESS 0

struct ping_icmp_param
{
    int * sockfd;
    struct sockaddr_in * destination;
    unsigned int * size_data;
    struct timespec * time_bef;
    int pid;
    int seq;
};

struct pseudo_entete
{
    u_int32_t ip_source; // Adresse ip source
    u_int32_t ip_destination; // Adresse ip destination
    char mbz; // Champs ¨¤ 0
    char type; // Type de protocole
    u_int16_t length; // htons( Taille de l'entete Pseudo + Entete TCP ou UDP + Data )
};

typedef struct json_node_t
{
    char ip[20];//255.255.255.255
    char delay[16];//xxx.xxx ms
    char ttl[8];
    struct json_node_t* next;
}print_node_t;

typedef struct print_ctrl_tag
{
    print_node_t * head;
    print_node_t * current_node;
    int size;
}print_ctrl_t;


/**
 * \brief analyse le packet retourn¨¦ par le reseau
 * \param buf le buffer contenant le packet
 * \param size la taille du packet
 * \param doctorWho celui qui a envoy¨¦ le packet
 */
//void tracert_icmp(unsigned char* buf, unsigned int size, struct sockaddr_in* doctorWho, int ttl);
void tracert_icmp(unsigned char * buf, unsigned int size, struct sockaddr_in* doctorWho, int ttl, struct timespec *tbef, print_ctrl_t * print_obj);

/**
 * \brief ecrit et lance le packet sur le reseau
 */
void pinger_icmp(struct ping_icmp_param * papram);

/* traceroute the host
 * error : return -1
 * normal: return 0
 */
char * traceroute_report(const char * host);

struct timespec time_diff(struct timespec* begin, struct timespec* end);


/**
 * \brief affiche le numero puis 3 ¨¦toiles
 * \param i Un numero ¨¤ afficher
 */
void show_asterisk(int i, print_ctrl_t * print_obj);

/**
 * \brief test si ip appartient au tableau tab
 * \param ip  L'element a chercher
 * \param tab  Le tableau dans lequel chercher
 * \return 0 si n'appartient pas et 1 sinon
 */

int host_has_arrived(u_int32_t ip, u_int32_t *tab);


/**
 * \fn u_int16_t checksum(u_int16_t * icmp, int totalLength)
 * \brief Fonction servant au Checksum ICMP
 * \param icmp un paquet ICMP
 * \param totalLength la taille totale
 * \return le checksum du paquet ICMP
 */
u_int16_t check_sum(u_int16_t * icmp, int totalLength);
char* create_json_string_of_traceroute(print_ctrl_t *list);
int check_recv_packet(unsigned char * recv_buff, struct ping_icmp_param * papram);

#ifdef __cplusplus
}
#endif

#endif // __TRACEROUTE_H
