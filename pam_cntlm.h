/**
** pam_cntlm patch
** Author: Roberto Gonzalez Azevedo <rga.gtr at gmail.com>
**/
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pwd.h>
#include <errno.h>
#include <semaphore.h>
#include <utmp.h>
//CNTLM
#include "utils.h"
#include "ntlm.h"
#include <netinet/in.h>

/*************************************************************************
 * Platform specific defines
 *************************************************************************/

#ifdef sun
#define PAM_EXTERN extern
/*
 *  On older versions of Solaris, you may have to change this to:
 *  #define CONST
 */
#define CONST const
#else
#define CONST const
#endif

#define PAM_SM_AUTH

#ifdef sun
#include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>

/* Uses MINIBUF_SIZE from 'utils.h' */

/* A simple linked-list
*/
struct LLIST {
	char user[MINIBUF_SIZE];
	struct LLIST *next;
};
typedef struct LLIST LLIST;


typedef struct {
	uid_t uid;
	char user[MINIBUF_SIZE];
	char domain[MINIBUF_SIZE];
	char passlm[MINIBUF_SIZE];
	char passnt[MINIBUF_SIZE];
	char passntlm2[MINIBUF_SIZE];
} NODE_PAM_CNTLM;

/* Uses pre-defined arrays, because shared memories doesn't like 'malloc()' or 'free()'.
   :(
*/

#define MAX_USERS 512

typedef struct {
	NODE_PAM_CNTLM node[MAX_USERS];
	unsigned int size;
	sem_t mutex;
} LIST_PAM_CNTLM;

#define NUM_MSG		1
#define FTOKEN		"/proc"
#define DOMAIN		"DOMAIN"
#define CNTLM_USER	"cntlm"
#define VERBOSE		"yes"

/*
** IPv4
*/
#define CLIENT_HOST_TCP_PORT_LEN	strlen("00000000:0000")+1
#define PROC_NET_TCP			"/proc/net/tcp"
#define PROC_NET_TCP_FIRST_COLUMN	6
#define PROC_NET_TCP_UID_COLUMN		81
/*
** IPv6
*/
#define CLIENT_HOST_TCP_PORT_LEN6	strlen("00000000000000000000000000000000:0000")+1
#define PROC_NET_TCP6			"/proc/net/tcp6"
#define PROC_NET_TCP_FIRST_COLUMN6	6
#define PROC_NET_TCP_UID_COLUMN6	129

#define FORGET(var, size)		do { if (var) { forget((void **) &(var), (size)); } } while (0)
#define PAM_CNTLM_VERBOSE(type, msg)	do { if (verbose) { syslog(type, msg); } } while (0)

extern int sharedmemory;

void update_creds(struct auth_s *tcreds, int cd);
char *get_client_uid(int sockfd, sa_family_t ss_family);

int semaphore_down(sem_t *mutex);
int semaphore_up(sem_t *mutex);

void *myalloc(size_t size);
void forget(void **p, size_t size);

void forget_llist(LLIST *llist);
int add_llist(LLIST **head, char *user);
int search_llist(CONST LLIST *llist, char *user);
LLIST *get_list_logged_users(void);
int cleanup_list(LIST_PAM_CNTLM *list);
int get_list_size(CONST LIST_PAM_CNTLM *list);
int search(CONST LIST_PAM_CNTLM *list, uid_t uid);
int update_user(LIST_PAM_CNTLM *list, int index, uid_t uid, CONST char *user, CONST char *domain, CONST char *password);
int add_user(LIST_PAM_CNTLM *list, uid_t uid, CONST char *user, CONST char *domain, CONST char *password);
int get_password(pam_handle_t *pamh, char *password);
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, CONST char **argv);
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, CONST char **argv);
ssize_t getline(char **lineptr, size_t *n, FILE *stream);

