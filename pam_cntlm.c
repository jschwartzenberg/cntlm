/*
** pam_cntlm patch
** Author: Roberto Gonzalez Azevedo <rga.gtr at gmail.com>
*/
#include "pam_cntlm.h"

static unsigned short int verbose = 0;
extern int debug;

/*
** Update thread local authentication struct (struct auth_s), replacing default config file
** parameters like username, password, domain and so on with values collected from shared memory.
*/
void update_creds(struct auth_s *tcreds, int cd) {
	LIST_PAM_CNTLM *list = NULL;
	char *client_uid = NULL;
	int shmid = -1;
	unsigned short int notok = 1;

	/*
	** Only if cntlm has been configured to use shared memory (cntlm -Z).
	*/
	if (sharedmemory) {
		int index = -1;

		// Get Shared Memory
		//
		if ((shmid = shmget(ftok(FTOKEN, (key_t) MAX_USERS), sizeof(LIST_PAM_CNTLM), IPC_EXCL|0600)) == -1) {
			goto bailout;
		}

		// Attach it
		//
		if ((list = (LIST_PAM_CNTLM *) shmat(shmid, NULL, 0)) == NULL) {
			goto bailout;
		}

		/*
		** Search user's uid in PROC_NET_TCP or PROC_NET_TCP6 through its tcp socket port.
		** First we'll get client's hostname and tcp port, then compare it
		** against the username which has been stored before by 'pam_cntlm'.
		*/
		client_uid = get_client_uid(cd, AF_INET);
		if (!client_uid) {
			client_uid = get_client_uid(cd, AF_INET6);
		}

		if (!client_uid) {
			if (debug) {
				printf("\n=--------------------=\npam_cntlm: get_client_uid(): User hasn't been found.\n=--------------------=\n");
			}

			goto bailout; // User hasn't been found...
		}

		// Semaphore, wait (down) - Critical section
		//
		if (sem_wait(&list->mutex)) {
			goto bailout;
		}

		// Now, we have client's uid. Let's check if it can be found in the list.
		//
		if ((index = search(list, atoi(client_uid))) == -1) {
			goto bailout;
		}

		// OK!!! It's time to update 'tcreds' !!!
		//
		strncpy(tcreds->user, list->node[index].user, MINIBUF_SIZE);
		strncpy(tcreds->domain, list->node[index].domain, MINIBUF_SIZE);
		strncpy(tcreds->passlm, list->node[index].passlm, MINIBUF_SIZE);
		strncpy(tcreds->passnt, list->node[index].passnt, MINIBUF_SIZE);
		strncpy(tcreds->passntlm2, list->node[index].passntlm2, MINIBUF_SIZE);

		// Semaphore, post (up) - End of critical section
		//
		if (sem_post(&list->mutex)) {
			goto bailout;
		}

		if (debug) {
			printf("\n=------ pam_cntlm: getuid: %d geteuid: %d ------=\n", (int) getuid(), (int) geteuid());
			printf("=-------------------------------------=\npam_cntlm: User uid (from shared memory): %s\n\n", client_uid);
			dump_auth(tcreds);
			printf("=-------------------------------------=\n");
		}

		notok = 0; // Everything is OK

	} // if(sharedmemory)

	bailout:
		if (list) {
			if (notok) {
				int sval = -255;

				if (!sem_getvalue(&list->mutex, &sval)) {
					if (!sval) {
						sem_init(&list->mutex, 1, 1); //Initialize semaphore again (avoiding deadlocks or starvation)
					}
				}
			}
			shmdt(list);
		}

		if (client_uid) {
			free(client_uid);
		}
}

/*
** Search user's uid in PROC_NET_TCP or PROC_NET_TCP6 through its tcp socket port.
** First we'll get client's hostname and tcp port, then compare it
** against the username which has been stored before by 'pam_cntlm'.
**
** Returns a pointer to client uid (char *) or NULL
*/
char *get_client_uid(int sockfd, sa_family_t ss_family) {
	FILE *fp = NULL;
	char *line_buf = NULL;
	char *client_uid = NULL;
	char *uid = NULL;
	char *client_host_tcp_port = NULL;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_len = sizeof(struct sockaddr_storage);
	int line_fd, client_host_tcp_port_len, proc_net_tcp_first_column, proc_net_tcp_uid_column;
	size_t line_size;


	// Retrieve client's hostname and tcp port
	//
	if (getpeername(sockfd, (struct sockaddr *) &client_addr, &client_addr_len) < 0) {
		goto error;
	}
	else {
		// IPv4 or IPv6 ?
		//
		client_host_tcp_port_len = (ss_family == AF_INET) ? CLIENT_HOST_TCP_PORT_LEN : CLIENT_HOST_TCP_PORT_LEN6;

		client_host_tcp_port = (char *) malloc(client_host_tcp_port_len);
		if (!client_host_tcp_port) {
			goto error;
		}
		memset(client_host_tcp_port, 0, client_host_tcp_port_len);

		if (ss_family == AF_INET) {
			struct sockaddr_in *s = (struct sockaddr_in *) &client_addr;

			// IPv4
			proc_net_tcp_first_column = PROC_NET_TCP_FIRST_COLUMN;
			proc_net_tcp_uid_column = PROC_NET_TCP_UID_COLUMN;

			snprintf(client_host_tcp_port, client_host_tcp_port_len, "%08X:%04X", s->sin_addr.s_addr, ntohs(s->sin_port));
		}
		else {
			struct sockaddr_in *s = (struct sockaddr_in *) &client_addr;

			// IPv6
			proc_net_tcp_first_column = PROC_NET_TCP_FIRST_COLUMN6;
			proc_net_tcp_uid_column = PROC_NET_TCP_UID_COLUMN6;

			snprintf(client_host_tcp_port, client_host_tcp_port_len, "%s:%04X", ((s->sin_addr.s_addr == 16777343) ? "0000000000000000FFFF00000100007F" : "NULL"), ntohs(s->sin_port));
		}
	}

	/*
	** Search user's uid in PROC_NET_TCP or PROC_NET_TCP6 through its tcp socket port.
	** First we'll get client's hostname and tcp port, then compare it
	** against the username which has been stored before by 'pam_cntlm'.
	*/

	// Open PROC_NET_TCP or PROC_NET_TCP6
	//
	fp = (ss_family == AF_INET) ? fopen(PROC_NET_TCP, "r") : fopen(PROC_NET_TCP6, "r");
	if (!fp) {
		goto error;
	}

	// Discards the first line...
	//
	if ((line_fd = getline(&line_buf, &line_size, fp)) == -1) {
		goto error;
	}

	// Retrieve client's uid (only works with local connections)
	//
	while ((line_fd = getline(&line_buf, &line_size, fp)) != -1) {
		if (!strncmp(line_buf+proc_net_tcp_first_column, client_host_tcp_port, client_host_tcp_port_len-1)) {
			line_buf[proc_net_tcp_uid_column] = '\0';
			client_uid = line_buf + proc_net_tcp_uid_column;

			while (*(client_uid-1) != ' ' && client_uid > line_buf) {
				client_uid--; // Rewind pointer until a space value (' ') comes out
			}
			break;
		}
	}

	if (client_uid) {
		uid = (char *) malloc(strlen(client_uid) + 1);
		if (!client_host_tcp_port) {
			goto error;
		}
		memset(uid, 0, strlen(client_uid) + 1);

		if (!strcpy(uid, client_uid)) {
			goto error;
		}
	}


	if (client_host_tcp_port) {
		free(client_host_tcp_port);
	}

	if (line_buf) {
		free(line_buf);
	}

	if (fp) {
		fclose(fp);
	}

	return uid;


	error:
		if (client_host_tcp_port) {
			free(client_host_tcp_port);
		}

		if (line_buf) {
			free(line_buf);
		}

		if (fp) {
			fclose(fp);
		}

		if (uid) {
			free(uid);
		}

		return NULL;
}

/*
** Down semaphore
*/
int semaphore_down(sem_t *mutex) {
	int ret;

	// Semaphore, wait (down) - Critical section
	//
	if ((ret = sem_wait(mutex))) {
		PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Error: down semaphore\n");
	}
	else {
		if (verbose) {
			int sval = -255;

			if (!(ret = sem_getvalue(mutex, &sval))) {
				syslog(LOG_ERR, "pam_cntlm: Semaphore down. Critical section. Value: %d\n", sval);
			}
			else {
				syslog(LOG_ERR, "pam_cntlm: Error: Couldn't get semaphore value... Probably it's down... [ sem_getvalue ]\n");
			}
		}
	}

	return ret;
}

/*
** Up semaphore
*/
int semaphore_up(sem_t *mutex) {
	int ret;

	// Semaphore, post (up) - End of critical section
	//
	if ((ret = sem_post(mutex))) {
		PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Error: up semaphore\n");
	}
	else {
		if (verbose) {
			int sval = -255;

			if (!(ret = sem_getvalue(mutex, &sval))) {
				syslog(LOG_ERR, "pam_cntlm: Semaphore up. End of critical section. Value: %d\n", sval);
			}
			else {
				syslog(LOG_ERR, "pam_cntlm: Error: Couldn't get semaphore value... Probably it's up... [ sem_getvalue ]\n");
			}
		}
	}

	return ret;
}

/*
** Malloc and clear a new memory block.
**
** Returns a pointer to recently malloc'ed and cleared block.
*/
void *myalloc(size_t size) {
	void *allocated = NULL;

	allocated = malloc(size);

	if (allocated) {
		memset(allocated, 0, size);
	}

	return allocated;
}

/*
** Clean, free and disable pointer.
*/
void forget(void **p, size_t size) {
	if (*p) {
		if (size > 0) {
			memset(*p, 0, size);
		}
		free(*p);
		*p = NULL;
	}
}

void forget_llist(LLIST *llist) {
	LLIST *temp = NULL;

	while(llist) {
		temp = llist;
		llist = temp->next;
		FORGET(temp, sizeof(LLIST));
	}
}

/*
** Add user into the linked-list
**
** Returns:
**
**	1 -> User has been successfully added
**	0 -> Couldn't add user to the linked-list
*/
int add_llist(LLIST **head, char *user) {
	LLIST *item = NULL;

	if (!(item = (LLIST *) myalloc(sizeof(LLIST)))) {
		goto error;
	}

	if (!strncpy(item->user, user, MINIBUF_SIZE)) {
		goto error;
	}

	item->next = *head;
	*head = item;

	return 1;

	error:
		PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Couldn't add a new node to linked list [ cleanup_list ]\n");

		forget_llist(*head);
		return 0;
}

/*
** Search user in linked-list
**
** Returns:
**
**	1 -> found
**	0 -> not found
*/
int search_llist(CONST LLIST *llist, char *user) {
	if (!llist->next) {
		return !strncmp(llist->user, user, MINIBUF_SIZE);
	}
	else {
		return (!strncmp(llist->user, user, MINIBUF_SIZE)) ? 1 : search_llist(llist->next, user);
	}
}

/*
** Get current logged users
**
** Returns a pointer to the logged user's linked-list, or NULL instead
*/
LLIST *get_list_logged_users(void) {
	LLIST *head = NULL;
	struct utmp *u = NULL;

	if (!(head = (LLIST *) myalloc(sizeof(LLIST)))) {
		goto error;
	}

	setutent();
	for (;;) {
		if (!(u = getutent())) {
			break;
		}

                if (u->ut_type != USER_PROCESS) {
                        continue;
		}
		else {
			if (!search_llist(head, u->ut_user)) {
				if (!add_llist(&head, u->ut_user)) {
					goto error;
				}
			}
		}
	}
	endutent();

	return head;

	error:
		PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Couldn't get a list of logged users [ cleanup_list ]\n");

		forget_llist(head);
		return NULL;
}

/*
** Cleanup list (if its full)
**
** Return:
**
**	0 -> Error
**	1 -> Okay. List has been cleaned properly
*/
int cleanup_list(LIST_PAM_CNTLM *list) {
	LLIST *llusers = NULL;
	NODE_PAM_CNTLM *new = NULL;
	unsigned int i, index;

	if (!(llusers = get_list_logged_users())) {
		goto error;
	}

	if (!(new = (NODE_PAM_CNTLM *) myalloc((MAX_USERS * sizeof(NODE_PAM_CNTLM))))) {
		goto error;
	}

	// Semaphore, wait (down) - Critical section
	//
	if (semaphore_down(&list->mutex)) {
		goto error;
	}

	index = 0;
	for (i=0; i < MAX_USERS; i++) {
		if (strlen(list->node[i].user)) {
			if (search_llist(llusers, list->node[i].user)) {
				if (!memcpy(&new[index++], &list->node[i], sizeof(NODE_PAM_CNTLM))) {
					goto error;
				}
			}
		}
	}

	if (!memcpy(list->node, new, (MAX_USERS * sizeof(NODE_PAM_CNTLM)))) {
		goto error;
	}

	list->size = index + 1;

	// Semaphore, post (up) - End of critical section
	//
	if (semaphore_up(&list->mutex)) {
		goto error;
	}

	forget_llist(llusers);
	FORGET(new, (MAX_USERS * sizeof(NODE_PAM_CNTLM)));

	return 1;

	error:
		forget_llist(llusers);
		FORGET(new, (MAX_USERS * sizeof(NODE_PAM_CNTLM)));

		if (list) {
			int sval = -255;

			if (!sem_getvalue(&list->mutex, &sval)) {
				if (!sval) {
					if (verbose) {
						syslog(LOG_ERR, "pam_cntlm: Semaphore old value: %d [ cleanup_list ] Initializing it again (try to avoid deadlocks or starvation)\n", sval);
					}

					sem_init(&list->mutex, 1, 1); // Initialize semaphore again (avoiding deadlocks or starvation)
				}
			}
		}
		return 0;
}

/*
** Returns list size
*/
int get_list_size(CONST LIST_PAM_CNTLM *list) {
	return (list->size - 1);
}

/*
** Search for user in list through its uid
*/
int search(CONST LIST_PAM_CNTLM *list, uid_t uid) {
	int index = -1;

	if (get_list_size(list) < 1) {
		return -1;
	}

	for (index=0; index < get_list_size(list) || index < MAX_USERS; index++) {
		if (list->node[index].uid == uid) {
			return index;
		}
	}

	//User uid hasn't been found
	//
	return -1;
}

/*
** Update user node through its index
*/
int update_user(LIST_PAM_CNTLM *list, int index, uid_t uid, CONST char *user, CONST char *domain, CONST char *password) {
	char *hash = NULL;

	//UID
	//
	if (list->node[index].uid != uid) {
		list->node[index].uid = uid;
	}

	//Username
	//
	if (strncmp(list->node[index].user, user, MINIBUF_SIZE)) {
		if (!strncpy(list->node[index].user, user, MINIBUF_SIZE)) {
			goto error;
		}
	}

	//Domain
	//
	if (strncmp(list->node[index].domain, domain, MINIBUF_SIZE)) {
		if (!strncpy(list->node[index].domain, domain, MINIBUF_SIZE)) {
			goto error;
		}
	}

	//LM
	//
	if ((hash = ntlm_hash_lm_password((char *) password))) {
		if (strncmp(list->node[index].passlm, hash, MINIBUF_SIZE)) {
			if (!strncpy(list->node[index].passlm, hash, MINIBUF_SIZE)) {
				goto error;
			}
		}
		FORGET(hash, strlen(hash));
	}

	//NTLM
	//
	if ((hash = ntlm_hash_nt_password((char *) password))) {
		if (strncmp(list->node[index].passnt, hash, MINIBUF_SIZE)) {
			if (!strncpy(list->node[index].passnt, hash, MINIBUF_SIZE)) {
				goto error;
			}
		}
		FORGET(hash, strlen(hash));
	}

	//NTLMv2
	//
	if ((hash = ntlm2_hash_password((char *) user, (char *) domain, (char *) password))) {
		if (strncmp(list->node[index].passntlm2, hash, MINIBUF_SIZE)) {
			if (!strncpy(list->node[index].passntlm2, hash, MINIBUF_SIZE)) {
				goto error;
			}
		}
		FORGET(hash, strlen(hash));
	}

	return index;

	error:
		if (hash) {
			FORGET(hash, strlen(hash));
		}
		return -1;
}

/*
** Add username to list and increments it's size (only if everything is alright)
*/
int add_user(LIST_PAM_CNTLM *list, uid_t uid, CONST char *user, CONST char *domain, CONST char *password) {
	int index = -1;

	if (get_list_size(list) >= MAX_USERS) {
		return -1;
	}
	else {
		if (!get_list_size(list)) {
			index = update_user(list, 0, uid, user, domain, password); //The very first user to be added to the list
		}
		else {
			index = update_user(list, get_list_size(list), uid, user, domain, password);
		}
	}

	if (index < 0) {
		return index;
	}
	else {
		//Update list size
		//
		list->size++;

		return index;
	}
}

/*
** Get password from the user directly
*/
int get_password(pam_handle_t *pamh, char *password) {
	CONST struct pam_conv *conv = NULL;
	CONST struct pam_message *msg[NUM_MSG];
	struct pam_message resp_msg;
	struct pam_response *resp = NULL;
	int retval;

	for (retval=0; retval <= NUM_MSG; retval++) {
		msg[retval] = NULL;
	}

	memset(&resp_msg, 0, sizeof(struct pam_message));
	resp_msg.msg_style = PAM_PROMPT_ECHO_OFF;
	resp_msg.msg = "Password: ";

	msg[0] = &resp_msg;

	if ((retval = pam_get_item(pamh, PAM_CONV, (CONST void **) &conv)) != PAM_SUCCESS) {
		goto error;
	}
	if (!conv) {
		goto error;
	}

	if ((retval = conv->conv(NUM_MSG, msg, &resp, conv->appdata_ptr)) != PAM_SUCCESS) {
		goto error;
	}

	if (!resp) {
		retval = PAM_SYSTEM_ERR;
		goto error;
	}
	else if (!resp->resp) {
		retval = PAM_SYSTEM_ERR;
		goto error;
	}
	else {
		if (!strncpy(password, resp->resp, MINIBUF_SIZE)) {
			goto error;
		}

		free(resp->resp);
		free(resp);
	}

	return PAM_SUCCESS;

	error:
		syslog(LOG_ERR, "pam_cntlm: Error in get_password: %s (%d)\n", pam_strerror(pamh, retval), retval);

		if (resp) {
			if (resp->resp) {
				free(resp->resp);
			}
			free(resp);
		}

		return retval;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, CONST char **argv) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, CONST char **argv) {
	LIST_PAM_CNTLM *list = NULL;
	CONST char *user = NULL;
	char *password = NULL;
	char *domain = NULL;
	char *cntlm_user = NULL;
	struct shmid_ds *settings = NULL;
	struct passwd *pwd = NULL;
	int shmid = -2, retval = -2, index = -2, malloc_password = 0;
	unsigned short int notok = 1;


	// Get cntlm daemon's user and PAM user's domain (through **argv).
	// If **argv isn't set, use the defaults values.
	//
	domain = (char *) myalloc(MINIBUF_SIZE);
	if (!domain) {
		goto error;
	}
	if (!strncpy(domain, DOMAIN, MINIBUF_SIZE)) {
		goto error;
	}

	cntlm_user = (char *) myalloc(MINIBUF_SIZE);
	if (!cntlm_user) {
		goto error;
	}
	if (!strncpy(cntlm_user, CNTLM_USER, MINIBUF_SIZE)) {
		goto error;
	}

	for (; argc-- > 0; ++argv) {
		if (!strncmp(*argv, "domain=", strlen("domain="))) {
			if (!strncpy(domain, (*argv)+strlen("domain="), MINIBUF_SIZE)) {
				goto error;
			}
		}

		if (!strncmp(*argv, "user=", strlen("user="))) {
			if (!strncpy(cntlm_user, (*argv)+strlen("user="), MINIBUF_SIZE)) {
				goto error;
			}
		}

		if (!strncmp(*argv, "verbose=", strlen("verbose="))) {
			// Set global variable
			//
			verbose = (!strncmp((*argv)+strlen("verbose="), VERBOSE, strlen(VERBOSE))) ? 1 : 0;
		}
	}

	PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: started.\n");

	// Get PAM user
	//
	if ((retval = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Couldn't get PAM user [ pam_get_user ]\n");
		goto error;
	}
	else {
		if (verbose) {
			syslog(LOG_ERR, "pam_cntlm: Got user '%s' [ pam_get_user ]\n", user);
		}
	}

	// Only root's process can create/update this shared memory (gdm-login, ssh etc.).
	// Thus, all other user's process (gnome-screensaver-dialog etc.) will be skipped.
	//
	if (geteuid() != 0) {
		PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: UID is different from 0 (zero) [ geteuid ]. Exiting ...\n");
		return PAM_SUCCESS;
	}
	else {
		PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: UID is equal to 0 (zero) [ geteuid ]. Continuing ...\n");
	}

	// Skip 'root' user
	//
	if (!strncmp(user, "root", strlen("root"))) {
		PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: User is 'root'. Exiting ...\n");
		return PAM_SUCCESS;
	}
	else {
		PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: User is not 'root'. Continuing ...\n");
	}

	if (verbose) {
		syslog(LOG_ERR, "pam_cntlm: Parameters: domain=%s  (shared memory's owner)user=%s  verbose=%s\n", domain, cntlm_user, (verbose) ? "yes" : "no");
	}

	// Get PAM user's password
	//
	if ((retval = pam_get_item(pamh, PAM_AUTHTOK, (CONST void **) &password)) != PAM_SUCCESS) {
		PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Couldn't get PAM password... [ pam_get_item(PAM_AUTHTOK) ]\n");
		goto error;
	}

	if (!password) {
		password = (char *) myalloc(MINIBUF_SIZE);
		if (!password) {
			goto error;
		}
		else {
			malloc_password = 1;
		}

		// Get password from user directly
		//
		if ((retval = get_password(pamh, password)) != PAM_SUCCESS) {
			PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Couldn't get PAM password from user directly... [ get_password ]\n");
			goto error;
		}
		else {
			PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Got PAM password from user [ get_password ]\n");

			// Update PAM_AUTHTOK to others PAM modules
			//
			if ((retval = pam_set_item(pamh, PAM_AUTHTOK, (CONST void *) password)) != PAM_SUCCESS) {
				PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Couldn't set PAM password to others PAM modules... [ pam_set_item(PAM_AUTHTOK) ]\n");
				goto error;
			}
			else {
				PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Sent PAM password to others PAM modules [ pam_set_item(PAM_AUTHTOK) ]\n");
			}
		}
	}

	// Create/Get Shared Memory
	//
	if ((shmid = shmget(ftok(FTOKEN, (key_t) MAX_USERS), sizeof(LIST_PAM_CNTLM), IPC_CREAT|0600)) == -1) {
		PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Couldn't get shared memory... [ shmget ]\n");
		goto error;
	}
	else {
		if (verbose) {
			syslog(LOG_ERR, "pam_cntlm: Shared memory id: %d [ shmget ]\n", shmid);
		}

		settings = (struct shmid_ds *) myalloc(sizeof(struct shmid_ds));
		if (!settings) {
			goto error; 
		}

		if (shmctl(shmid, IPC_STAT, settings) == -1) {
			PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Couldn't get shared memory info... [ shmctl(IPC_STAT) ]\n");
			goto error;
		}
		else {
			if (verbose) {
				syslog(LOG_ERR, "pam_cntlm: Shared memory's UID: %d [ settings->shm_perm.uid ]\n", (int) settings->shm_perm.uid);
			}

			// Retrieve cntlm daemon user's info in passwd, NIS, LDAP etc.
			//
			pwd = (struct passwd *) myalloc(sizeof(struct passwd));
			if (!pwd) {
				goto error;
			}

			memcpy(pwd, getpwnam(cntlm_user), sizeof(struct passwd));
			if (!pwd) {
				goto error;
			}

			if (verbose) {
				syslog(LOG_ERR, "pam_cntlm: CNTLM User '%s' has uid: %d [ getpwnam ]\n", cntlm_user, pwd->pw_uid);
			}

			if (settings->shm_perm.uid != pwd->pw_uid) {
				// Set UID
				//
				settings->shm_perm.uid = pwd->pw_uid;

				if (shmctl(shmid, IPC_SET, settings) == -1) {
					PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Couldn't set shared memory info... [ shmctl(IPC_SET) ]\n");
					goto error;
				}

				if (verbose) {
					syslog(LOG_ERR, "pam_cntlm: Shared memory's NEW UID: %d [ settings->shm_perm.uid ]\n", (int) settings->shm_perm.uid);
				}
			}
		}
	}
	
	// Attach it
	//
	if ((list = (LIST_PAM_CNTLM *) shmat(shmid, NULL, 0)) == ((void *) -1)) {
		PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Couldn't attach shared memory... [ shmat ]\n");
		goto error;
	}
	else {
		PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Shared memory successfully attached [ shmat ]\n");

		if (!list->size) {
			list->size++; // It's the very first time that we get that list

			PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: List has been initialized\n");

			if (sem_init(&list->mutex, 1, 1)) { // Initialize semaphore
				goto error;
			}

			PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Semaphore has been initialized\n");
		}
		else {
			if (verbose) {
				syslog(LOG_ERR, "pam_cntlm: Current list size: %d\n", get_list_size(list));
			}

			if (get_list_size(list) >= MAX_USERS) {// List is full, time to clean it up.
				PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: List is full, time to clean it up...\n");

				if (!cleanup_list(list)) {
					PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Couldn't cleanup list...\n");
					goto error;
				}
			}
		}
	}

	// Retrieve PAM user's info in passwd, NIS, LDAP etc.
	//
	if (!pwd) {
		pwd = (struct passwd *) myalloc(sizeof(struct passwd));
		if (!pwd) {
			goto error;
		}
	}
	memcpy(pwd, getpwnam(user), sizeof(struct passwd));
	if (!pwd) {
		goto error;
	}

	if (verbose) {
		syslog(LOG_ERR, "pam_cntlm: PAM user '%s' has uid: %d [ getpwnam ]\n", user, pwd->pw_uid);
	}

	// Semaphore, wait (down) - Critical section
	//
	if (semaphore_down(&list->mutex)) {
		goto error;
	}

	// Search PAM user in List. If user isn't found, add it to list; else update it's credentials.
	//
	if ((index = search(list, pwd->pw_uid)) < 0) {
		if (add_user(list, pwd->pw_uid, user, domain, password) < 0) {
			if (verbose) {
				syslog(LOG_ERR, "pam_cntlm: Error: PAM user '%s' (uid=%d) has NOT been added to list\n", user, pwd->pw_uid);
			}
			goto error;
		}
		else {
			if (verbose) {
				syslog(LOG_ERR, "pam_cntlm: PAM user '%s' (uid=%d) has been added to list\n", user, pwd->pw_uid);
			}
		}
	}
	else {
		if (update_user(list, index, pwd->pw_uid, user, domain, password) < 0) {
			if (verbose) {
				syslog(LOG_ERR, "pam_cntlm: Error: List entry for PAM user '%s' (uid=%d) has NOT been updated\n", user, pwd->pw_uid);
			}
			goto error;
		}
		else {
			if (verbose) {
				syslog(LOG_ERR, "pam_cntlm: List entry for PAM user '%s' (uid=%d) has been updated\n", user, pwd->pw_uid);
			}
		}
	}

	// Semaphore, post (up) - End of critical section
	//
	if (semaphore_up(&list->mutex)) {
		goto error;
	}

	notok = 0; // Everything is OK

	//Detach Shared Memory
	//
	if (shmdt(list) != 0) {
		PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Shared memory couldn't be properly detached [ shmdt ]\n");
		goto error;
	}
	else {
		PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: Shared memory has been properly detached [ shmdt ]\n");
	}

	//syslog(LOG_AUTHPRIV, "pam_cntlm: successful authentication for user %s (uid=%d)\n", user, pwd->pw_uid);
	syslog(LOG_ERR, "pam_cntlm: successful authentication for user %s (uid=%d)\n", user, pwd->pw_uid);

	FORGET(settings, sizeof(struct shmid_ds));
	FORGET(pwd, sizeof(struct passwd));
	FORGET(domain, MINIBUF_SIZE);
	FORGET(cntlm_user, MINIBUF_SIZE);

	if (malloc_password) {
		FORGET(password, MINIBUF_SIZE);
	}

	PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: ended.\n");

	return PAM_SUCCESS;

	error:
		syslog(LOG_ERR, "pam_cntlm: ERROR!!! user: %p password: %p shmid: %d list: %p settings: %p pwd: %p domain: %p cntlm_user: %p (list) index: %d\n", user, password, shmid, list, settings, pwd, domain, cntlm_user, index);

		if (malloc_password) {
			FORGET(password, MINIBUF_SIZE);
		}

		FORGET(settings, sizeof(struct shmid_ds));
		FORGET(pwd, sizeof(struct passwd));
		FORGET(domain, MINIBUF_SIZE);
		FORGET(cntlm_user, MINIBUF_SIZE);

		if (retval == PAM_SUCCESS) {
			syslog(LOG_ERR, "pam_cntlm: System Error => %s\n", strerror(errno));
		}
		else {
			syslog(LOG_ERR, "pam_cntlm: PAM Error => %s\n", pam_strerror(pamh, retval));
		}

		if (list) {
			if (notok) {
				int sval = -255;

				if (!sem_getvalue(&list->mutex, &sval)) {
					if (!sval) {
						if (verbose) {
							syslog(LOG_ERR, "pam_cntlm: Semaphore old value: %d Initializing it again (try to avoid deadlocks or starvation)\n", sval);
						}
						sem_init(&list->mutex, 1, 1); //Initialize semaphore again (avoiding deadlocks or starvation)
					}
				}
			}
			shmdt(list);
		}

		PAM_CNTLM_VERBOSE(LOG_ERR, "pam_cntlm: ended.\n");

		return (retval == PAM_SUCCESS) ? PAM_AUTH_ERR : retval;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_cntlm_modstruct = {
	"pam_cntlm",
	pam_sm_authenticate,
	pam_sm_setcred,
};
#endif
