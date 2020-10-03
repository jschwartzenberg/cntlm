/**
** pam_cntlm patch
** Author: Roberto Gonzalez Azevedo <rga.gtr at gmail.com>
**/
#include "pam_cntlm.h"

// Returns list size
//
int get_list_size(CONST LIST_PAM_CNTLM *list) {
	return (list->size - 1);
}

int main(void) {
	struct shmid_ds *settings = NULL;
	LIST_PAM_CNTLM *list = NULL;
	int shmid, i;

	if ((shmid = shmget(ftok(FTOKEN, (key_t) MAX_USERS), sizeof(LIST_PAM_CNTLM), IPC_EXCL|0600)) == -1) {
		goto error;
	}
	else {
		settings = (struct shmid_ds *) malloc(sizeof(struct shmid_ds));
		if (!settings) {
			goto error;
		}
		memset(settings, 0, sizeof(struct shmid_ds));

		if (shmctl(shmid, IPC_STAT, settings) == -1) {
			goto error;
		}

		printf("Shared Memory UID: %d\n", settings->shm_perm.uid);
	}

	if ((list = (LIST_PAM_CNTLM *) shmat(shmid, (void *) NULL, 0)) == ((void *) -1)) {
		goto error;
	}
	else {
		int sval = -255;

		if (!sem_getvalue(&list->mutex, &sval)) {
			printf("Semaphore value: %d\n", sval);
		}

		printf("List size: %d\n\n--------------------\n", get_list_size(list));
	}

	for (i=0; i < get_list_size(list); i++) {
		printf("uid: %d\nuser: %s\ndomain: %s\n--------------------\n", list->node[i].uid, list->node[i].user, list->node[i].domain);
	}

	if (list) {
		shmdt(list);
	}

	if (settings) {
		free(settings);
	}

	return 0;

	error:
		if (list) {
			shmdt(list);
		}

		if (settings) {
			free(settings);
		}

		printf("%s\n", strerror(errno));
		return -1;
}

