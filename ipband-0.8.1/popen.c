/* popen.c   secure popen: code mix from Richard Stevens and ntop source 
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

#include <sys/wait.h>
#include <limits.h>
#include <fcntl.h>

#include "ipband.h"

#define __SEC_POPEN_TOKEN " "

static pid_t	*childpid = NULL;    /* ptr to array allocated at run-time */
static int	maxfd;

/* popen() substitute */
FILE * sec_popen(const char *cmd, const char *type) {

	char 		**argv, *ptr, *strtokState;
	char		*cmdcpy = NULL;
	int		i, pfd[2];
	pid_t		pid;
	FILE		*fp;

  	if(cmd == NULL || cmd == "")
		return(NULL);

	if ((type[0] != 'r' && type[0] != 'w') || type[1] != 0) {
		errno = EINVAL;		/* required by POSIX.2 */
		return(NULL);
	}

  	if((cmdcpy = strdup(cmd)) == NULL)
		return(NULL);

  	argv = NULL;

	if((ptr = strtok_r(cmdcpy, __SEC_POPEN_TOKEN, &strtokState)) == NULL) {
		free(cmdcpy);
		return(NULL);
  	}

	for(i = 0;; i++) {
	   if((argv = (char **)realloc(argv, (i+1) * sizeof(char*))) == NULL) {
	      free(cmdcpy);
	      return(NULL);
    	   }

	   if((*(argv+i) = (char*)malloc((strlen(ptr)+1) * sizeof(char))) == NULL) {
	     free(cmdcpy);
	     return(NULL);
	   }

	   strcpy(argv[i], ptr);

	   if((ptr = strtok_r(NULL, __SEC_POPEN_TOKEN, &strtokState)) == NULL) {
	      if((argv = (char **) realloc(argv, (i+2) * sizeof(char*))) == NULL) {
	         free(cmdcpy);
	   	 return(NULL);
              }
              argv[i+1] = NULL;
              break;
	   }
	}

	free(cmdcpy);

	if (childpid == NULL) {		/* first time through */

		/* allocate zeroed out array for child pids */
		maxfd = open_max();
		if ( (childpid = calloc(maxfd, sizeof(pid_t))) == NULL)
			return(NULL);
	}

	if (pipe(pfd) < 0)
		return(NULL);	/* errno set by pipe() */

	if ( (pid = fork()) < 0)
		return(NULL);	/* errno set by fork() */

	else if (pid == 0) {	/* child */

	   if((getuid() != geteuid()) || (getgid() != getegid())) {

		/* setuid binary, drop privileges */
		if (setgid(getgid()) != 0 || setuid(getuid()) != 0) 
			err_sys("Error dropping privileges");

	   }

		if (*type == 'r') {
			close(pfd[0]);
			if (pfd[1] != STDOUT_FILENO) {
				dup2(pfd[1], STDOUT_FILENO);
				close(pfd[1]);
			}
		} else {
			close(pfd[1]);
			if (pfd[0] != STDIN_FILENO) {
				dup2(pfd[0], STDIN_FILENO);
				close(pfd[0]);
			}
		}

		/* close all descriptors in childpid[] */
		for (i = 0; i < maxfd; i++)
			if (childpid[i] > 0)
				close(i);


	if(strchr(argv[0], '/') == NULL)
		execvp(argv[0], argv);  /* search in $PATH */
	else
		execv(argv[0], argv);

		_exit(127);

	} 		/* parent */
	if (*type == 'r') {
		close(pfd[1]);
		if ( (fp = fdopen(pfd[0], type)) == NULL)
			return(NULL);
	} else {
		close(pfd[0]);
		if ( (fp = fdopen(pfd[1], type)) == NULL)
			return(NULL);
	}
	childpid[fileno(fp)] = pid;	/* remember child pid for this fd */
	return(fp);
}

int sec_pclose(FILE *fp) {

	int	fd, stat;
	pid_t	pid;

	if (childpid == NULL)
		return(-1);		/* popen() has never been called */

	fd = fileno(fp);
	if ( (pid = childpid[fd]) == 0)
		return(-1);		/* fp wasn't opened by popen() */

	childpid[fd] = 0;
	if (fclose(fp) == EOF)
		return(-1);

	while (waitpid(pid, &stat, 0) < 0)
		if (errno != EINTR)
			return(-1);	/* error other than EINTR from waitpid() */

	return(stat);	/* return child's termination status */
}


/* Determine maximum number of open files */

#ifdef	OPEN_MAX
static int	openmax = OPEN_MAX;
#else
static int	openmax = 0;
#endif

#define	OPEN_MAX_GUESS	256		/* if OPEN_MAX is indeterminate */
					/* we're not guaranteed this is adequate */
int open_max(void)
{
	if (openmax == 0) {		/* first time through */
	   errno = 0;

	   if ( (openmax = sysconf(_SC_OPEN_MAX)) < 0) {
		if (errno == 0)
			openmax = OPEN_MAX_GUESS;	/* it's indeterminate */
		else
			err_sys("sysconf error for _SC_OPEN_MAX");
  	   }
	}

	return(openmax);
}
