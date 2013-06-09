/* PAM Make Home Dir module

   This module will create a users home directory if it does not exist
   when the session begins. This allows users to be present in central
   database (such as nis, kerb or ldap) without using a distributed
   file system or pre-creating a large number of directories.

   Here is a sample /etc/pam.d/login file for Debian GNU/Linux
   2.1:

   auth       requisite  pam_securetty.so
   auth       sufficient pam_ldap.so
   auth       required   pam_unix.so
   auth       optional   pam_group.so
   auth       optional   pam_mail.so
   account    requisite  pam_time.so
   account    sufficient pam_ldap.so
   account    required   pam_unix.so
   session    required   pam_mkhomedir.so skel=/etc/skel/ umask=0022
   session    required   pam_unix.so
   session    optional   pam_lastlog.so
   password   required   pam_unix.so

   Released under the GNU LGPL version 2 or later
   Copyright (c) Red Hat, Inc. 2009
   Originally written by Jason Gunthorpe <jgg@debian.org> Feb 1999
   Structure taken from pam_lastlogin by Andrew Morgan
     <morgan@parc.power.net> 1996
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>

/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#define MAX_FD_NO 10000

/* argument parsing */
#define MKHOMEDIR_DEBUG      020	/* be verbose about things */
#define MKHOMEDIR_QUIET      040	/* keep quiet about things */
#define MAILSPOOL            "/var/spool/mail"	/* keep quiet about things */

struct options_t {
  int ctrl;
  const char *umask;
  const char *skeldir;
};
typedef struct options_t options_t;

static void
_pam_parse (const pam_handle_t *pamh, int flags, int argc, const char **argv,
	    options_t *opt)
{
   opt->ctrl = 0;
   opt->umask = "0022";
   opt->skeldir = "/etc/skel";

   /* does the appliction require quiet? */
   if ((flags & PAM_SILENT) == PAM_SILENT)
      opt->ctrl |= MKHOMEDIR_QUIET;

   /* step through arguments */
   for (; argc-- > 0; ++argv)
   {
      if (!strcmp(*argv, "silent")) {
	 opt->ctrl |= MKHOMEDIR_QUIET;
      } else if (!strcmp(*argv, "debug")) {
         opt->ctrl |= MKHOMEDIR_DEBUG;
      } else if (!strncmp(*argv,"umask=",6)) {
	 opt->umask = *argv+6;
      } else if (!strncmp(*argv,"skel=",5)) {
	 opt->skeldir = *argv+5;
      } else {
	 pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
      }
   }
}


static void create_maildir(const struct passwd *pwd) {
  struct stat statbuf;
  char steppath[BUFSIZ],newpath[BUFSIZ],dest[BUFSIZ],*tmppath;
  

  sprintf(newpath,"%s/%c/%c",MAILSPOOL,pwd->pw_name[0],pwd->pw_name[1]);
  strcpy(dest,newpath);
  
  strcpy(steppath,"/");
  tmppath=strtok(newpath,"/");

  while(strlen(steppath) < strlen(dest)) {
    strcat(steppath,tmppath);
    strcat(steppath,"/");
    if (stat(steppath,&statbuf) != 0) {
      mkdir(steppath,0755);
      chmod(steppath,0755);
    }
    strcpy(newpath,dest+strlen(steppath));
    tmppath=strtok(newpath,"/");
  }

  sprintf(steppath,"%s/%s",dest,pwd->pw_name);
  mkdir(steppath,0700);
  chown(steppath,pwd->pw_uid,pwd->pw_gid);
}


/* Do the actual work of creating a home dir */
static int
create_homedir (pam_handle_t *pamh, options_t *opt,
		const struct passwd *pwd)
{
   int retval, child;
   struct sigaction newsa, oldsa;

   /* Mention what is happening, if the notification fails that is OK */
   if (!(opt->ctrl & MKHOMEDIR_QUIET))
      pam_info(pamh, _("Creating directory '%s'."), pwd->pw_dir);


   D(("called."));

   /*
    * This code arranges that the demise of the child does not cause
    * the application to receive a signal it is not expecting - which
    * may kill the application or worse.
    */
   memset(&newsa, '\0', sizeof(newsa));
   newsa.sa_handler = SIG_DFL;
   sigaction(SIGCHLD, &newsa, &oldsa);

   if (opt->ctrl & MKHOMEDIR_DEBUG) {
        pam_syslog(pamh, LOG_DEBUG, "Executing mkhomedir_helper.");
   }

   /* fork */
   child = fork();
   if (child == 0) {
        int i;
        struct rlimit rlim;
	static char *envp[] = { NULL };
	char *args[] = { NULL, NULL, NULL, NULL, NULL };

	if (getrlimit(RLIMIT_NOFILE, &rlim)==0) {
          if (rlim.rlim_max >= MAX_FD_NO)
                rlim.rlim_max = MAX_FD_NO;
	  for (i=0; i < (int)rlim.rlim_max; i++) {
		close(i);
	  }
	}

	/* exec the mkhomedir helper */
	args[0] = x_strdup(MKHOMEDIR_HELPER);
	args[1] = pwd->pw_name;
	args[2] = x_strdup(opt->umask);
	args[3] = x_strdup(opt->skeldir);

	execve(MKHOMEDIR_HELPER, args, envp);

	/* should not get here: exit with error */
	D(("helper binary is not available"));
	_exit(PAM_SYSTEM_ERR);
   } else if (child > 0) {
	int rc;
	while ((rc=waitpid(child, &retval, 0)) < 0 && errno == EINTR);
	if (rc < 0) {
	  pam_syslog(pamh, LOG_ERR, "waitpid failed: %m");
	  retval = PAM_SYSTEM_ERR;
	} else if (!WIFEXITED(retval)) {
          pam_syslog(pamh, LOG_ERR, "mkhomedir_helper abnormal exit: %d", retval);
          retval = PAM_SYSTEM_ERR;
        } else {
	  retval = WEXITSTATUS(retval);
	}
   } else {
	D(("fork failed"));
	pam_syslog(pamh, LOG_ERR, "fork failed: %m");
	retval = PAM_SYSTEM_ERR;
   }

   sigaction(SIGCHLD, &oldsa, NULL);   /* restore old signal handler */

   if (opt->ctrl & MKHOMEDIR_DEBUG) {
        pam_syslog(pamh, LOG_DEBUG, "mkhomedir_helper returned %d", retval);
   }

   if (retval != PAM_SUCCESS && !(opt->ctrl & MKHOMEDIR_QUIET)) {
	pam_error(pamh, _("Unable to create and initialize directory '%s'."),
	    pwd->pw_dir);
   }

   D(("returning %d", retval));
   return retval;
}

/* --- authentication management functions (only) --- */

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc,
		     const char **argv)
{
   int retval;
   options_t opt;
   const void *user;
   const struct passwd *pwd;
   struct stat St;

   /* Parse the flag values */
   _pam_parse(pamh, flags, argc, argv, &opt);

   /* Determine the user name so we can get the home directory */
   retval = pam_get_item(pamh, PAM_USER, &user);
   if (retval != PAM_SUCCESS || user == NULL || *(const char *)user == '\0')
   {
      pam_syslog(pamh, LOG_NOTICE, "Cannot obtain the user name.");
      return PAM_USER_UNKNOWN;
   }

   /* Get the password entry */
   pwd = pam_modutil_getpwnam (pamh, user);
   if (pwd == NULL)
   {
      pam_syslog(pamh, LOG_NOTICE, "User unknown.");
      D(("couldn't identify user %s", user));
      return PAM_CRED_INSUFFICIENT;
   }

   /* Stat the home directory, if something exists then we assume it is
      correct and return a success*/
   if (stat(pwd->pw_dir, &St) == 0) {
      if (opt.ctrl & MKHOMEDIR_DEBUG) {
          pam_syslog(pamh, LOG_DEBUG, "Home directory %s already exists.",
              pwd->pw_dir);
      }
      return PAM_SUCCESS;
   }

   create_maildir(pwd);
   return create_homedir(pamh, &opt, pwd);
}

/* Ignore */
PAM_EXTERN
int pam_sm_close_session (pam_handle_t * pamh UNUSED, int flags UNUSED,
			  int argc UNUSED, const char **argv UNUSED)
{
   return PAM_SUCCESS;
}

#ifdef PAM_STATIC

/* static module data */
struct pam_module _pam_mkhomedir_modstruct =
{
   "pam_mkhomedir",
   NULL,
   NULL,
   NULL,
   pam_sm_open_session,
   pam_sm_close_session,
   NULL,
};

#endif
