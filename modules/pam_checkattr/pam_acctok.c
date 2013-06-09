#define _GNU_SOURCE 1
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>

#include <ldap.h>
#include <lber.h>
#include "pam_ldap.h"

#define PAM_SM_ACCOUNT

#define CHECKATTR_DEBUG      020        /* keep quiet about things */
#define CHECKATTR_QUIET      040        /* keep quiet about things */

static char *ldapServer,*bindpasswd,*binddn;
static char attrcheck[BUFSIZ],basedn[BUFSIZ]="",searchfilter[BUFSIZ];
static int searchscope = LDAP_SCOPE_SUBTREE;
static int port = LDAP_PORT;

#include <security/pam_modules.h>
#include <security/_pam_macros.h>

static void _release_config (pam_ldap_config_t ** pconfig);
static int _read_config (const char *configFile,pam_ldap_config_t ** presult);
static int _alloc_config (pam_ldap_config_t ** presult);


static void _release_config (pam_ldap_config_t ** pconfig) {
  pam_ldap_config_t *c;

  c = *pconfig;
  if (c == NULL)
    return;

  binddn = c->binddn;
  bindpasswd=c->bindpw;
  ldapServer=c->host;
  port=c->port;
}

static int _alloc_config (pam_ldap_config_t ** presult)
{
  pam_ldap_config_t *result;

  if (*presult == NULL)
    {
      *presult = (pam_ldap_config_t *) calloc (1, sizeof (*result));
      if (*presult == NULL)
        return PAM_BUF_ERR;
    }

  result = *presult;

  result->port = 0;
  result->binddn = NULL;
  result->bindpw = NULL;
  result->host = NULL;

  return PAM_SUCCESS;
}

static int _read_config (const char *configFile, pam_ldap_config_t ** presult) {
  FILE *fp;
  char b[BUFSIZ];
  pam_ldap_config_t *result;

  if (_alloc_config (presult) != PAM_SUCCESS) {
      return PAM_BUF_ERR;
  }

  result = *presult;


  /* configuration file location is configurable; default /etc/ldap.conf */
  if (configFile == NULL)
    {
      configFile = PAM_LDAP_PATH_CONF;
      result->configFile = NULL;
    }
  else
    {
      result->configFile = strdup (configFile);
      if (result->configFile == NULL)
        return PAM_BUF_ERR;
    }


  fp = fopen (configFile, "r");

  if (fp == NULL)
    {
      /*
       * According to PAM Documentation, such an error in a config file
       * SHOULD be logged at LOG_ALERT level
       */
      syslog (LOG_ALERT, "pam_ldap: missing file \"%s\"", configFile);
      return PAM_SERVICE_ERR;
    }

  result->scope = LDAP_SCOPE_SUBTREE;
  while (fgets (b, sizeof (b), fp) != NULL)
    {
      char *k, *v;
      int len;

      if (*b == '\n' || *b == '#')
        continue;

      k = b;
      v = k;
      while (*v != '\0' && *v != ' ' && *v != '\t')
        v++;

      if (*v == '\0')
        continue;

      *(v++) = '\0';

      /* skip all whitespaces between keyword and value */
      /* Lars Oergel <lars.oergel@innominate.de>, 05.10.2000 */
      while (*v == ' ' || *v == '\t')
        v++;

      /* kick off all whitespaces and newline at the end of value */
      /* Bob Guo <bob@mail.ied.ac.cn>, 08.10.2001 */
      len = strlen (v) - 1;
      while (v[len] == ' ' || v[len] == '\t' || v[len] == '\n')
        --len;
      v[len + 1] = '\0';

     if (!strcasecmp (k, "base"))
        {
          CHECKPOINTER (result->base = strdup (v));
        }
      else if (!strcasecmp (k, "binddn"))
        {
          CHECKPOINTER (result->binddn = strdup (v));
        }
      else if (!strcasecmp (k, "bindpw"))
        {
          CHECKPOINTER (result->bindpw = strdup (v));
        }
      else if (!strcasecmp (k, "host"))
        {
          CHECKPOINTER (result->host = strdup (v));
        }
      else if (!strcasecmp (k, "port"))
        {
          result->port = atoi (v);
        }
    }
  fclose (fp);

  /* can't use _pam_overwrite because it only goes to end of string,
   * not the buffer
   */
  memset (b, 0, BUFSIZ);
  return PAM_SUCCESS;
}

static void _log_err(int err, const char *format, ...) {
    va_list args;
    va_start(args, format);
    openlog("PAM-checkattr", LOG_CONS|LOG_PID, LOG_AUTHPRIV);
    vsyslog(err, format, args);
    va_end(args);
    closelog();
}

static int _pam_parse(int flags, int argc, const char **argv) {
   int ctrl = 0;

   if ((flags & PAM_SILENT) == PAM_SILENT)
      ctrl |= CHECKATTR_QUIET;

   for (; argc-- > 0; ++argv) {
      if (!strcmp(*argv, "silent")) {
	 ctrl |= CHECKATTR_QUIET;
      } else if (!strncmp(*argv,"attr=",5)) {
	 strcpy(attrcheck,*argv+5);
      } else if (!strncmp(*argv,"basedn=",7)) {
	 strcpy(basedn,*argv+7);
      } else {
	 _log_err(LOG_ERR, "unknown option; %s", *argv);
      }
   }

   D(("ctrl = %o", ctrl));
   return ctrl;
}


PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t * pamh, int flags, int argc ,const char **argv) {
   int retval, ctrl;
   const struct passwd *pwd;
   char *user,*domuser;
   LDAP *ld = NULL;
   int rc;
   int version=3;
   int tls_opts = LDAP_OPT_X_TLS_HARD;
   pam_ldap_config_t *ldapconfig;
   LDAPMessage *res,*entry;
   const char *configFile = PAM_LDAP_PATH_CONF;      
   ctrl = _pam_parse(flags, argc, argv);

   retval = pam_get_item(pamh, PAM_USER, (const void **) &user);
   if (retval != PAM_SUCCESS || user == NULL || *user == '\0') {
      _log_err(LOG_NOTICE, "user unknown");
      return PAM_USER_UNKNOWN;
   }

   pwd = getpwnam(user);
   if (pwd == NULL) {
      D(("couldn't identify user %s", user));
      return PAM_CRED_INSUFFICIENT;
   }

   setbuf(stdout, NULL);

   ldapconfig=malloc(sizeof(pam_ldap_config_t));
   _read_config(configFile,&ldapconfig);
   _release_config(&ldapconfig);

   if ((ld = ldap_init(ldapServer, port)) == NULL) {
      _log_err(LOG_ERR,"\nUnable to connect to LDAP server:%s port:%d\n",ldapServer, port);
     return PAM_SYSTEM_ERR; 
   }

   rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION,&version);
   if (rc != LDAP_SUCCESS) {
     _log_err(LOG_ERR,"ldap_set_option LDAP_OPT_PROTOCOL_VERSION: %s'\n", ldap_err2string(rc));
     return PAM_SYSTEM_ERR; 
   }

   rc = ldap_set_option (ld, LDAP_OPT_X_TLS, &tls_opts);
   if (rc != LDAP_SUCCESS) {
     _log_err(LOG_ERR,"ldap_set_option LDAP_OPT_X_TLS: %s",ldap_err2string (rc));
     return PAM_SYSTEM_ERR; 
   }
   rc = ldap_start_tls_s(ld,NULL,NULL);

   rc = ldap_simple_bind_s(ld, binddn, bindpasswd);
   if (rc != LDAP_SUCCESS) {
     _log_err(LOG_ERR,"ldap_simple_bind: %s",ldap_err2string (rc));
     return PAM_SYSTEM_ERR; 
   }

   domuser=rindex(user,'\\');
   if (domuser != NULL) {
     sprintf(user,"%s",domuser+1);
   }

   sprintf(searchfilter,"uid=%s",user);
   if (ldap_search_s(ld, basedn, searchscope, searchfilter,NULL, 1, &res) != LDAP_SUCCESS) {
     _log_err(LOG_ERR,"ldap_search_s: %s filter %s",ldap_err2string(rc),searchfilter);
     return PAM_SYSTEM_ERR; 
   }

   entry = ldap_first_entry(ld, res);
   if (!entry) {
     ldap_msgfree(res);
     _log_err(LOG_ERR,"user %s not in ldap proceeding",user);
     return PAM_SUCCESS;
   }

   sprintf(searchfilter,"(&(%s=yes)(uid=%s))",attrcheck,user);
   if (ldap_search_s(ld, basedn, searchscope, searchfilter,NULL, 1, &res) != LDAP_SUCCESS) {
     _log_err(LOG_ERR,"ldap_search_s: %s filter %s",ldap_err2string(rc),searchfilter);
     return PAM_SYSTEM_ERR; 
   }

	   entry = ldap_first_entry(ld, res);
   if (!entry) {
     ldap_msgfree(res);
     _log_err(LOG_ERR,"user %s not authorised for access",user);
     return PAM_PERM_DENIED;
   } else {
     return PAM_SUCCESS;
   }
}

PAM_EXTERN 
int pam_sm_close_session(pam_handle_t * pamh, int flags, int argc
			 ,const char **argv) {
   return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_checkattr_modstruct ={
   "pam_checkattr",
   NULL,
   NULL,
   pam_sm_acct_mgmt,
   NULL,
   NULL,
   NULL,
};
#endif
