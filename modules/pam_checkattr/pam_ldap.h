/*
 * Copyright (C) 1998-2003 Luke Howard.
 * This file is part of the pam_ldap library.
 * Contributed by Luke Howard, <lukeh@padl.com>, 1998.
 *
 * The pam_ldap library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * The pam_ldap library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with the pam_ldap library; see the file COPYING.LIB.  If not,
 * write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#define PAM_LDAP_PATH_CONF "/etc/ldap.conf"
#define PAM_LDAP_PATH_ROOTPASSWD        "/etc/ldap.secret"

#define CHECKPOINTER(ptr) do { if ((ptr) == NULL) { \
    fclose(fp); \
    return PAM_BUF_ERR; \
} \
} while (0)

/* /etc/ldap.conf nss_ldap-style configuration */
typedef struct pam_ldap_config {
 char *configFile;
 char *host;
 int port;
 char *base;
 int scope;
 char *binddn;
 char *bindpw;
}
pam_ldap_config_t;
