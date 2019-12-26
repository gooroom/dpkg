#ifndef IMASIG_H
#define IMASIG_H

#include <dpkg/tarfn.h>

#define SIGFILE			"sig_shasums"
#define SEC_IMA			"security.ima"

int imasig_attr(struct pkginfo *pkg);


#endif
