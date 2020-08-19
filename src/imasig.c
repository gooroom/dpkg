#include <config.h>
#include <compat.h>

#include <sys/stat.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <dpkg/i18n.h>
#include <dpkg/dpkg.h>
#include <dpkg/dpkg-db.h>
#include <dpkg/debug.h>
#include <dpkg/fdio.h>
#include <dpkg/dir.h>

#include "imasig.h"
#include "main.h"
#include "filesdb.h"
#include "infodb.h"

// attr
#include <sys/xattr.h>
#include <ctype.h>

struct siginfo {
  int num;
  int hashlen;
  char **filename;
  unsigned char **sigval;
};

int hex_digit(char c);
int count_imasig_file(char *buf);
int decode(const char *value, unsigned char *decoded);

void parse_sigdata_buff(char *buf, char **filename_array, char **sig_array);
void copy_filename(char **filename, struct siginfo *sigdata);
void decode_signature(char **sig_array, struct siginfo *sigdata);
void free_sigdata(struct siginfo *sigdata);

void set_imasig_attr(struct siginfo *sigdata);

int
imasig_attr(struct pkginfo *pkg)
{
	int fd;
	const char *sigfile;
	struct stat st;
	
	sigfile = pkg_infodb_get_file(pkg, &pkg->installed, SIGFILE);

	fd = open(sigfile, O_RDONLY);
	if (fd < 0) {
//		ohshite("cannot open signature file '%s' for package '%s'",
//		        SIGFILE, pkg_name(pkg, pnaw_nonambig));
		return 0;
	}
	
	if (fstat(fd, &st) < 0)
		ohshite(_("cannot stat control file '%s' for package '%s'"),
		        SIGFILE, pkg_name(pkg, pnaw_nonambig));

	if (!S_ISREG(st.st_mode))
		ohshit(_("control file '%s' for package '%s' is not a regular file"),
		       SIGFILE, pkg_name(pkg, pnaw_nonambig));

	if (st.st_size > 0) {
		char *buf;
		char **filename_array, **sig_array;
		struct siginfo sigdata;

		buf = m_malloc(st.st_size + 1);
		buf[st.st_size] = '\0';

		if (fd_read(fd, buf, st.st_size) < 0)
			ohshite(_("cannot read control file '%s' for package '%s'"),
			        SIGFILE, pkg_name(pkg, pnaw_nonambig));
		
		sigdata.num = count_imasig_file(buf);
		filename_array = (char **)m_malloc(sizeof(char *) * sigdata.num);
		sig_array = (char **)m_malloc(sizeof(char *) * sigdata.num);
		
		parse_sigdata_buff(buf, filename_array, sig_array);

		sigdata.hashlen = strlen(sig_array[0]) / 2;
		
		copy_filename(filename_array, &sigdata);
		decode_signature(sig_array, &sigdata);
		
		set_imasig_attr(&sigdata);
		
		free(buf);
		free(filename_array);
		free(sig_array);
		free_sigdata(&sigdata);
	}

	if (close(fd))
		ohshite(_("cannot close control file '%s' for package '%s'"),
		        SIGFILE, pkg_name(pkg, pnaw_nonambig));

	return 0;
}

void
free_sigdata(struct siginfo *sigdata)
{
	int i;
	
	for(i=0; i< sigdata->num; i++) {
		free(sigdata->filename[i]);
		free(sigdata->sigval[i]);
	}
	
	free(sigdata->filename);
	free(sigdata->sigval);
}

void
copy_filename(char **filename, struct siginfo *sigdata)
{
	int i;
	
	sigdata->filename = (char **)m_malloc(sizeof(char *) * sigdata->num);
	
	for(i=0; i < sigdata->num; i++) {
		int len;
		
		len = strlen(filename[i]);
		sigdata->filename[i] = (char *)m_malloc((sizeof(char) * len) + 2);
		
		sigdata->filename[i][0] = '/';
		sigdata->filename[i][1] = '\0';
		strcat(sigdata->filename[i], filename[i]);
	}
}

void
set_imasig_attr(struct siginfo *sigdata)
{
	int i;
	
	for(i=0; i < sigdata->num; i++) {
		int err;
		
		err = setxattr(sigdata->filename[i], SEC_IMA, sigdata->sigval[i], sigdata->hashlen, 0);
		
		if(err < 0) {
			fprintf(stderr, "IMA-sig set error: %s\n",	sigdata->filename[i]);
			//return;
		}
	}
}

void
decode_signature(char **sig_array, struct siginfo *sigdata)
{
	int i;
	
	sigdata->sigval = (unsigned char **)m_malloc(sizeof(unsigned char *) * sigdata->num);
	
	for(i=0; i < sigdata->num; i++) {
		unsigned char *decoded;
		int err;
		int j;

		decoded = (unsigned char *)m_malloc(strlen(sig_array[i]) / 2);
		
		err = decode(sig_array[i], decoded);
		if( err )
			ohshite(_("wrong signature '%s' file"), sigdata->filename[i]);
			
		sigdata->sigval[i] = decoded;
		
		printf("file_name : %s\n", sigdata->filename[i]);
		printf("sig size : %d\n", sigdata->hashlen);
		printf("signature : %s \n", sig_array[i]);
		
		for(j=0; j < sigdata->hashlen; j++)
		{
			printf("%02x", decoded[j]);
		}
		printf("\n");
	}
}

int
count_imasig_file(char *buf)
{
	int len, i;
	int file_count=0;
	
	len = strlen(buf);
	
	for(i=0; i < len; i++)
	{
		if(buf[i]=='\n') {
			file_count++;
		}
	}
	return file_count;
}

void
parse_sigdata_buff(char *buf, char **filename_array, char **sig_array)
{
	char *ret_ptr, *next_ptr;
	int i=0;
	
	ret_ptr = strtok_r(buf, "\n", &next_ptr);
	
	while(ret_ptr) {
		char *filename, *signature, *tmp;

		tmp = strchr(ret_ptr, ' ');
		filename = tmp + 2;
		*(tmp + 1) = '\0';
		
		tmp = strrchr(filename, ' ');
		*tmp = '\0';
		signature = tmp + 1;
		
		filename_array[i] = filename;
		sig_array[i] = signature;
		i++;
		
		ret_ptr = strtok_r(NULL, "\n", &next_ptr);
	}
}

int
decode(const char *value, unsigned char *decoded)
{
	const char *v, *end;
	unsigned char *d;
	
	v = value;
	end = value + strlen(value);
	d = decoded;
	
	if (strlen(value) <= 0)
		return -1;
	
	while (v < end) {
		int d1, d0;

		while (v < end && isspace(*v))
			v++;
		if (v == end)
			break;
		d1 = hex_digit(*v++);
		
		while (v < end && isspace(*v))
			v++;
		if (v == end) {
			return -1;
		}
		d0 = hex_digit(*v++);
		
		if (d1 < 0 || d0 < 0)
			return -1;
		*d++ = ((d1 << 4) | d0);
	}
	
	return 0;
}

int
hex_digit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else
		return -1;
}

