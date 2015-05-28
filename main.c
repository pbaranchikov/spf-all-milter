/*
 * main.c
 *
 *  Created on: 28 мая 2015 г.
 *      Author: pavel
 */

#include <resolv.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <libmilter/mfapi.h>
#include <libmilter/mfdef.h>
#include <syslog.h>
#include <ctype.h>

#include "config.h"

char** getTextRecords(ns_msg handle, ns_sect section);
void freeList(char** stringList);
int parseDomain(const char* domainName);
int startsWith(const char* stringToTest, const char* prefix);

sfsistat
mlfi_envfrom(SMFICTX *ctx, char **envfrom);

struct smfiDesc smfilter = {
PACKAGE, /* filter name */
SMFI_VERSION, /* version code */
SMFIF_ADDHDRS, /* flags */
NULL, /* connection info filter */
NULL, /* SMTP HELO command filter */
mlfi_envfrom, /* envelope sender filter */
NULL, /* envelope recipient filter */
NULL, /* header filter */
NULL, /* end of header */
NULL, /* body block filter */
NULL, /* end of message */
NULL, /* message aborted */
NULL, /* connection cleanup */
};

int main(int argc, char **argv) {
	if (argc != 2) {
		printf("Error. Socket should be passed as a parameter");
	}
//	char *socketPath = "/home/pavel/sfp-all-milter.sock";
	char *socketPath = argv[1];
	smfi_setconn(socketPath);

	if (smfi_register(smfilter) == MI_FAILURE) {
		fprintf(stderr, "%s: smfi_register failed\n", argv[0]);
		exit(1);
	}

	syslog(LOG_INFO, "%s milter ssuccessfully started. Listening socket %s",
	PACKAGE, socketPath);
	return smfi_main();
}

void strtolower(char *str) {
	/* check for required data presented */
	if (!str)
		return;
	for (; *str; str++)
		*str = tolower(*str);
}

sfsistat mlfi_envfrom(SMFICTX *ctx, char **envfrom) {
	char *from_addr = NULL, *from_host = NULL;

	/* get macro data */
	if (!(from_addr = smfi_getsymval(ctx, "{mail_addr}"))) {
		syslog(LOG_ERR, "mail_macro: {mail_addr} must be available");
		return SMFIS_TEMPFAIL;
	}

	strtolower(from_addr);

	/* get host part of e-mail address */
	if ((from_host = strrchr(from_addr, '@')))
		from_host++;
	else
		from_host = from_addr;

	if (!parseDomain(from_host)) {
		smfi_setreply(ctx, "530", "5.7.1",
				"Sender domain has wrong SPF record (containing +all)");
		return SMFIS_REJECT;
	}
	return SMFIS_CONTINUE;
}

/**
 * Parses DNS records for the domain to analyze avalability of +all statement
 * @returns 0 if domain is Ok, 1 if domain has +all in its SPF records
 */
int parseDomain(const char* domainName) {
	int responseLen;
	union {
		HEADER hdr; /* defined in resolv.h */
		u_char buf[NS_PACKETSZ]; /* defined in arpa/nameser.h */
	} response; /* response buffers */

	if ((responseLen = res_query(domainName, C_IN, T_TXT, (u_char *) &response,
			NS_PACKETSZ)) < 0) {
		syslog(LOG_WARNING, "Can't query %s\n", domainName);
		return 0;
	}
	ns_msg handle;
	if (ns_initparse(response.buf, responseLen, &handle) < 0) {
		syslog(LOG_ERR, "ns_initparse: %s\n", strerror(errno));
		return 0;
	}
	char** records = getTextRecords(handle, ns_s_an);
	int i;
	for (i = 0; records[i] != NULL; i++) {
		if (startsWith(records[i], "v=spf1")) {
			if (strstr(records[i], "+all")) {
				printf("Domain %s has invalid SPF record: %s\n", domainName,
						records[i]);
				return 0;
			}
		}
	}
	freeList(records);
	return 1;
}

int startsWith(const char* stringToTest, const char* prefix) {
	return !strncmp(stringToTest, prefix, strlen(prefix));
}

char **getTextRecords(ns_msg handle, ns_sect section) {
	char **textRecords = NULL;
	int textRecordsCount = 0;
	int rrnum; /* resource record number */
	ns_rr rr; /* expanded resource record */

	/*
	 * Look at all the resource records in this section.
	 */
	for (rrnum = 0; rrnum < ns_msg_count(handle, section); rrnum++) {
		/*
		 * Expand the resource record number rrnum into rr.
		 */
		if (ns_parserr(&handle, section, rrnum, &rr)) {
			fprintf(stderr, "ns_parserr: %s\n", strerror(errno));
		}

		/*
		 * If the record type is NS, save the name of the
		 * name server.
		 */
		if (ns_rr_type(rr) == ns_t_txt) {

			/*
			 * Allocate storage for the name.  Like any good
			 * programmer should, we test malloc's return value,
			 * and quit if it fails.
			 */
			textRecordsCount++;
			textRecords = (char**) realloc(textRecords,
					textRecordsCount * sizeof(char*));
			char *txtField = (char *) malloc(MAXDNAME);
			textRecords[textRecordsCount - 1] = txtField;
			textRecords[textRecordsCount] = NULL;

			if (txtField == NULL) {
				(void) fprintf(stderr, "malloc failed\n");
				freeList(textRecords);
				return NULL;
			}

			const int dataSize = ns_rr_rdlen(rr);
			const char* dataPointer = ns_rr_rdata(rr) + 1;
			if (dataSize >= MAXDNAME) {
				fprintf(stderr,
						"DNS RR data field size is more that buffer has");
				freeList(textRecords);
				return NULL;
			}
			memcpy(txtField, dataPointer, dataSize);
			txtField[dataSize - 1] = 0;
		}
	}
	return textRecords;
}

void freeList(char** stringList) {
	int i;
	for (i = 0; stringList[i] != NULL; i++) {
		free(stringList[i]);
	}
	free(stringList);
}

