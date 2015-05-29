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

const char** readExcludedDomains();
int isInList(const char** list, const char* string);
char** createList();
char** addNewElement(char** list, char* newElement);

#define CONFIG_FILE "/etc/spf-all-milter-exclusions.conf"
#define FILENAME_LENGTH 255

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

const char** excludedDomains;
const int loglevel = LOG_DEBUG;

int main(int argc, char **argv) {
	if (argc != 2) {
		printf("Error. Socket should be passed as a parameter");
	}
	char *socketPath = argv[1];
	smfi_setconn(socketPath);

	if (smfi_register(smfilter) == MI_FAILURE) {
		fprintf(stderr, "%s: smfi_register failed\n", argv[0]);
		exit(1);
	}

	syslog(LOG_INFO, "%s milter ssuccessfully started. Listening socket %s",
	PACKAGE, socketPath);
	if ((excludedDomains = readExcludedDomains()))
		return smfi_main();
	else {
		fprintf(stderr, "Could not load exclusions");
		return 1;
	}
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
	if (loglevel >= LOG_DEBUG) {
		syslog(LOG_DEBUG, "Parsing domain %s", domainName);
	}
	int responseLen;
	union {
		HEADER hdr; /* defined in resolv.h */
		u_char buf[NS_PACKETSZ]; /* defined in arpa/nameser.h */
	} response; /* response buffers */

	if ((responseLen = res_query(domainName, C_IN, T_TXT, (u_char *) &response,
			NS_PACKETSZ)) < 0) {
		if (errno != 0) {
			syslog(LOG_WARNING, "Can't query %s: %s\n", domainName,
					strerror(errno));
		}
		// if errno==0, then there is no answer. So... no TXT records to analyze.
		return 1;
	}
	ns_msg handle;
	if (ns_initparse(response.buf, responseLen, &handle) < 0) {
		syslog(LOG_ERR, "ns_initparse: %s\n", strerror(errno));
		return 1;
	}
	char** records = getTextRecords(handle, ns_s_an);
	if (!records) {
		// On errors, we just ignore the milter.
		syslog(LOG_ERR, "Error retrieving TXT records from domain %s",
				domainName);
		return 1;
	}
	int i;
	for (i = 0; records[i] != NULL; i++) {
		// If this is an SFP record
		if (startsWith(records[i], "v=spf1")) {
			// It it is invalid
			if (strstr(records[i], "+all")) {
				// If domain is not excluded
				if (!isInList(excludedDomains, domainName)) {
					if (loglevel >= LOG_INFO) {
						syslog(LOG_INFO,
								"Domain %s has invalid SPF record: %s\n",
								domainName, records[i]);
					}
					return 0;
				}
			}
		}
	}
	if (loglevel >= LOG_DEBUG) {
		syslog(LOG_DEBUG, "Freeing RR list for domain %s", domainName);
	}
	freeList(records);
	return 1;
}

int startsWith(const char* stringToTest, const char* prefix) {
	return !strncmp(stringToTest, prefix, strlen(prefix));
}

char **getTextRecords(ns_msg handle, ns_sect section) {
	char **textRecords = createList();
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
			syslog(LOG_WARNING, "ns_parserr: %s. DNS record is ignored\n",
					strerror(errno));
			continue;
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
			char *txtField = (char *) malloc(MAXDNAME);
			textRecords = addNewElement(textRecords, txtField);

			if (txtField == NULL) {
				syslog(LOG_ERR, "malloc failed\n");
				freeList(textRecords);
				return NULL;
			}

			const int dataSize = ns_rr_rdlen(rr);
			const char* dataPointer = ns_rr_rdata(rr) + 1;
			if (dataSize >= MAXDNAME) {
				syslog(LOG_ERR,
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
	if (!stringList) {
		return;
	}
	int i;
	for (i = 0; stringList[i] != NULL; i++) {
		free(stringList[i]);
	}
	free(stringList);
}

const char** readExcludedDomains() {
	FILE* config = fopen( CONFIG_FILE, "r");
	if (!config) {
		syslog(LOG_ERR, "Exclusions file %s does not exist", CONFIG_FILE);
		return NULL;
	}
	char** result = createList();

	while (!feof(config)) {
		char *newLine = (char*) malloc(FILENAME_LENGTH);
		if (!fgets(newLine, FILENAME_LENGTH, config)) {
			if (errno == 0) {
				break;
			} else {
				fprintf(stderr, "error reading exclusions file %s: %s\n",
				CONFIG_FILE, strerror(errno));
				freeList(result);
				fclose(config);
				free(newLine);
				return NULL;
			}
		}
		char* nlPos;
		if ((nlPos = strchr(newLine, '\n'))) {
			*nlPos = 0x0;
		}
		result = addNewElement(result, newLine);
	}
	fclose(config);
	return (const char**) result;
}

char** createList() {
	char** result = (char**) malloc(sizeof(char*));
	result[0] = NULL;
	return result;
}

int isInList(const char** list, const char* string) {
	int i;
	for (i = 0; list[i] != NULL; i++) {
		if (!strcasecmp(list[i], string)) {
			return 1;
		}
	}
	return 0;
}

char** addNewElement(char** list, char* newElement) {
	int size;
	for (size = 0; list[size] != NULL; size++) {
	}
	char** result = (char**) realloc(list, sizeof(char*) * (size + 2));
	result[size] = newElement;
	result[size + 1] = NULL;
	return result;
}

