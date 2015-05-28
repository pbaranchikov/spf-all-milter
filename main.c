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

char** getTextRecords(ns_msg handle, ns_sect section);
void freeList(char** stringList);
int parseDomain(const char* domainName);

int main(int argc, char **argv) {
	if (argc == 2)
		parseDomain(argv[1]);
	return 0;
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
		printf("@Can't query %s\n", domainName);
		return 1;
	}
	ns_msg handle;
	if (ns_initparse(response.buf, responseLen, &handle) < 0) {
		fprintf(stderr, "ns_initparse: %s\n", strerror(errno));
		return 2;
	}
	char** records = getTextRecords(handle, ns_s_an);
	int i;
	for (i = 0; records[i] != NULL; i++) {
		printf("TXT record contents: %s\n", records[i]);

	}
	freeList(records);
	return 0;
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

