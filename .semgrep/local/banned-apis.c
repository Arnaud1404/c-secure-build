// Test cases for banned-apis.yaml: semgrep --test .semgrep/local/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ato_bad(const char *s)
{
	// ruleid: banned-ato
	int a = atoi(s);
	// ruleid: banned-ato
	long b = atol(s);
	// ruleid: banned-ato
	long long c = atoll(s);
	// ruleid: banned-ato
	double d = atof(s);
	return a + (int)b + (int)c + (int)d;
}

long ato_good(const char *s)
{
	char *end;
	// ok: banned-ato
	return strtol(s, &end, 10);
}

char *strtok_bad(char *s)
{
	// ruleid: banned-strtok
	return strtok(s, " ");
}

char *strtok_good(char *s)
{
	char *state;
	// ok: banned-strtok
	return strtok_r(s, " ", &state);
}

void temp_bad(char *buf, char *tmpl)
{
	// ruleid: banned-temp-name
	tmpnam(buf);
	// ruleid: banned-temp-name
	tempnam("/tmp", "x");
	// ruleid: banned-temp-name
	mktemp(tmpl);
}

int temp_good(char *tmpl)
{
	// ok: banned-temp-name
	return mkstemp(tmpl);
}
