#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>

union guid_t
{
	struct
	{
		uint32_t g1;
		uint16_t g2;
		uint16_t g3;
		uint8_t g4[8];
	} g;
	uint8_t bytes[16];
};

void putguid(char *s)
{
	char *next;
	union guid_t guid;
	for (next = s; isalnum(*next); next++)
		;
	*next = 0;
	printf("flagGuid(\"%s\", \"", s); // g...Guid
	for (; !isalnum(*next); next++)
		;
	guid.g.g1 = strtoul(next, &next, 0);
	next++;
	guid.g.g2 = strtoul(next, &next, 0);
	next++;
	guid.g.g3 = strtoul(next, &next, 0);
	for (; !isalnum(*next); next++)
		;
	for (int i=0; i<8; i++) {
		guid.g.g4[i] = strtoul(next, &next, 0);
		next++;
	}
	for (int i=0; i<16; i++)
		printf("%02x", guid.bytes[i]);
	puts("\")");
}

int main(int argc, char *argv[])
{
	char line[1024];
	while (fgets(line, 1024, stdin) != NULL)
		putguid(line);

	return 0;
}
