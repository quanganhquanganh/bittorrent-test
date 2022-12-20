#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <unistd.h>

#include "p2p.h"

void extract_name(const char *file, char *name)
{
	int i = strlen(file) - 1;
	while(file[i] != '/' && i >= 0) {
		i--;
	}

	strcpy(name, file + i + 1);
}

int main(int argc, char **argv)
{
	srand(time(NULL) * getpid());

	int generate = 0;
	char *file = NULL;
	char *filename = NULL;
	char *name = NULL;

	// Start from 1 because first argument is program name
	for(int i = 1; i < argc; i++) {

		if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--generate") == 0) {
			generate = 1;
			continue;
		}

		if(argv[i][0] == '-') {
			printf("Invalid argument '%s'\n", argv[i]);
			return 1;
		}

		if(file == NULL) {
			file = argv[i];
			filename = malloc(strlen(file) + 1);
			extract_name(file, filename);
		} else if(name == NULL) {
			name = argv[i];
		}
	}

	if(file == NULL) {
		printf("No torrent file specified\n");
		return 1;
	}

	if (generate) {
		char torrent[256];
		strcpy(torrent, name == NULL ? filename : name);
		strcat(torrent, ".torrent");
		return generate_torrent(file, filename, torrent);
	} else {
		return p2p_start(file, name);
	}

}