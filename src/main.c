#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <unistd.h>

#include "p2p.h"

const char *info =
"c_bittorrent - an experimental bare-bones bittorrent client";
const char *usage =
"Usage: c_bittorrent TORRENTFILE [FILENAME] [OPTION]\n"
"\n"
"-v --verbose    explain what is being done\n"
"-h --help       print this help message and exit";

int
main(int argc, char **argv)
{
	srand(time(NULL) * getpid());

	// int verbose = 0;
	// char *file = NULL;
	// char *name = NULL;
	// char torrent[256];

	// // Start from 1 because first argument is program name
	// for(int i = 1; i < argc; i++) {
	// 	if(strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
	// 		verbose = 1;
	// 		continue;
	// 	}
	// 	if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
	// 		printf("%s\n", info);
	// 		printf("%s\n", usage);
	// 		return 0;
	// 	}

	// 	if(argv[i][0] == '-') {
	// 		printf("Invalid argument '%s'\n", argv[i]);
	// 		printf("%s\n", usage);
	// 		return 1;
	// 	}

	// 	if(file == NULL) {
	// 		file = argv[i];
	// 	} else if(name == NULL) {
	// 		name = argv[i];
	// 	}
	// }

	// if(file == NULL) {
	// 	printf("No torrent file specified\n");
	// 	printf("%s\n", usage);
	// 	return 1;
	// }

	// strcat(torrent, name);
	// strcat(torrent, ".torrent");

	// return generate_torrent(file, name, torrent);
	return seed(6889, 1, "./robotslide.pptx", "./robotslide3.torrent");
	// return seed(6889, 1, "debian-11.5.0-amd64-netinst.iso", "debian-11.5.0-amd64-netinst.iso.torrent")
}