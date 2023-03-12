#include <time.h>
#include <unistd.h>

#include "p2p.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_PORT 6889

int main(int argc, char *argv[]) {
    int verbose = 0;
    int result = 0;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s [-l|-s] [<torrent_file_location>|<file_location>]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-l") == 0) {
        char name[256];
        result = leech(argv[2], name, verbose);
        if (result == 0) {
            result = seed(DEFAULT_PORT, verbose, name, argv[2]);
        }
    }
    else if (strcmp(argv[1], "-s") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s -s <file_location>\n", argv[0]);
            return 1;
        }
        char *name = strrchr(argv[2], '/');
        name = (name == NULL) ? argv[2] : name + 1;
        char *output = malloc(strlen(name) + 9);
        sprintf(output, "%s.torrent", name);
        result = generate_torrent(argv[2], name, output);
        if (result == 0) {
            result = seed(DEFAULT_PORT, verbose, argv[2], output);
        }
        free(output);
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }

    return result;
}
