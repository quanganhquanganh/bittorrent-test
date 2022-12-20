#ifndef P2P_H
#define P2P_H

#include <openssl/sha.h>
#include <arpa/inet.h>

#define BUFFLEN 1024 // Only used for query string
#define PEERID_LEN 20

#define MAX_RETRY 10 // Number of times to retry connecting to the tracker

#define HANDLECOUNT 50 // Max number of peers to connect to simultaneously
#define SIMULBLOCKS 5 // Max number of blocks to request simultaneously

#define TIMEOUT 3 // seconds (only used for connecting)
#define COMMTIMEOUT 10000 // useconds (used while communicating with peers)

#define PSTR "BitTorrent protocol"
#define PSTRLEN 19

#define BLOCKLEN 16384 // 2^14 (16 KiB)
#define PIECELEN 262144 // 2^18 (256 KiB)

#define DESTROY(x) do {free(x); x = NULL;} while(0);
#define DICT_DESTROY(d) do {dict_destroy(d); d = NULL;} while(0);

typedef struct peer
{
	char ip[INET_ADDRSTRLEN];
	unsigned short int port;
} peer;

typedef enum dwn_status
{
	NONE,
	DOWNLOADING,
	DOWNLOADED,
} dwn_status;

typedef struct block
{
	int length;
	int offset;
	dwn_status status;
} block;

typedef struct piece
{
	block *blocks;
	size_t length;
	unsigned char *data;
	unsigned char valid_hash[SHA_DIGEST_LENGTH];
	dwn_status status;
} piece;

int generate_torrent(const char *file, const char *name, const char *output);

int p2p_start(const char *file, const char *name);

// int seed(const char *file, const char *name);

#endif /* P2P_H */
