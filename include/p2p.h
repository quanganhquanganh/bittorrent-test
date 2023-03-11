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
#define COMMTIMEOUT 100 // useconds (used while communicating with peers)

#define PSTR "BitTorrent protocol"
#define PSTRLEN 19

#define BLOCKLEN 16384 // 2^14 (16 KiB)
#define PIECELEN 262144 // 2^18 (256 KiB)

#define MAXREQS 16 // PIECELEN / BLOCKLEN

#define DESTROY(x) do {free(x); x = NULL;} while(0);
#define DICT_DESTROY(d) do {dict_destroy(d); d = NULL;} while(0);
#define verprintf(verbose, ...) do {if(verbose) printf(__VA_ARGS__);} while(0);

typedef enum mssg_id
{
	CHOKE,
	UNCHOKE,
	INTERESTED,
	NOT_INTERESTED,
	HAVE,
	BITFIELD,
	REQUEST,
	PIECE,
	CANCEL,
	HAVEALL = 0x0e,
	EXTENDED = 0x14,
} mssg_id;

typedef enum steps
{
	STEP_NONE,
	STEP_HANDSHAKE,
	STEP_READMSG,
	STEP_READID,
	STEP_BITFIELD,
	STEP_SNDBTFLD, // Send bitfield
	STEP_HAVE,
	STEP_DOWNLOAD,
	STEP_UNCHOKE,
	STEP_CHOKE,
	STEP_READREQ,
	STEP_CANCEL,
	STEP_NOTINTERESTED,
	STEP_SNDCANCEL,
	STEP_HAVEALL,
	STEP_EXT,
} steps;

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

typedef struct peer_req
{
	int index;
	int begin;
	int length;
} peer_req;

typedef struct peer_status
{
	steps curr_step;
	int mssg_len;
	int recv_mssg_len;
	int choked;
	int interested;
	int has_pcs;
	int recv_intrstd;
	int sent_btfld;
	int am_choking;
	unsigned char *bitfield;
	unsigned char *mssg;
	int curr_reqs; // Number of ongoing requests
	int curr_pc_idx;
	peer_req *req;
	int req_len;
	long long int curr_blck_off;
	int curr_blck_len;

	char ip[INET_ADDRSTRLEN];
} peer_status;

int generate_torrent(const char *file, const char *name, const char *output);

int p2p_start(const char *file, const char *name, int verbose);

int seed(int port, int verbose, char* file_name, char* torrent_file);

#endif /* P2P_H */
