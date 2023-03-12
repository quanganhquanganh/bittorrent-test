#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <unistd.h>

#include <openssl/sha.h>

#include <curl/curl.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "bencode.h"
#include "p2p.h"

static int
write_data(void* content, int size, int nmemb, be_string* response)
{
	int realsize = size * nmemb;
	unsigned char* str = realloc(response->str, response->len + realsize + 1);
	if (str == NULL) {
		printf("Not enough memory for response data\n");
		return 0;
	}
	response->str = str;
	memcpy(&(response->str[response->len]), content, realsize);
	response->len += realsize;
	response->str[response->len] = '\0';

	return realsize;
}

static char*
generate_peer_id(void)
{
	char* peer_id = malloc(PEERID_LEN + 1);
	sprintf(peer_id, "%s", "-EX0001-");
	int i;
	for (i = 8; i < PEERID_LEN; ++i) {
		peer_id[i] = '0' + (rand()) % 10;
	}
	peer_id[i] = '\0';
	return peer_id;
}

static void
close_peer_socks(int* sockets, int size)
{
	for (int i = 0; i < size; i++) {
		if (sockets[i] == -1) {
			continue;
		}
		close(sockets[i]);
	}
}

static void
cleanup(peer_status* stats,
		int conn_peers,
		piece* cl_pcs,
		int num_pcs,
		int* sockets,
		int total_peers,
		FILE* fp)
{
	for (int i = 0; i < conn_peers; i++) {
		DESTROY(stats[i].bitfield);
		DESTROY(stats[i].mssg);
	}
	for (int i = 0; i < num_pcs; i++) {
		DESTROY(cl_pcs[i].blocks);
		DESTROY(cl_pcs[i].data);
	}
	close_peer_socks(sockets, total_peers);
	fclose(fp);
}

static int
err_is_ignorable()
{
	return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}

static int
send_all(int sockfd, unsigned char* buff, int* len)
{
	int total = 0;
	int bytes_left = *len;
	int n;
	while (total < *len) {
		n = send(sockfd, buff + total, *len, MSG_NOSIGNAL);
		if (n == -1) {
			break;
		}
		total += n;
		bytes_left -= n;
	}
	*len = total;
	if (n != -1) {
		n = 0;
	}
	return n;
}

// chndhsk = client handshake
// phndhsk = peer handshake
// clen = length of client handshake
// plen = length of peer handshake
static int
valid_hndshk(unsigned char* chndhsk, unsigned char* phndhsk, int plen)
{
	int clen = 1 + PSTRLEN + 8 + SHA_DIGEST_LENGTH + PEERID_LEN;
	if (plen != clen) {
		printf("Handshake lengths don't match\n");
		return 0;
	}
	int hash_i = 1 + PSTRLEN + 8; // index where info hash begins
	// check if info hash is same in both handshakes
	// Print out the hashes for debugging
	printf("Client hash: ");
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
		printf("%02x", chndhsk[hash_i + i]);
	}
	printf("\nPeer hash: ");
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
		printf("%02x", phndhsk[hash_i + i]);
	}
	printf("\n");
	return memcmp(&chndhsk[hash_i], &phndhsk[hash_i], SHA_DIGEST_LENGTH) == 0;
}

// Endianness is accounted for by the shifts. No need for htonl or family
static int
get_mssg_len(unsigned char* mssg, int buff_len)
{
	if (buff_len < 4) {
		return -1;
	}
	uint32_t mssg_len =
	  (mssg[0] << 24) + (mssg[1] << 16) + (mssg[2] << 8) + mssg[3];
	return mssg_len;
}

static int
int_from_bytes(unsigned char* mssg)
{
	return get_mssg_len(mssg, 4);
}

// Endianness is accounted for by the shifts. No need for htonl or family
static void
int_to_bytes(unsigned char* bytes, int n)
{
	bytes[0] = (n >> 24) & 0xFF;
	bytes[1] = (n >> 16) & 0xFF;
	bytes[2] = (n >> 8) & 0xFF;
	bytes[3] = n & 0xFF;
}

static int
has_piece(unsigned char* bitfield, int index)
{
	if (index < 0) {
		return 0;
	}
	int byte_index = index / 8;
	int offset = index % 8;
	return ((bitfield[byte_index] >> (7 - offset)) & 1) != 0;
}

static void
set_piece(unsigned char* bitfield, int index)
{
	int byte_index = index / 8;
	int offset = index % 8;
	bitfield[byte_index] |= 1 << (7 - offset);
}

static int
mssg_received(peer_status status)
{
	return ((status.mssg_len == status.recv_mssg_len) &&
			(status.mssg_len != 0));
}

static void
reset_peer_step(peer_status* status)
{
	status->mssg_len = 0;
	status->recv_mssg_len = 0;
	status->curr_step = STEP_READMSG;
}

static void
clear_dwnlds(piece* pc, int num_blcks)
{
	for (int i = 0; i < num_blcks; i++) {
		if (pc->blocks[i].status == DOWNLOADING) {
			pc->blocks[i].status = NONE;
		}
	}
}

static int
pc_completed(block* curr_blocks, int num_blcks)
{
	for (int i = 0; i < num_blcks; i++) {
		if (curr_blocks[i].status != DOWNLOADED) {
			return 0;
		}
	}
	return 1;
}

static int
hash_matched(piece pc)
{
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1(pc.data, pc.length, hash);
	return memcmp(hash, pc.valid_hash, SHA_DIGEST_LENGTH) == 0;
}

static int
chck_pc_complete(piece* cl_pcs,
				 int* pc_idx,
				 int* pcs_dwnlded,
				 int num_blcks,
				 int num_pcs,
				 int left_peers,
				 FILE* fp)
{
	if (*pc_idx < 0) {
		return 0;
	}
	if (cl_pcs[*pc_idx].status == DOWNLOADED) {
		*pc_idx = -1;
		return 0;
	}
	if (pc_completed(cl_pcs[*pc_idx].blocks, num_blcks)) {
		long long int piece_len = cl_pcs[0].length;
		int res = hash_matched(cl_pcs[*pc_idx]);
		// res == 1 (hash check successful)
		if (res) {
			int idx = *pc_idx;
			piece pc = cl_pcs[idx];
			if (fseek(fp, idx * piece_len, SEEK_SET) < 0) {
				printf("[E] fseek() failed: %s. Aborting download\n",
					   strerror(errno));
				DESTROY(cl_pcs[*pc_idx].data);
				return -1;
			}
			if (fwrite(pc.data, 1, pc.length, fp) != pc.length) {
				printf("[E] fwrite() failed: %s. Aborting download\n",
					   strerror(errno));
				DESTROY(cl_pcs[*pc_idx].data);
				return -1;
			}
			cl_pcs[*pc_idx].status = DOWNLOADED;
			++(*pcs_dwnlded);
			float percentage = (((float)*pcs_dwnlded) / num_pcs) * 100;
			printf("[>] (%0.2f%%) Downloaded piece #%d from %d peers\n",
				   percentage,
				   idx,
				   left_peers);
			DESTROY(cl_pcs[*pc_idx].data);
			*pc_idx = -1;
			return 1;
		} else {
			clear_dwnlds(&cl_pcs[*pc_idx], num_blcks);
			cl_pcs[*pc_idx].status = NONE;
			return -2;
		}
	}
	// piece not yet complete
	return 0;
}

static size_t
write_ip(void* ptr, size_t size, size_t nmemb, void* data)
{
	if (size * nmemb < 16) {
		memcpy(data, ptr, size * nmemb);
		((char*)data)[size * nmemb] = '\0';
	}
	return size * nmemb;
}

// Curl whatismyip.akamai.com to get the external IP address
static int
get_external_ip(char* ip)
{
	CURL* curl = curl_easy_init();
	if (!curl) {
		return 1;
	}
	curl_easy_setopt(curl, CURLOPT_URL, "http://whatismyip.akamai.com");
	curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
	curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_ip);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, ip);
	
	int i = 0;
	int err;
	while ((err = curl_easy_perform(curl)) != 0) {
		if (i++ > MAX_RETRY) {
			printf("[E] curl_easy_perform() failed: %s\n",
				   curl_easy_strerror(err));
			return 1;
		}
	}
	curl_easy_cleanup(curl);
	return 0;
}

int generate_torrent(const char *file, const char *name, const char *output)
{
    FILE *fp = fopen(file, "rb");
    if(fp == NULL) {
        fprintf(stderr, "Could not open file '%s'\n", file);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    be_dict *dict = dict_create();
    be_string *node;

    // Add announce URL
		unsigned char *announce_url = "https://opentracker.i2p.rocks:443/announce";
    node = str_create((unsigned char*)"https://opentracker.i2p.rocks:443/announce", strlen(announce_url));
    dict_set(dict, (unsigned char*)"announce", node, BE_STR);

    // Add creation date
    dict_set(dict, (unsigned char*)"creation date", (void*)time(NULL), BE_INT);

    // Add info dictionary
    be_dict *info = dict_create();

    // Add name
    node = str_create((const unsigned char*)name, strlen(name));
    dict_set(info, (unsigned char*)"name", node, BE_STR);

    // Add piece length
    dict_set(info, (unsigned char*)"piece length", (void*)PIECELEN, BE_INT);

    // Add pieces
    unsigned char *pieces = malloc((long)ceil((double)size / PIECELEN) * SHA_DIGEST_LENGTH);
    unsigned char *piece = malloc(PIECELEN);
    unsigned char *hash = malloc(SHA_DIGEST_LENGTH);
    for(size_t i = 0; i < (long)ceil((double)size / PIECELEN); i++) {
			memset(piece, 0, PIECELEN);
			fread(piece, 1, PIECELEN, fp);
			SHA1(piece, size - i * PIECELEN < PIECELEN ? size - i * PIECELEN : PIECELEN, hash);
			memcpy(pieces + i * SHA_DIGEST_LENGTH, hash, SHA_DIGEST_LENGTH);
    }
    node = str_create(pieces, (long)ceil((double)size / PIECELEN) * SHA_DIGEST_LENGTH);
    dict_set(info, (unsigned char*)"pieces", node, BE_STR);

    // Add length
    dict_set(info, (unsigned char*)"length", (void*)size, BE_INT);

    // Add info dictionary to main dictionary
    dict_set(dict, (unsigned char*)"info", info, BE_DICT);

    // Write to file
    FILE *out = fopen(output, "wb");
    if(out == NULL) {
        fprintf(stderr, "Could not open file '%s'\n", output);
        return 1;
    }
    dict_print(NULL, dict, BE_DICT, out);
    fclose(out);

    // Free memory
    free(pieces);
    free(piece);
    free(hash);
    fclose(fp);

    return 0;
}

int seed(int port, int verbose, char* file_name, char* torrent_file) {
	// ------------------------- INITIALIZATION -------------------------
	char query[BUFFLEN + 1];
	void* val;
	be_type type;

	FILE* fp; // file to which the content will be downloaded

	unsigned char* annurl;
	// 3 characters for every info hash element. 2 for hex representation
	// and 1 for the '%' sign
	char info_hash[(3 * SHA_DIGEST_LENGTH) + 1] = "\0";
	long long int length;
	long long int piece_len;
	int num_pcs;
	int pcs_dwnlded = 0;

	int conn_socks[HANDLECOUNT];
	memset(conn_socks, -1, sizeof(conn_socks));
	// -------
	char* peer_id = generate_peer_id();

	be_string* string;
	be_dict* dict = decode_file(torrent_file);
	if (dict == NULL) {
		printf("Could not read or Found syntax error in torrent file\n");
		DESTROY(peer_id);
		return 1;
	}

	// announce URL
	// ------------
	val = dict_get(dict, (unsigned char*)"announce", &type);
	if (val == NULL || type != BE_STR) {
		printf("No announce URL found\n");
		DICT_DESTROY(dict);
		DESTROY(peer_id);
		return 1;
	}
	string = (be_string*)val;
	annurl = string->str;

	// info hash
	// ---------
	if (!dict->has_info_hash) {
		DICT_DESTROY(dict);
		printf("Info hash could not be calculated");
		DESTROY(peer_id);
		return 1;
	}
	for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
		// 3 is used because each hex representation will be 2 bytes
		// so 2+1 = 3. for null terminating character and '%'
		info_hash[i * 3] = '%';
		snprintf(&info_hash[i * 3 + 1], 3, "%02X", dict->info_hash[i]);
	}

	// info
	// ----
	val = dict_get(dict, (unsigned char*)"info", &type);
	if (val == NULL || type != BE_DICT) {
		printf("No info dictionary found\n");
		DICT_DESTROY(dict);
		DESTROY(peer_id);
		return 1;
	}
	be_dict* info = (be_dict*)val;

	// length
	// ------
	val = dict_get(info, (unsigned char*)"length", &type);
	if (val == NULL || type != BE_INT) {
		printf("No length found\n");
		DICT_DESTROY(dict);
		DESTROY(peer_id);
		return 1;
	}
	length = (long long int)val;

	// piece length
	// ------------
	val = dict_get(info, (unsigned char*)"piece length", &type);
	if (val == NULL || type != BE_INT) {
		printf("No piece length found\n");
		DICT_DESTROY(dict);
		DESTROY(peer_id);
		return 1;
	}
	piece_len = (long long int)val;

	// name
	// ----

	fp = fopen(file_name, "r");
	if (fp == NULL) {
		printf("Could not open file: %s\n", strerror(errno));
		DICT_DESTROY(dict);
		DESTROY(peer_id);
		return 1;
	}

	// -----------------------------------------------------------------------
	num_pcs = length / piece_len + (length % piece_len != 0);
	int cl_bitf_len = num_pcs / 8 + (num_pcs % 8 != 0);
	int num_blcks = piece_len / BLOCKLEN + (piece_len % BLOCKLEN != 0);
	// -----------------------------------------------------------------------

	// pieces
	val = dict_get(info, (unsigned char*)"pieces", &type);
	if (val == NULL || type != BE_STR) {
		printf("No pieces found\n");
		DICT_DESTROY(dict);
		DESTROY(peer_id);
		return 1;
	}
	be_string* hashes = (be_string*)val;
	int hash_len = hashes->len;
	if ((hash_len / SHA_DIGEST_LENGTH) != num_pcs ||
		(hash_len % SHA_DIGEST_LENGTH) != 0) {
		printf("Invalid pieces content in torrent file\n");
		DICT_DESTROY(dict);
		DESTROY(peer_id);
		return 1;
	}

	// Get listen socket
	int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_sock < 0) {
		switch (errno) {
			case EPROTONOSUPPORT: {
				printf("Protocol not supported\n");
				break;
			}
			case EACCES: {
				printf("Permisson to create socket denied\n");
				break;
			}
			default: {
				printf("Error creating socket: %s\n", strerror(errno));
				break;
			}
		}
		fclose(fp);
		return 1;
	}
	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);
	if (bind(listen_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) <
		0) {
		printf("Could not bind to port %d\n", port);
		return 1;
	}
	if (listen(listen_sock, 5) < 0) {
		printf("Could not listen on socket\n");
		return 1;
	}

	char ip[16];

	// Get local IP address
	get_external_ip(ip);
	printf("Local IP: %s\n", ip);

	printf("Tracker found: %s\n", annurl);

	// snprintf(query,
	// 		 BUFFLEN + 1,
	// 		 "%s?info_hash=%s&peer_id=%s&port=%d&uploaded=0&downloaded=%lld"
	// 		 "ip=%s&left=0&compact=1",
	// 		 annurl,
	// 		 info_hash,
	// 		 peer_id,
	// 		 port,
	// 		 length,
	// 		 ip);

	snprintf(query,
			 BUFFLEN + 1,
			 "%s?info_hash=%s&peer_id=%s&port=%d&uploaded=0&downloaded=%lld"
			 "&left=0&compact=1",
			 annurl,
			 info_hash,
			 peer_id,
			 port,
			 length);

	// ------------------------------ HANDSHAKE ------------------------------
	// 1 byte for length of protocol identifier
	// PSTRLEN for actual protocol identifier
	// 8 bytes for extensions support (all 0 for now)
	// SHA_DIGEST_LENGTH for info_hash
	// PEERID_LEN for peer ID
	// -----------------------------------------------------------------------
	int hndshk_len = 1 + PSTRLEN + 8 + SHA_DIGEST_LENGTH + PEERID_LEN;
	unsigned char hndshk[hndshk_len];
	hndshk[0] = PSTRLEN;
	memcpy(&hndshk[1], PSTR, PSTRLEN);
	memset(&hndshk[1 + PSTRLEN], 0, 8);
	memcpy(&hndshk[1 + PSTRLEN + 8], dict->info_hash, SHA_DIGEST_LENGTH);
	memcpy(&hndshk[1 + PSTRLEN + 8 + SHA_DIGEST_LENGTH], peer_id, PEERID_LEN);

	// ------------------------------ EXTENDED HANDSHAKE ---------------------
	// 1 byte for message ID
	// A be_dict containing the following:
	// 		m: be_dict containing the following:
	// 			ut_metadata: 3
	// 		upload_only: 1
	be_dict* ext_hndshk = dict_create();
	be_dict* m = dict_create();
	dict_set(m, (unsigned char*)"ut_metadata", (void*)3, BE_INT);
	dict_set(ext_hndshk, (unsigned char*)"m", (void*)m, BE_DICT);
	dict_set(ext_hndshk, (unsigned char*)"upload_only", (void*)1, BE_INT);
	char ext_hndshk_str[1024];
	dict_print_to_str(NULL, ext_hndshk, BE_DICT, ext_hndshk_str);
	int ext_hndshk_len = strlen(ext_hndshk_str);

	// Destroy dictionary after everything related
	// to this dictionary is done
	DICT_DESTROY(dict);
	dict = NULL;

	CURL* curl;
	be_string response;
	response.len = 0;
	response.str = malloc(1);
	response.str[0] = '\0';
	curl = curl_easy_init();
	if (curl != NULL) {
		curl_easy_setopt(curl, CURLOPT_URL, query);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, verbose);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
		curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 8);
		curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);

		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_data);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

		printf("Getting response from tracker\n");
		// Try connecting to server MAX_RETRY times and exit if still failing
		int i = 0;
		int err;
		while ((err = curl_easy_perform(curl)) != 0) {
			if (i >= MAX_RETRY) {
				printf("CURL error while connecting to server: %d\n", err);
				DESTROY(peer_id);
				return 1;
			}
			++i;
		}

		curl_easy_cleanup(curl);
		DESTROY(peer_id); // Free peer_id because we don't need it anymore
		curl = NULL;
	}

	unsigned char* orig_resp = response.str; // For freeing later

	// parse server response
	dict = decode(&response.str, &response.len, &type);
	if (dict == NULL || type != BE_DICT) {
		printf("Invalid response of length %ld from server\n", response.len);
		if (response.len > 0) {
			fwrite(orig_resp, 1, response.len, stdout);
			printf("\n");
		}
		DESTROY(dict);
		DESTROY(orig_resp);
		fclose(fp);
		return 1;
	}

	// peers
	val = dict_get(dict, (unsigned char*)"peers", &type);
	if (val == NULL || type != BE_STR) {
		printf("Invalid peers in server response\n");
		fwrite(orig_resp, 1, response.len, stdout);
		printf("\n");
		DICT_DESTROY(dict);
		DESTROY(orig_resp);
		fclose(fp);
		return 1;
	}
	string = (be_string*)val;
	unsigned char str[string->len + 1];
	memcpy(str, string->str, string->len);
	unsigned char* peers_str = str;

	// Peers are each 6 bytes if correctly formatted
	if (string->len % 6 != 0) {
		printf("Invalid peers length in server response\n");
		fwrite(orig_resp, 1, response.len, stdout);
		printf("\n");
		DICT_DESTROY(dict);
		DESTROY(orig_resp);
		fclose(fp);
		return 1;
	}

	int total_peers = string->len / 6; // Number of peers
	printf("Peers found: %d\n", total_peers);

	peer peers[HANDLECOUNT];
	int i = total_peers;

	while (i) {
		snprintf(peers[total_peers - i].ip,
				 INET_ADDRSTRLEN,
				 "%d.%d.%d.%d",
				 peers_str[0],
				 peers_str[1],
				 peers_str[2],
				 peers_str[3]);
		// ----------------------------------
		// Port number is calculated as
		// ----------------------------------
		// (peers_str[4] << 8)|(peers_str[5])
		// ----------------------------------
		// Shifting the 5th byte and OR it with the 6th byte
		// Suppose 5th byte is 001A and 6th byte is 00E1
		// Shifting 5th byte gives 1A00 and OR with 00E1 gives
		// 1AE1, which is the port number
		peers[total_peers - i].port = (peers_str[4] << 8) | peers_str[5];
		peers_str = peers_str + 6;
		printf("Peer %d: %s:%d\n",
			   total_peers - i,
			   peers[total_peers - i].ip,
			   peers[total_peers - i].port);
		--i;
	}
	DICT_DESTROY(dict);
	DESTROY(orig_resp);
	
	// Remove ourselves from the list of peers
	for (i = 0; i < total_peers; i++) {
		if ((strcmp(peers[i].ip, "127.0.0.1") == 0 || strcmp(peers[i].ip, ip) == 0)
			&& peers[i].port == port) {
			printf("Removing ourselves from the list of peers\n");
			while (i < total_peers - 1) {
				peers[i] = peers[i + 1];
				++i;
			}
			--total_peers;
			break;
		}
	}

	int sockets[total_peers]; // sockets for all peers returned by tracker
	int fdmax = 0;
	fd_set conn_master; // master set for connecting
	FD_ZERO(&conn_master);
	for (i = 0; i < total_peers; i++) {
		sockets[i] = socket(PF_INET, SOCK_STREAM, 0);
		if (sockets[i] < 0) {
			switch (errno) {
				case EPROTONOSUPPORT: {
					printf("Protocol not supported\n");
					break;
				}
				case EACCES: {
					printf("Permisson to create socket denied\n");
					break;
				}
				default: {
					printf("Error creating socket: %s\n", strerror(errno));
					break;
				}
			}
			fclose(fp);
			return 1;
		}
		struct sockaddr_in addr;
		memset(addr.sin_zero, 0, sizeof(addr.sin_zero));
		inet_pton(AF_INET, peers[i].ip, &addr.sin_addr);
		addr.sin_family = AF_INET;
		addr.sin_port = htons(peers[i].port);

		int sock_flags_before;
		if ((sock_flags_before = fcntl(sockets[i], F_GETFL, 0)) < 0) {
			printf("Failed to GET flags (fcntl)\n");
			close(sockets[i]);
			continue;
		}

		if (fcntl(sockets[i], F_SETFL, sock_flags_before | O_NONBLOCK) < 0) {
			printf("Failed to SET flags (fcntl)\n");
			close(sockets[i]);
			continue;
		}

		if (sockets[i] > fdmax) {
			fdmax = sockets[i];
		}

		int res = connect(sockets[i], (struct sockaddr*)&addr, sizeof(addr));
		if (res == 0) {
			printf("Connected to peer %s:%d\n", peers[i].ip, peers[i].port);
			continue;
		} else if (res < 0 && errno != EINPROGRESS) {
			printf("Error while connecting to peer %s:%d: %s\n",
				   peers[i].ip, peers[i].port,
				   strerror(errno));
			continue;
		}

		FD_SET(sockets[i], &conn_master);
	}

	printf("Connecting to peers\n");

	fd_set comm_master; // master set for communicating and downloading
	FD_ZERO(&comm_master);

	// Writing data to peers
	int conn_peers = 0;
	int left_peers = total_peers;
	while (left_peers > 0 && conn_peers < HANDLECOUNT) {
		struct timeval tv;
		tv.tv_sec = TIMEOUT;
		tv.tv_usec = 0;
		// Ready file desriptors copied from conn_master every loop
		fd_set ready_fds;
		FD_ZERO(&ready_fds);
		ready_fds = conn_master;
		int res = select(fdmax + 1, NULL, &ready_fds, NULL, &tv);
		if (res == -1) {
			verprintf(
			  verbose, "[E] Error on select() (hndshk): %s\n", strerror(errno));
			close_peer_socks(sockets, total_peers);
			fclose(fp);
			return 1;
		} else if (res) {
			for (int i = 0; i < total_peers && conn_peers < HANDLECOUNT; i++) {
				int curr_sock = sockets[i];
				if (curr_sock == -1) {
					continue;
				}
				if (FD_ISSET(curr_sock, &ready_fds)) {
					socklen_t len = sizeof res;
					getsockopt(curr_sock, SOL_SOCKET, SO_ERROR, &res, &len);
					if (res == 0) { // Can write
						verprintf(
						  verbose, "[c] Connected to peer %s:%d\n", peers[i].ip, peers[i].port);

						conn_socks[conn_peers] = curr_sock;
						FD_CLR(curr_sock, &conn_master);
						FD_SET(curr_sock, &comm_master);
						++conn_peers;

						res = send_all(curr_sock, hndshk, &hndshk_len);
						if (res < 0) {
							verprintf(verbose,
									  "[e] Could not send data to peer %s:%d\n",
									  peers[i].ip, peers[i].port);
						} else {
							verprintf(verbose,
									  "[h] Sent handshake to peer %s:%d\n",
									  peers[i].ip, peers[i].port);
						}
					} else { // Error
						verprintf(verbose,
								  "[e] Error on peer %s:%d: %s (whndshk)\n",
								  peers[i].ip, peers[i].port,
								  strerror(res));
						FD_CLR(curr_sock, &conn_master);
					}
				}
			}
		} else {
			verprintf(verbose, "[!] Timeout for connecting peers\n");
			break;
		}
	}

	verprintf(verbose, "[!] Connected to %d peers\n", conn_peers);

	peer_status stats[HANDLECOUNT];
	for (int i = 0; i < HANDLECOUNT; i++) {
		stats[i].mssg_len = 0;
		stats[i].recv_mssg_len = 0;
		stats[i].curr_step = i < conn_peers ? STEP_HANDSHAKE : STEP_NONE;
		stats[i].choked = 1;
		stats[i].interested = 0;
		stats[i].has_pcs = 0;
		stats[i].recv_intrstd = 0;
		stats[i].am_choking = 1;
		stats[i].bitfield = NULL;
		stats[i].mssg = NULL;
		stats[i].req = NULL;
		stats[i].req_len = 0;
		stats[i].curr_reqs = 0; // Number of ongoing requests
		stats[i].curr_pc_idx = -1;
		stats[i].curr_blck_off = -1;
		if (conn_socks[i] != -1) {
			struct sockaddr_in addr;
			socklen_t addrlen = sizeof addr;
			getpeername(conn_socks[i], (struct sockaddr*)&addr, &addrlen);
			inet_ntop(AF_INET, &addr.sin_addr, stats[i].ip, INET_ADDRSTRLEN);
		}
	}

	FD_SET(listen_sock, &comm_master);
	if (listen_sock > fdmax) {
		fdmax = listen_sock;
	}
	conn_socks[conn_peers++] = listen_sock;

	printf("Seeding \n");

	left_peers = conn_peers;
	// Ready file desriptors copied from comm_master set every loop
	fd_set ready_fds;
	int *leeched = calloc(SIMULBLOCKS, sizeof(int));
	int leeched_len = 0;

// 	// ------------------------- MAIN LOOP ------------------------------
	while (1) {
		int res;
		struct timeval tv = { .tv_sec = 0, .tv_usec = COMMTIMEOUT };
		FD_ZERO(&ready_fds);
		ready_fds = comm_master;
		res = select(fdmax + 1, &ready_fds, NULL, NULL, &tv);
		if (res == -1) {
			verprintf(
			  verbose, "[E] Error on select() (read): %s\n", strerror(errno));
			return 1;
		} else if (res) {
			for (int i = 0; i < conn_peers; i++) {
				int curr_sock = conn_socks[i];
				// printf("curr_sock: %d, ip: %s, port: %d\n", curr_sock, peers[i].ip, peers[i].port);
				if (curr_sock == -1) {
					FD_CLR(curr_sock, &comm_master);
					continue;
				}
				
				if (FD_ISSET(curr_sock, &ready_fds)) {
					if (curr_sock == listen_sock) {
						// ------------------------- ACCEPT -------------------------

						struct sockaddr_in cli_addr;
						socklen_t cli_len = sizeof(cli_addr);
						int new_sock = accept(listen_sock, (struct sockaddr*)&cli_addr,
											&cli_len);
						char ip[INET_ADDRSTRLEN];
						unsigned short port = ntohs(cli_addr.sin_port);
						inet_ntop(AF_INET, &cli_addr.sin_addr, ip, INET_ADDRSTRLEN);

						if (new_sock < 0) {
							printf("[e] Could not accept connection\n");
							return -1;
						}
						// Check message handshake
						unsigned char peer_hndshk[hndshk_len];
						res = recv(
						new_sock, peer_hndshk, hndshk_len, MSG_NOSIGNAL);
						if (res <= 0) {
							if (res == 0) {
								verprintf(
								verbose, "[e] Peer %s:%d hung up\n", ip, port);
							} else {
								verprintf(
								verbose,
								"[e] Error on peer %s:%d: %s (rhndshk)\n",
								ip, port,
								strerror(errno));
							}
							continue;
						} else {
							// res is the length of peer_hndshk that was read
							// as returned by recv()
							if (valid_hndshk(hndshk, peer_hndshk, res)) {
								verprintf(verbose,
										"[v] Got handshake from peer %s:%d\n",
										ip, port);
								// Update peer status
								int peer_idx = -1;
								for (int j = 0; j < HANDLECOUNT; j++) {
									if (conn_socks[j] == -1) {
										peer_idx = j;
										break;
									}
								}
								if (peer_idx == -1) {
									verprintf(verbose, "[e] Could not accept connection from peer %s:%d,"
											" no free slots\n", ip, port);
									close(new_sock);
									continue;
								}
								
								res = send_all(new_sock, hndshk, &hndshk_len);
								if (res < 0) {
									verprintf(verbose,
											"[e] Could not send data to peer %s:%d\n",
											ip, port);
									close(new_sock);
									continue;
								} else {
									verprintf(verbose,
											"[h] Sent handshake to peer %s:%d\n",
											ip, port);
									strcpy(stats[peer_idx].ip, ip);
									strcpy(peers[peer_idx].ip, stats[peer_idx].ip);
									peers[peer_idx].port = port;
									conn_socks[peer_idx] = new_sock;

									FD_SET(new_sock, &comm_master);
									if (new_sock > fdmax) {
										fdmax = new_sock;
									}
									left_peers++; 
									if (conn_peers <= peer_idx) {
										conn_peers = peer_idx + 1;
									}
									reset_peer_step(&stats[peer_idx]);
									stats[peer_idx].curr_step = STEP_SNDBTFLD;
									verprintf(
										verbose, "[a] Accepted connection from peer %s:%d\n",
										peers[peer_idx].ip, peers[peer_idx].port);
									continue;
								}
							} else {
								verprintf(verbose,
										"[e] BAD handshake from peer %s:%d\n",
										ip, port);
								continue;
							}
						}
						
					// ----------------------------------------------------------
					}
					char* curr_ip = stats[i].ip;
					int curr_pc_idx = stats[i].curr_pc_idx;
					// ===================== HANDSHAKE =======================
					if (stats[i].curr_step == STEP_HANDSHAKE) {
						unsigned char peer_hndshk[hndshk_len];
						res = recv(
						curr_sock, peer_hndshk, hndshk_len, MSG_NOSIGNAL);
						if (res <= 0) {
							if (res == 0) {
								verprintf(
								verbose, "[e] Peer %s:%d hung up\n", curr_ip, peers[i].port);
							} else {
								verprintf(
								verbose,
								"[e] Error on peer %s:%d: %s (rhndshk)\n",
								curr_ip, peers[i].port,
								strerror(errno));
							}
							conn_socks[i] = -1;
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							continue;
						} else {
							// res is the length of peer_hndshk that was read
							// as returned by recv()
							if (valid_hndshk(hndshk, peer_hndshk, res)) {
								verprintf(verbose,
										"[v] Got handshake from peer %s:%d\n",
										curr_ip, peers[i].port);
								reset_peer_step(&stats[i]);
								stats[i].curr_step = STEP_SNDBTFLD;
								continue;
							} else {
								verprintf(verbose,
										"[e] BAD handshake from peer %s:%d: %s\n",
										curr_ip, peers[i].port, strerror(errno));
								FD_CLR(curr_sock, &comm_master);
								--left_peers;
								continue;
							}
						}
					}

					// =================== MESSAGE LENGTH ====================
					if (stats[i].curr_step == STEP_READMSG) {
						// Tried recv() on peer but got no response
						if (stats[i].mssg_len > 0 &&
							stats[i].recv_mssg_len == 0) {
							verprintf(
							verbose,
							"[e] Peer %s:%d not responding. Disconnecting\n",
							curr_ip, peers[i].port);
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							DESTROY(stats[i].mssg);
							continue;
						}
						if (stats[i].mssg_len == 0) {
							stats[i].mssg_len = 4;
							stats[i].recv_mssg_len = 0;
							DESTROY(stats[i].mssg);
							stats[i].mssg = malloc(4);
						}
						if (mssg_received(stats[i])) {
							stats[i].mssg_len = int_from_bytes(stats[i].mssg);
							if (stats[i].mssg_len == 0) {
								verprintf(verbose,
										"[k] Peer %s:%d sent keep-alive\n",
										curr_ip, peers[i].port);
								DESTROY(stats[i].mssg);
								continue;
							}
							stats[i].curr_step = STEP_READID;
							DESTROY(stats[i].mssg);
							continue;
						}
						int len = stats[i].mssg_len - stats[i].recv_mssg_len;

						res = recv(curr_sock,
								stats[i].mssg + stats[i].recv_mssg_len,
								len,
								MSG_NOSIGNAL);
						if (res <= 0 && err_is_ignorable()) {
							continue;
						}
						if (res <= 0) {
							verprintf(
							verbose,
							"[e] Could not read length from peer %s:%d: %s\n",
							curr_ip, peers[i].port,
							strerror(errno));
							DESTROY(stats[i].mssg);
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							continue;
						}
						stats[i].recv_mssg_len += res;
						if (mssg_received(stats[i])) {
							stats[i].mssg_len = int_from_bytes(stats[i].mssg);
							if (stats[i].mssg_len == 0) {
								verprintf(verbose,
										"[k] Peer %s:%d sent keep-alive\n",
										curr_ip, peers[i].port);
								continue;
							}
							stats[i].curr_step = STEP_READID;
							DESTROY(stats[i].mssg);
							continue;
						}
						continue;
					}
					// =======================================================

					// ========================= ID ==========================
					if (stats[i].curr_step == STEP_READID) {
						DESTROY(stats[i].mssg);
						unsigned char id;
						res = recv(curr_sock, &id, 1, MSG_NOSIGNAL);
						if (res <= 0) {
							verprintf(
							verbose,
							"[e] Could not read id from peer %s:%d %s\n",
							curr_ip, peers[i].port,
							strerror(errno));
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							continue;
						}
						stats[i].mssg_len -= 1;     // Read ID
						stats[i].recv_mssg_len = 0; // Resetting to 0
						switch (id) {
							case INTERESTED: {
								verprintf(
								verbose,
								"[?] Got INTERESTED message from peer %s:%d\n",
								curr_ip, peers[i].port);
								stats[i].recv_intrstd = 1;
								if (leeched_len < SIMULBLOCKS)
									stats[i].curr_step = STEP_UNCHOKE;
								continue;
							}
							case NOT_INTERESTED: {
								verprintf(verbose,
										"[?] Got NOT INTERESTED message "
										"from peer %s:%d\n",
										curr_ip, peers[i].port);
								stats[i].recv_intrstd = 0;
								DESTROY(stats[i].mssg);
								// Check if this peer is in the leeched list
								// If so, remove it
								for (int j = 0; j < leeched_len; ++j) {
									if (leeched[j] == curr_sock) {
										leeched[j] = leeched[leeched_len - 1];
										--leeched_len;
										break;
									}
								}
								continue;
							}
							case REQUEST: {
								verprintf(
								verbose,
								"[?] Got REQUEST message from peer %s\n",
								curr_ip);
								if (stats[i].am_choking) {
									verprintf(
									verbose,
									"[e] Peer %s:%d requested piece while "
									"we are choking him\n",
									curr_ip, peers[i].port);
									FD_CLR(curr_sock, &comm_master);
									--left_peers;
									DESTROY(stats[i].mssg);
									continue;
								}
								leeched[leeched_len++] = curr_sock;
								stats[i].curr_step = STEP_READREQ;
								continue;
							}
							case CANCEL: {
								verprintf(
								verbose,
								"[?] Got CANCEL message from peer %s:%d\n",
								curr_ip, peers[i].port);
								stats[i].curr_step = STEP_CANCEL;
								continue;
							}
							case HAVEALL: {
								verprintf(
								verbose,
								"[?] Got HAVEALL message from peer %s:%d\n",
								curr_ip, peers[i].port);
								stats[i].curr_step = STEP_UNCHOKE;
								continue;
							}
							// fall through
							case EXTENDED: {
								verprintf(
								verbose,
								"[?] Got EXTENDED message from peer %s:%d\n",
								curr_ip, peers[i].port);
								continue;
							}
							case HAVE: {
								if (stats[i].bitfield == NULL) {
									stats[i].bitfield = calloc(
									  cl_bitf_len, sizeof(unsigned char));
									if (stats[i].bitfield == NULL) {
										verprintf(verbose,
												  "[e] Could not allocate "
												  "bitfield for peer %s\n",
												  curr_ip);
									}
								}
								stats[i].curr_step = STEP_HAVE;
								continue;
							}
							case PIECE: {
								stats[i].recv_mssg_len = 0;
								stats[i].curr_step = STEP_DOWNLOAD;
								continue;
							}
							case BITFIELD: {
								stats[i].curr_step = STEP_BITFIELD;
								continue;
							}
							case UNCHOKE: {
								verprintf(verbose,
										"[u] Peer %s:%d unchoked us\n",
										curr_ip, peers[i].port);
								continue;
							}
							// fall through
							case CHOKE: {
								verprintf(
								verbose, "[o] Peer %s:%d choked us\n",
								curr_ip, peers[i].port);
								continue;
							}
							// fall through
							default: {
								FD_CLR(curr_sock, &comm_master);	
								--left_peers;
								continue;
							}
						}
					}
					// ====================== BITFIELD =======================
					if (stats[i].curr_step == STEP_BITFIELD) {
						if (stats[i].mssg_len != cl_bitf_len) {
							verprintf(verbose,
									  "[e] Peer %s sent bitfield of invalid "
									  "length %d\n",
									  curr_ip,
									  stats[i].mssg_len);
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							continue;
						}
						if (mssg_received(stats[i])) {
							verprintf(verbose,
									  "[b] Read bitfield (%d) from peer %s\n",
									  stats[i].recv_mssg_len,
									  curr_ip);
							stats[i].mssg_len = 0;
							stats[i].recv_mssg_len = 0;
							stats[i].has_pcs = 1;
							continue;
						}
						if (stats[i].bitfield == NULL) {
							stats[i].bitfield = malloc(stats[i].mssg_len);
							if (stats[i].bitfield == NULL) {
								verprintf(verbose,
										  "[x] Could not allocate bitfield "
										  "for peer %s\n",
										  curr_ip);
								FD_CLR(curr_sock, &comm_master);
								--left_peers;
								continue;
							}
						}
						int len = stats[i].mssg_len - stats[i].recv_mssg_len;
						if (len > cl_bitf_len) {
							printf("bitf");
							len = 0;
						}
						res = recv(curr_sock,
								   stats[i].bitfield + stats[i].recv_mssg_len,
								   len,
								   MSG_NOSIGNAL);
						if (res <= 0) {
							verprintf(
							  verbose,
							  "[e] Could not read bitfield from peer %s: %s\n",
							  curr_ip,
							  strerror(errno));
							DESTROY(stats[i].bitfield);
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							continue;
						}
						stats[i].recv_mssg_len += res;
						if (mssg_received(stats[i])) {
							verprintf(verbose,
									  "[b] Read bitfield (%d) from peer %s\n",
									  stats[i].recv_mssg_len,
									  curr_ip);
							stats[i].mssg_len = 0;
							stats[i].recv_mssg_len = 0;
							stats[i].has_pcs = 1;
							continue;
						}
						continue;
					}
					// =======================================================

					// ======================== HAVE =========================
					if (stats[i].curr_step == STEP_HAVE) {
						int have_len = stats[i].mssg_len;
						if (have_len != 4) {
							verprintf(
							  verbose,
							  "[e] Peer %s sent HAVE of invalid length %d\n",
							  curr_ip,
							  have_len);
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							continue;
						}
						unsigned char index[have_len];
						uint32_t piece_index = -1;
						res = recv(curr_sock, index, have_len, MSG_NOSIGNAL);
						if (res < 4) {
							verprintf(verbose,
									  "[e] Could not read HAVE from peer %s\n",
									  curr_ip);
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							continue;
						} else {
							piece_index = int_from_bytes(index);
							set_piece(stats[i].bitfield, piece_index);
							if (has_piece(stats[i].bitfield, piece_index)) {
								verprintf(verbose,
										  "[v] Peer %s HAVE piece %d\n",
										  curr_ip,
										  piece_index);
							} else {
								verprintf(
								  verbose,
								  "[e] Could not set HAVE for peer %s\n",
								  curr_ip);
							}
						}
						reset_peer_step(&stats[i]);
						stats[i].has_pcs = 1;
						continue;
					}

					// ================== DOWNLOAD BLOCKS ====================
					if (stats[i].curr_step == STEP_DOWNLOAD) {
						if (mssg_received(stats[i])) {
							int blck_idx = stats[i].curr_blck_off / BLOCKLEN;
							verprintf(verbose,
									  "[b] Read piece %d and block %d (%d) "
									  "from peer %s\n",
									  curr_pc_idx,
									  blck_idx,
									  stats[i].recv_mssg_len,
									  curr_ip);

							DESTROY(stats[i].mssg);
							stats[i].curr_blck_off = -1;
							reset_peer_step(&stats[i]);
							--stats[i].curr_reqs;
							break;
						}
						if (stats[i].recv_mssg_len == 0 &&
							stats[i].curr_blck_off < 0) {
							unsigned char piece_index_buff[4];
							unsigned char block_offset_buff[4];
							res = recv(
							  curr_sock, piece_index_buff, 4, MSG_NOSIGNAL);
							if (res <= 0 && err_is_ignorable()) {
								continue;
							}
							if (res < 4) {
								verprintf(verbose,
										  "[e] Could not read piece index "
										  "from peer %s: %s\n",
										  curr_ip,
										  strerror(errno));
								FD_CLR(curr_sock, &comm_master);
								--left_peers;
								DESTROY(stats[i].mssg);
								continue;
							}
							int piece_index = int_from_bytes(piece_index_buff);
							// If got a wrong piece index reset the piece this
							// peer was downloading
							if (piece_index != curr_pc_idx) {
								verprintf(verbose,
										  "[e] Wrong piece index %d (req: %d) "
										  "on peer %s\n",
										  piece_index,
										  curr_pc_idx,
										  curr_ip);
								DESTROY(stats[i].mssg);
								FD_CLR(curr_sock, &comm_master);
								--left_peers;
								continue;
							}
							res = recv(
							  curr_sock, block_offset_buff, 4, MSG_NOSIGNAL);
							if (res <= 0 && err_is_ignorable()) {
								continue;
							}
							if (res < 4) {
								verprintf(
								  verbose,
								  "[e] Could not read block offset from peer "
								  "%s: %s (Piece %d, Block %lld)\n",
								  curr_ip,
								  strerror(errno),
								  curr_pc_idx,
								  stats[i].curr_blck_off);
								FD_CLR(curr_sock, &comm_master);
								--left_peers;
								DESTROY(stats[i].mssg);
								continue;
							}
							stats[i].curr_blck_off =
							  int_from_bytes(block_offset_buff);
							stats[i].mssg_len -= 8; // Read 8 bytes already
							DESTROY(stats[i].mssg);
							stats[i].mssg = malloc(stats[i].mssg_len);
							if (stats[i].mssg == NULL) {
								verprintf(
								  verbose,
								  "[x] Could not allocate block for peer %s\n",
								  curr_ip);
								FD_CLR(curr_sock, &comm_master);
								--left_peers;
								continue;
							}
						}
						int len = stats[i].mssg_len - stats[i].recv_mssg_len;
						res = recv(curr_sock,
								   stats[i].mssg + stats[i].recv_mssg_len,
								   len,
								   MSG_NOSIGNAL);
						if (res <= 0 && err_is_ignorable()) {
							continue;
						}
						if (res <= 0) {
							verprintf(
							  verbose,
							  "[e] Could not read block from peer %s: %s\n",
							  curr_ip,
							  strerror(errno));
							int blck_idx = stats[i].curr_blck_off / BLOCKLEN;
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							continue;
						}
						stats[i].recv_mssg_len += res;
						if (mssg_received(stats[i])) {
							int blck_idx = stats[i].curr_blck_off / BLOCKLEN;
							verprintf(verbose,
									  "[b] Read piece %d and block %d (%d) "
									  "from peer %s\n",
									  curr_pc_idx,
									  blck_idx,
									  stats[i].recv_mssg_len,
									  curr_ip);

							DESTROY(stats[i].mssg);

							stats[i].curr_blck_off = -1;
							reset_peer_step(&stats[i]);
							--stats[i].curr_reqs;
							break;
						}
					}
					// =======================================================
				}
			}
		}

		// =================== SEND MESSAGES =====================
		for (int i = 0; i < conn_peers; i++) {
			char* curr_ip = stats[i].ip;
			int curr_sock = conn_socks[i];
			if (conn_socks[i] == -1 || conn_socks[i] == listen_sock)
				continue;
			// =================== SEND BITFIELD =====================
			if (stats[i].curr_step == STEP_SNDBTFLD) {
				// Bitfield message:
				// 4 byte: length prefix
				// 1 byte: message id
				// x byte: bitfield
				unsigned char btfld_msg[cl_bitf_len + 5];
				// Set length prefix
				int_to_bytes(btfld_msg, cl_bitf_len + 1);
				// Set message id	
				btfld_msg[4] = 5;
				// Create finished bitfield, and set it in the message
				unsigned char* btfld = &btfld_msg[5];
				memset(btfld, 255, cl_bitf_len);
				// Set the last byte of the bitfield
				int last_byte = cl_bitf_len - 1;
				int last_byte_bits = num_blcks % 8;
				if (last_byte_bits == 0) {
					last_byte_bits = 8;
				}
				btfld[last_byte] = 0;
				for (int j = 0; j < last_byte_bits; ++j) {
					btfld[last_byte] |= 1 << (7 - j);
				}
				// Send the bitfield message
				int btfld_len = cl_bitf_len + 5;
				res = send_all(curr_sock, btfld_msg, &btfld_len);
				if (res < 0) {
					verprintf(
					verbose,
					"[e] Error on peer %s:%d: %s (sndbtfld)\n",
					curr_ip, peers[i].port,
					strerror(errno));
					conn_socks[i] = -1;
					FD_CLR(curr_sock, &comm_master);
					--left_peers;
				} else {
					verprintf(verbose,
							"[v] Sent bitfield to peer %s:%d\n",
							curr_ip, peers[i].port);
					reset_peer_step(&stats[i]);
					DESTROY(stats[i].mssg);
				}
			}
			// =================== SEND NOT INTERESTED =====================
			if (stats[i].curr_step == STEP_NOTINTERESTED) {
				// Not interested message:
				// 4 byte: length prefix
				// 1 byte: message id
				unsigned char notint_msg[5];
				// Set length prefix
				int_to_bytes(notint_msg, 1);
				// Set message id
				notint_msg[4] = NOT_INTERESTED;
				// Send the not interested message
				int notint_len = 5;
				res = send_all(curr_sock, notint_msg, &notint_len);
				if (res < 0) {
					verprintf(
					verbose,
					"[e] Error on peer %s:%d: %s (sndnotint)\n",
					curr_ip, peers[i].port,
					strerror(errno));
					conn_socks[i] = -1;
					FD_CLR(curr_sock, &comm_master);
					--left_peers;
				} else {
					verprintf(verbose,
							"[v] Sent not interested to peer %s:%d\n",
							curr_ip, peers[i].port);
					reset_peer_step(&stats[i]);
					DESTROY(stats[i].mssg);
				}
			}
			// =================== EXTENDED =====================
			if (stats[i].curr_step == STEP_EXT) {
				// Extended message:
				// 4 byte: length prefix
				// 1 byte: message id
				// x byte: extended message
				unsigned char ext_msg[ext_hndshk_len + 5];
				// Set length prefix
				int_to_bytes(ext_msg, ext_hndshk_len + 1);
				// Set message id
				ext_msg[4] = EXTENDED;
				// Set extended message
				unsigned char* ext = &ext_msg[5];
				memcpy(ext, ext_hndshk_str, ext_hndshk_len);
				// Send the extended message
				int ext_len = ext_hndshk_len + 5;
				res = send_all(curr_sock, ext_msg, &ext_len);
				if (res < 0) {
					verprintf(
					verbose,
					"[e] Error on peer %s:%d: %s (sndext)\n",
					curr_ip, peers[i].port,
					strerror(errno));
					conn_socks[i] = -1;
					FD_CLR(curr_sock, &comm_master);
					--left_peers;
				} else {
					verprintf(verbose,
							"[v] Sent extended message to peer %s:%d\n",
							curr_ip, peers[i].port);
					reset_peer_step(&stats[i]);
					stats[i].curr_step = STEP_HAVEALL;
					DESTROY(stats[i].mssg);
				}
			}
			// =================== SEND HAVEALL =====================
			if (stats[i].curr_step == STEP_HAVEALL) {
				// Have all message:
				// 4 byte: length prefix: 0001
				// 1 byte: message id: 14
				unsigned char haveall_msg[5] = {0, 0, 0, 1, HAVEALL};
				int haveall_len = 5;
				res = send_all(curr_sock, haveall_msg, &haveall_len);
				if (res < 0) {
					verprintf(
					verbose,
					"[e] Error on peer %s:%d: %s (sndhaveall)\n",
					curr_ip, peers[i].port,
					strerror(errno));
					conn_socks[i] = -1;
					FD_CLR(curr_sock, &comm_master);
					--left_peers;
				} else {
					verprintf(verbose,
							"[v] Sent HAVEALL to peer %s:%d\n",
							curr_ip, peers[i].port);
					reset_peer_step(&stats[i]);
					DESTROY(stats[i].mssg);
				}
			}
			// =================== UNCHOKE PEER ======================
			if (stats[i].curr_step == STEP_UNCHOKE) {
				verprintf(verbose, "[u] Unchoking peer %s:%d\n", curr_ip, peers[i].port);
				stats[i].am_choking = 0;
				unsigned char unchoke[] = {0, 0, 0, 1, UNCHOKE};
				int unchokelen = 5;
				res = send_all(curr_sock, unchoke, &unchokelen);
				if (res < 0) {
					verprintf(
					verbose,
					"[e] Could not send unchoke to peer %s:%d: %s\n",
					curr_ip, peers[i].port,
					strerror(errno));
					FD_CLR(curr_sock, &comm_master);
					--left_peers;
				} else {
					reset_peer_step(&stats[i]);
					DESTROY(stats[i].mssg);
				}
			}

			// =================== CHOKE PEER ========================
			if (stats[i].curr_step == STEP_CHOKE) {
				verprintf(verbose, "[u] Choking peer %s:%d\n", curr_ip, peers[i].port);
				stats[i].am_choking = 1;
				unsigned char choke[] = {0, 0, 0, 1, CHOKE};
				int chokelen = 5;
				res = send_all(curr_sock, choke, &chokelen);
				if (res < 0) {
					verprintf(
					verbose,
					"[e] Could not send choke to peer %s:%d: %s\n",
					curr_ip, peers[i].port,
					strerror(errno));
					FD_CLR(curr_sock, &comm_master);
					--left_peers;
				} else {
					reset_peer_step(&stats[i]);
					DESTROY(stats[i].mssg);
				}
			}

			// =================== READ REQUEST ======================
			if (stats[i].curr_step == STEP_READREQ) {
				verprintf(
				verbose,
				"[?] Reading request from peer %s:%d\n",
				curr_ip, peers[i].port);
				
				if (stats[i].mssg == NULL) {
					stats[i].mssg = malloc(13);
					stats[i].mssg_len = 13;
					stats[i].recv_mssg_len = 0;
					if (stats[i].mssg == NULL) {
						verprintf(
						verbose,
						"[e] Could not allocate memory for request "
						"from peer %s:%d\n",
						curr_ip, peers[i].port);
						FD_CLR(curr_sock, &comm_master);
						--left_peers;
						continue;
					}
				}
				res = recv(curr_sock,
						stats[i].mssg + stats[i].recv_mssg_len,
						12,
						MSG_NOSIGNAL);

				if (res <= 0) {
					verprintf(
					verbose,
					"[e] Could not read request from peer %s:%d: %s\n",
					curr_ip, peers[i].port,
					strerror(errno));
					FD_CLR(curr_sock, &comm_master);
					--left_peers;
					continue;
				}
				stats[i].recv_mssg_len += res;
				
				int index = int_from_bytes(stats[i].mssg);
				int begin = int_from_bytes(stats[i].mssg + 4);
				int length = int_from_bytes(stats[i].mssg + 8);
				if (index >= num_pcs) {
					verprintf(
					verbose,
					"[e] Peer %s:%d requested piece %d, but we only "
					"have %d pieces\n",
					curr_ip, peers[i].port,
					index,
					num_pcs);
					FD_CLR(curr_sock, &comm_master);
					--left_peers;
					continue;
				}
				if (length > PIECELEN) {
					verprintf(
					verbose,
					"[e] Peer %s:%d requested piece %d, offset %d, "
					"length %d, but we only have %d bytes per "
					"piece\n",
					curr_ip, peers[i].port,
					index,
					begin,
					length,
					PIECELEN);
					FD_CLR(curr_sock, &comm_master);
					--left_peers;
					continue;
				}
				if (begin + length > PIECELEN) {
					verprintf(
					verbose,
					"[e] Peer %s:%d requested piece %d, offset %d, "
					"length %d, but it exceeds the piece length "
					"of %d bytes\n",
					curr_ip, peers[i].port,
					index,
					begin,
					length,
					PIECELEN);
					FD_CLR(curr_sock, &comm_master);
					--left_peers;
					continue;
				}
				if (stats[i].req_len == MAXREQS) {
					verprintf(
					verbose,
					"[e] Peer %s:%d requested piece %d, offset %d, "
					"length %d, but we already have %d requests "
					"from it\n",
					curr_ip, peers[i].port,
					index,
					begin,
					length,
					MAXREQS);
					FD_CLR(curr_sock, &comm_master);
					--left_peers;
					continue;
				}
				if (stats[i].req == NULL) {
					stats[i].req = malloc(sizeof(peer_req) * MAXREQS);
					if (stats[i].req == NULL) {
						verprintf(
						verbose,
						"[e] Could not allocate memory for request "
						"from peer %s:%d\n",
						curr_ip, peers[i].port);
						FD_CLR(curr_sock, &comm_master);
						--left_peers;
						continue;
					}
					for (int j = 0; j < MAXREQS; ++j) {
						stats[i].req[j].index = -1;
						stats[i].req[j].begin = -1;
						stats[i].req[j].length = -1;
					}
				}
				verprintf(
				verbose,
				"[?] Requested piece %d, offset %d, length %d\n",
				index,
				begin,
				length);
				// Add the request to empty slot
				for (int j = 0; j < MAXREQS; ++j) {
					if (stats[i].req[j].index == -1) {
						stats[i].req[j].index = index;
						stats[i].req[j].begin = begin;
						stats[i].req[j].length = length;
						++stats[i].req_len;
						break;
					}
				}
				reset_peer_step(&stats[i]);
				DESTROY(stats[i].mssg);
			}

			// =================== CANCEL REQUESTS ======================
			if (stats[i].curr_step == STEP_CANCEL) {
				if (stats[i].mssg == NULL) {
					stats[i].mssg = malloc(13);
					stats[i].mssg_len = 13;
					stats[i].recv_mssg_len = 0;
					if (stats[i].mssg == NULL) {
						verprintf(
						verbose,
						"[e] Could not allocate memory for request "
						"from peer %s:%d\n",
						curr_ip, peers[i].port);
						FD_CLR(curr_sock, &comm_master);
						--left_peers;
						continue;
					}
				}
				res = recv(curr_sock,
						stats[i].mssg + stats[i].recv_mssg_len,
						12,
						MSG_NOSIGNAL);

				if (res <= 0) {
					verprintf(
					verbose,
					"[e] Could not read request from peer %s:%d: %s\n",
					curr_ip, peers[i].port,
					strerror(errno));
					FD_CLR(curr_sock, &comm_master);
					--left_peers;
					continue;
				}
				stats[i].recv_mssg_len += res;
				
				int index = int_from_bytes(stats[i].mssg);
				int begin = int_from_bytes(stats[i].mssg + 4);
				int length = int_from_bytes(stats[i].mssg + 8);
				
				for (int j = 0; j < MAXREQS; ++j) {
					if (stats[i].req[j].index == index &&
						stats[i].req[j].begin == begin &&
						stats[i].req[j].length == length) {
						stats[i].req[j].index = -1;
						stats[i].req[j].begin = -1;
						stats[i].req[j].length = -1;
						--stats[i].req_len;
						break;
					}
				}
				verprintf(
				verbose,
				"[?] Cancelled request for piece %d, offset %d, "
				"length %d\n", index, begin, length);
				reset_peer_step(&stats[i]);
				DESTROY(stats[i].mssg);
			}
		}

		// =================== LEECH PIECES ======================
		for (int i = 0; i < leeched_len; ++i) {
			int curr_sock = leeched[i];
			int curr_peer = -1;
			for (int j = 0; j < conn_peers; ++j) {
				if (conn_socks[j] == curr_sock) {
					curr_peer = j;
					break;
				}
			}
			if (curr_peer == -1) {
				verprintf(verbose, "[e] Could not find peer for socket %d\n", curr_sock);
				FD_CLR(curr_sock, &comm_master);
				--left_peers;
				leeched[i] = leeched[--leeched_len];
				--i;
				continue;
			}
			char *curr_ip = stats[curr_peer].ip;
			// Start by checking if we have any requests from this peer
			if (stats[curr_peer].req_len == 0) {
				verprintf(verbose, "[?] No requests from peer %s:%d\n", curr_ip, peers[curr_peer].port);
				// Replace this socket with the last one in the array
				leeched[i] = leeched[--leeched_len];
				--i;
				continue;
			}
			// Check if we have any pieces to send
			int curr_req = -1;
			for (int j = 0; j < MAXREQS; ++j) {
				if (stats[curr_peer].req[j].index == -1) {
					continue;
				}
				curr_req = j;
				break;
			}
			if (curr_req == -1) {
				verprintf(verbose, "[?] No pieces to send to peer %s:%d\n",
				curr_ip, peers[curr_peer].port);
				// Replace this socket with the last one in the array
				leeched[i] = leeched[--leeched_len];
				--i;
				// Send a keep-alive message
				verprintf(verbose, "[?] Sending keep-alive to peer %s:%d\n",
				curr_ip, peers[curr_peer].port);
				unsigned char *keep_alive = (char *)malloc(4);
				int_to_bytes(keep_alive, 0);
				if (send(curr_sock, keep_alive, 4, 0) == -1) {
					verprintf(verbose, "[e] Could not send keep-alive to peer %s:%d\n",
					curr_ip, peers[curr_peer].port);
					FD_CLR(curr_sock, &comm_master);
					--left_peers;
					continue;
				}
				continue;
			}
			// Send the piece
			int index = stats[curr_peer].req[curr_req].index;
			int begin = stats[curr_peer].req[curr_req].begin;
			int length = stats[curr_peer].req[curr_req].length;
			verprintf(
			verbose,
			"[?] Sending piece %d, offset %d, length %d to peer %s:%d\n",
			index,
			begin,
			length,
			curr_ip, peers[curr_peer].port);
			char *piece = malloc(length);
			if (piece == NULL) {
				verprintf(verbose, "[e] Could not allocate memory for piece\n");
				FD_CLR(curr_sock, &comm_master);
				--left_peers;
				continue;
			}
			// Read the piece from the file
			fseek(fp, index * PIECELEN + begin, SEEK_SET);
			fread(piece, 1, length, fp);
			// Send the piece
			unsigned char *mssg = malloc(13 + length);
			if (mssg == NULL) {
				verprintf(verbose, "[e] Could not allocate memory for piece mssg\n");
				FD_CLR(curr_sock, &comm_master);
				--left_peers;
				continue;
			}
			// Piece mssg format: <len=0009 + X><id=7><index><begin><piece>
			int mssg_len = 9 + length;
			int_to_bytes(mssg, mssg_len);
			mssg[4] = 7;
			int_to_bytes(mssg + 5, index);
			int_to_bytes(mssg + 9, begin);
			memcpy(mssg + 13, piece, length);
			free(piece);
			mssg_len += 4;
			res = send_all(curr_sock, mssg, &mssg_len);
			if (res < 0) {
				verprintf(verbose, "[e] Could not send piece to peer %s:%d\n",
				curr_ip, peers[curr_peer].port);
				FD_CLR(curr_sock, &comm_master);
				--left_peers;
				leeched[i] = leeched[--leeched_len];
				--i;
				continue;
			}
			// Delete the request
			stats[curr_peer].req[curr_req].index = -1;
			stats[curr_peer].req[curr_req].begin = -1;
			stats[curr_peer].req[curr_req].length = -1;
			--stats[curr_peer].req_len;
			DESTROY(stats[curr_peer].mssg);
			DESTROY(mssg);
		}	
	}
	if (left_peers == 0) {
		verprintf(verbose, "[i] No more peers left to communicate with \n");
	}
	cleanup(stats, conn_peers, NULL, 0, sockets, total_peers, fp);
	return 0;
}

int
leech(const char* file, char* name, int verbose)
{
	char query[BUFFLEN + 1];
	void* val;
	be_type type;

	FILE* fp; // file to which the content will be downloaded

	unsigned char* annurl;
	// 3 characters for every info hash element. 2 for hex representation
	// and 1 for the '%' sign
	char info_hash[(3 * SHA_DIGEST_LENGTH) + 1] = "\0";
	long long int length;
	long long int piece_len;
	int num_pcs;
	int pcs_dwnlded = 0;

	int conn_socks[HANDLECOUNT] = { -1 };

	// peer id
	// -------
	char* peer_id = generate_peer_id();

	be_string* string;
	be_dict* dict = decode_file(file);
	if (dict == NULL) {
		printf("Could not read or Found syntax error in torrent file\n");
		DESTROY(peer_id);
		return 1;
	}

	// announce URL
	// ------------
	val = dict_get(dict, (unsigned char*)"announce", &type);
	if (val == NULL || type != BE_STR) {
		printf("No announce URL found\n");
		DICT_DESTROY(dict);
		DESTROY(peer_id);
		return 1;
	}
	string = (be_string*)val;
	annurl = string->str;

	// info hash
	// ---------
	if (!dict->has_info_hash) {
		DICT_DESTROY(dict);
		printf("Info hash could not be calculated");
		DESTROY(peer_id);
		return 1;
	}
	for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
		// 3 is used because each hex representation will be 2 bytes
		// so 2+1 = 3. for null terminating character and '%'
		info_hash[i * 3] = '%';
		snprintf(&info_hash[i * 3 + 1], 3, "%02X", dict->info_hash[i]);
	}

	// info
	// ----
	val = dict_get(dict, (unsigned char*)"info", &type);
	if (val == NULL || type != BE_DICT) {
		printf("No info dictionary found\n");
		DICT_DESTROY(dict);
		DESTROY(peer_id);
		return 1;
	}
	be_dict* info = (be_dict*)val;

	// length
	// ------
	val = dict_get(info, (unsigned char*)"length", &type);
	if (val == NULL || type != BE_INT) {
		printf("No length found\n");
		DICT_DESTROY(dict);
		DESTROY(peer_id);
		return 1;
	}
	length = (long long int)val;

	// piece length
	// ------------
	val = dict_get(info, (unsigned char*)"piece length", &type);
	if (val == NULL || type != BE_INT) {
		printf("No piece length found\n");
		DICT_DESTROY(dict);
		DESTROY(peer_id);
		return 1;
	}
	piece_len = (long long int)val;

	// name
	// ----
	val = dict_get(info, (unsigned char*)"name", &type);
	if (val == NULL || type != BE_STR) {
		printf("No name found\n");
		DICT_DESTROY(dict);
		DESTROY(peer_id);
		return 1;
	}
	string = (be_string*)val;
	strcpy(name, (char*)string->str);

	fp = fopen(name, "w+");
	if (fp == NULL) {
		printf("Could not open file: %s\n", strerror(errno));
		DICT_DESTROY(dict);
		DESTROY(peer_id);
		return 1;
	}

	// -----------------------------------------------------------------------
	num_pcs = length / piece_len + (length % piece_len != 0);
	int cl_bitf_len = num_pcs / 8 + (num_pcs % 8 != 0);
	int num_blcks = piece_len / BLOCKLEN + (piece_len % BLOCKLEN != 0);
	// -----------------------------------------------------------------------

	// pieces
	val = dict_get(info, (unsigned char*)"pieces", &type);
	if (val == NULL || type != BE_STR) {
		printf("No pieces found\n");
		DICT_DESTROY(dict);
		DESTROY(peer_id);
		return 1;
	}
	be_string* hashes = (be_string*)val;
	int hash_len = hashes->len;
	if ((hash_len / SHA_DIGEST_LENGTH) != num_pcs ||
		(hash_len % SHA_DIGEST_LENGTH) != 0) {
		printf("Invalid pieces content in torrent file\n");
		DICT_DESTROY(dict);
		DESTROY(peer_id);
		return 1;
	}

	// --------------------------- CLIENT BITFIELD ---------------------------
	piece cl_pcs[num_pcs];
	long long int total = 0;
	for (int i = 0; i < num_pcs; i++) {
		cl_pcs[i].status = NONE;
		cl_pcs[i].data = NULL;

		memcpy(cl_pcs[i].valid_hash,
			   (hashes->str) + (i * SHA_DIGEST_LENGTH),
			   SHA_DIGEST_LENGTH);
		if (i < num_pcs - 1) {
			cl_pcs[i].length = piece_len;
			total += piece_len;
		} else
			cl_pcs[i].length = length - total;

		cl_pcs[i].blocks = malloc(num_blcks * sizeof(block));
		int blck_total = 0;
		for (int j = 0; j < num_blcks; j++) {
			int this_len = cl_pcs[i].length - blck_total;
			if (BLOCKLEN < this_len) {
				this_len = BLOCKLEN;
			}
			cl_pcs[i].blocks[j].length = this_len;
			cl_pcs[i].blocks[j].status = NONE;
			if (cl_pcs[i].blocks[j].length == 0) {
				cl_pcs[i].blocks[j].status = DOWNLOADED;
			}
			cl_pcs[i].blocks[j].offset = j * BLOCKLEN;
			blck_total += this_len;
		}
	}
	// -----------------------------------------------------------------------

	printf("Tracker found: %s\n", annurl);

	snprintf(query,
			 BUFFLEN + 1,
			 "%s?info_hash=%s&peer_id=%s&port=6887&uploaded=0&downloaded=0&"
			 "left=%lld&compact=1",
			 annurl,
			 info_hash,
			 peer_id,
			 length);

	// ------------------------------ HANDSHAKE ------------------------------
	// 1 byte for length of protocol identifier
	// PSTRLEN for actual protocol identifier
	// 8 bytes for extensions support (all 0 for now)
	// SHA_DIGEST_LENGTH for info_hash
	// PEERID_LEN for peer ID
	// -----------------------------------------------------------------------
	int hndshk_len = 1 + PSTRLEN + 8 + SHA_DIGEST_LENGTH + PEERID_LEN;
	unsigned char hndshk[hndshk_len];
	hndshk[0] = PSTRLEN;
	memcpy(&hndshk[1], PSTR, PSTRLEN);
	memset(&hndshk[1 + PSTRLEN], 0, 8);
	memcpy(&hndshk[1 + PSTRLEN + 8], dict->info_hash, SHA_DIGEST_LENGTH);
	memcpy(&hndshk[1 + PSTRLEN + 8 + SHA_DIGEST_LENGTH], peer_id, PEERID_LEN);

	// Destroy dictionary after everything related
	// to this dictionary is done
	DICT_DESTROY(dict);
	dict = NULL;

	CURL* curl;
	be_string response;
	response.len = 0;
	response.str = malloc(1);
	response.str[0] = '\0';
	curl = curl_easy_init();
	if (curl != NULL) {
		curl_easy_setopt(curl, CURLOPT_URL, query);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
		curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_data);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

		printf("Getting response from tracker\n");
		// Try connecting to server MAX_RETRY times and exit if still failing
		int i = 0;
		int err;
		while ((err = curl_easy_perform(curl)) != 0) {
			if (i >= MAX_RETRY) {
				printf("CURL error while connecting to server: %d\n", err);
				DESTROY(peer_id);
				return 1;
			}
			++i;
		}

		curl_easy_cleanup(curl);
		DESTROY(peer_id); // Free peer_id because we don't need it anymore
		curl = NULL;
	}

	unsigned char* orig_resp = response.str; // For freeing later
	
	// Print server response
	printf("Server response:\n");
	fwrite(orig_resp, 1, response.len, stdout);

	// parse server response
	dict = decode(&response.str, &response.len, &type);
	if (dict == NULL || type != BE_DICT) {
		printf("Invalid response of length %ld from server\n", response.len);
		if (response.len > 0) {
			fwrite(orig_resp, 1, response.len, stdout);
			printf("\n");
		}
		DESTROY(dict);
		DESTROY(orig_resp);
		fclose(fp);
		return 1;
	}

	// peers
	val = dict_get(dict, (unsigned char*)"peers", &type);
	if (val == NULL || type != BE_STR) {
		printf("Invalid peers in server response\n");
		fwrite(orig_resp, 1, response.len, stdout);
		printf("\n");
		DICT_DESTROY(dict);
		DESTROY(orig_resp);
		fclose(fp);
		return 1;
	}
	string = (be_string*)val;
	unsigned char str[string->len + 1];
	memcpy(str, string->str, string->len);
	unsigned char* peers_str = str;

	// Peers are each 6 bytes if correctly formatted
	if (string->len % 6 != 0) {
		printf("Invalid peers length in server response\n");
		fwrite(orig_resp, 1, response.len, stdout);
		printf("\n");
		DICT_DESTROY(dict);
		DESTROY(orig_resp);
		fclose(fp);
		return 1;
	}

	int total_peers = string->len / 6; // Number of peers
	printf("Peers found: %d\n", total_peers);

	peer peers[total_peers];
	int i = total_peers;

	while (i) {
		snprintf(peers[total_peers - i].ip,
				 INET_ADDRSTRLEN,
				 "%d.%d.%d.%d",
				 peers_str[0],
				 peers_str[1],
				 peers_str[2],
				 peers_str[3]);
		// ----------------------------------
		// Port number is calculated as
		// ----------------------------------
		// (peers_str[4] << 8)|(peers_str[5])
		// ----------------------------------
		// Shifting the 5th byte and OR it with the 6th byte
		// Suppose 5th byte is 001A and 6th byte is 00E1
		// Shifting 5th byte gives 1A00 and OR with 00E1 gives
		// 1AE1, which is the port number
		peers[total_peers - i].port = (peers_str[4] << 8) | peers_str[5];
		peers_str = peers_str + 6;
		--i;
	}
	DICT_DESTROY(dict);
	DESTROY(orig_resp);

	// Remove ourselves from the list of peers
	for (i = 0; i < total_peers; i++) {
		if (strcmp(peers[i].ip, "127.0.0.1") == 0 && peers[i].port == 6887) {
			printf("Removing ourselves from the list of peers\n");
			while (i < total_peers - 1) {
				peers[i] = peers[i + 1];
				++i;
			}
			--total_peers;
			break;
		}
	}

	int sockets[total_peers]; // sockets for all peers returned by tracker
	int fdmax = 0;
	fd_set conn_master; // master set for connecting
	FD_ZERO(&conn_master);
	for (i = 0; i < total_peers; i++) {
		sockets[i] = socket(PF_INET, SOCK_STREAM, 0);
		if (sockets[i] < 0) {
			switch (errno) {
				case EPROTONOSUPPORT: {
					printf("Protocol not supported\n");
					break;
				}
				case EACCES: {
					printf("Permisson to create socket denied\n");
					break;
				}
				default: {
					printf("Error creating socket: %s\n", strerror(errno));
					break;
				}
			}
			fclose(fp);
			return 1;
		}
		struct sockaddr_in addr;
		memset(addr.sin_zero, 0, sizeof(addr.sin_zero));
		inet_pton(AF_INET, peers[i].ip, &addr.sin_addr);
		addr.sin_family = AF_INET;
		addr.sin_port = htons(peers[i].port);

		int sock_flags_before;
		if ((sock_flags_before = fcntl(sockets[i], F_GETFL, 0)) < 0) {
			printf("Failed to GET flags (fcntl)\n");
			close(sockets[i]);
			continue;
		}

		if (fcntl(sockets[i], F_SETFL, sock_flags_before | O_NONBLOCK) < 0) {
			printf("Failed to SET flags (fcntl)\n");
			close(sockets[i]);
			continue;
		}

		if (sockets[i] > fdmax) {
			fdmax = sockets[i];
		}

		int res = connect(sockets[i], (struct sockaddr*)&addr, sizeof(addr));
		if (res == 0) {
			printf("Connected to peer %s\n", peers[i].ip);
			continue;
		} else if (res < 0 && errno != EINPROGRESS) {
			printf("Error while connecting to peer %s: %s\n",
				   peers[i].ip,
				   strerror(errno));
			continue;
		}

		FD_SET(sockets[i], &conn_master);
	}

	printf("Connecting to peers\n");

	fd_set comm_master; // master set for communicating and downloading
	FD_ZERO(&comm_master);

	// Writing data to peers
	int conn_peers = 0;
	int left_peers = total_peers;
	while (left_peers > 0 && conn_peers < HANDLECOUNT) {
		struct timeval tv;
		tv.tv_sec = TIMEOUT;
		tv.tv_usec = 0;
		// Ready file desriptors copied from conn_master every loop
		fd_set ready_fds;
		FD_ZERO(&ready_fds);
		ready_fds = conn_master;
		int res = select(fdmax + 1, NULL, &ready_fds, NULL, &tv);
		if (res == -1) {
			verprintf(
			  verbose, "[E] Error on select() (hndshk): %s\n", strerror(errno));
			close_peer_socks(sockets, total_peers);
			fclose(fp);
			return 1;
		} else if (res) {
			for (int i = 0; i < total_peers && conn_peers < HANDLECOUNT; i++) {
				int curr_sock = sockets[i];
				if (curr_sock == -1) {
					continue;
				}
				if (FD_ISSET(curr_sock, &ready_fds)) {
					socklen_t len = sizeof res;
					getsockopt(curr_sock, SOL_SOCKET, SO_ERROR, &res, &len);
					if (res == 0) { // Can write
						verprintf(
						  verbose, "[c] Connected to peer %s\n", peers[i].ip);

						conn_socks[conn_peers] = curr_sock;
						FD_CLR(curr_sock, &conn_master);
						FD_SET(curr_sock, &comm_master);
						++conn_peers;

						res = send_all(curr_sock, hndshk, &hndshk_len);
						if (res < 0) {
							verprintf(verbose,
									  "[e] Could not send data to peer %s\n",
									  peers[i].ip);
						} else {
							verprintf(verbose,
									  "[h] Sent handshake to peer %s\n",
									  peers[i].ip);
						}
					} else { // Error
						verprintf(verbose,
								  "[e] Error on peer %s:%d: %s (whndshk)\n",
								  peers[i].ip, peers[i].port,
								  strerror(res));
						FD_CLR(curr_sock, &conn_master);
					}
				}
			}
		} else {
			verprintf(verbose, "[!] Timeout for connecting peers\n");
			break;
		}
	}
	if (left_peers == 0) {
		printf("No peers connected\n");
		close_peer_socks(sockets, total_peers);
		fclose(fp);
		return 1;
	}

	verprintf(verbose, "[!] Connected to %d peers\n", conn_peers);

	peer_status stats[conn_peers];
	for (int i = 0; i < conn_peers; i++) {
		stats[i].mssg_len = 0;
		stats[i].recv_mssg_len = 0;
		stats[i].curr_step = STEP_HANDSHAKE; // Start with reading handshake
		stats[i].choked = 1;
		stats[i].has_pcs = 0;
		stats[i].interested = 0;
		stats[i].bitfield = NULL;
		stats[i].mssg = NULL;
		stats[i].curr_reqs = 0; // Number of ongoing requests
		stats[i].curr_pc_idx = -1;
		stats[i].curr_blck_off = -1;
		if (conn_socks[i] != -1) {
			struct sockaddr_in addr;
			socklen_t addrlen = sizeof addr;
			getpeername(conn_socks[i], (struct sockaddr*)&addr, &addrlen);
			inet_ntop(AF_INET, &addr.sin_addr, stats[i].ip, INET_ADDRSTRLEN);
		}
	}

	printf("Starting download\n");

	left_peers = conn_peers;
	// Ready file desriptors copied from comm_master set every loop
	fd_set ready_fds;
	while (left_peers > 0 && pcs_dwnlded < num_pcs) {
		int res;
		struct timeval tv = { .tv_sec = 0, .tv_usec = COMMTIMEOUT };
		FD_ZERO(&ready_fds);
		ready_fds = comm_master;
		res = select(fdmax + 1, &ready_fds, NULL, NULL, &tv);
		if (res == -1) {
			verprintf(
			  verbose, "[E] Error on select() (read): %s\n", strerror(errno));
			cleanup(
			  stats, conn_peers, cl_pcs, num_pcs, sockets, total_peers, fp);
			return 1;
		} else if (res) {
			for (int i = 0; i < conn_peers; i++) {
				int curr_sock = conn_socks[i];
				if (curr_sock == -1) {
					FD_CLR(curr_sock, &comm_master);
					continue;
				}
				if (FD_ISSET(curr_sock, &ready_fds)) {
					char* curr_ip = stats[i].ip;
					int curr_pc_idx = stats[i].curr_pc_idx;
					// ===================== HANDSHAKE =======================
					if (stats[i].curr_step == STEP_HANDSHAKE) {
						unsigned char peer_hndshk[hndshk_len];
						res = recv(
						  curr_sock, peer_hndshk, hndshk_len, MSG_NOSIGNAL);
						if (res <= 0) {
							if (res == 0) {
								verprintf(
								  verbose, "[e] Peer %s:%d hung up\n", curr_ip, peers[i].port);
							} else {
								verprintf(
								  verbose,
								  "[e] Error on peer %s: %s (rhndshk)\n",
								  curr_ip,
								  strerror(errno));
							}
							conn_socks[i] = -1;
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							continue;
						} else {
							// res is the length of peer_hndshk that was read
							// as returned by recv()
							if (valid_hndshk(hndshk, peer_hndshk, res)) {
								verprintf(verbose,
										  "[v] Got handshake from peer %s\n",
										  curr_ip);
								reset_peer_step(&stats[i]);
								stats[i].curr_step = STEP_READMSG;
								continue;
							} else {
								verprintf(verbose,
										  "[e] BAD handshake from peer %s:%d\n",
										  curr_ip, peers[i].port);
								FD_CLR(curr_sock, &comm_master);
								--left_peers;
								continue;
							}
						}
					}
					// =======================================================

					// =================== MESSAGE LENGTH ====================
					if (stats[i].curr_step == STEP_READMSG) {
						// Tried recv() on peer but got no response
						if (stats[i].mssg_len > 0 &&
							stats[i].recv_mssg_len == 0) {
							verprintf(
							  verbose,
							  "[e] Peer %s not responding. Disconnecting\n",
							  curr_ip);
							if (curr_pc_idx >= 0) {
								clear_dwnlds(&cl_pcs[curr_pc_idx], num_blcks);
								cl_pcs[curr_pc_idx].status = NONE;
							}
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							DESTROY(stats[i].mssg);
							continue;
						}
						if (stats[i].mssg_len == 0) {
							stats[i].mssg_len = 4;
							stats[i].recv_mssg_len = 0;
							DESTROY(stats[i].mssg);
							stats[i].mssg = malloc(4);
						}
						if (mssg_received(stats[i])) {
							stats[i].mssg_len = int_from_bytes(stats[i].mssg);
							if (stats[i].mssg_len == 0) {
								verprintf(verbose,
										  "[k] Peer %s sent keep-alive\n",
										  curr_ip);
								DESTROY(stats[i].mssg);
								continue;
							}
							stats[i].curr_step = STEP_READID;
							DESTROY(stats[i].mssg);
							continue;
						}
						int len = stats[i].mssg_len - stats[i].recv_mssg_len;
						res = recv(curr_sock,
								   stats[i].mssg + stats[i].recv_mssg_len,
								   len,
								   MSG_NOSIGNAL);
						if (res <= 0 && err_is_ignorable()) {
							continue;
						}
						if (res <= 0) {
							verprintf(
							  verbose,
							  "[e] Could not read length from peer %s: %s\n",
							  curr_ip,
							  strerror(errno));
							if (curr_pc_idx >= 0) {
								clear_dwnlds(&cl_pcs[curr_pc_idx], num_blcks);
								cl_pcs[curr_pc_idx].status = NONE;
							}
							DESTROY(stats[i].mssg);
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							continue;
						}
						stats[i].recv_mssg_len += res;
						if (mssg_received(stats[i])) {
							stats[i].mssg_len = int_from_bytes(stats[i].mssg);
							if (stats[i].mssg_len == 0) {
								verprintf(verbose,
										  "[k] Peer %s sent keep-alive\n",
										  curr_ip);
								continue;
							}
							stats[i].curr_step = STEP_READID;
							DESTROY(stats[i].mssg);
							continue;
						}
						continue;
					}
					// =======================================================

					// ========================= ID ==========================
					if (stats[i].curr_step == STEP_READID) {
						DESTROY(stats[i].mssg);
						unsigned char id;
						res = recv(curr_sock, &id, 1, MSG_NOSIGNAL);
						if (res <= 0) {
							verprintf(
							  verbose,
							  "[e] Could not read id from peer %s: %s\n",
							  curr_ip,
							  strerror(errno));
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							if (curr_pc_idx >= 0) {
								clear_dwnlds(&cl_pcs[curr_pc_idx], num_blcks);
								cl_pcs[curr_pc_idx].status = NONE;
							}
							continue;
						}
						stats[i].mssg_len -= 1;     // Read ID
						stats[i].recv_mssg_len = 0; // Resetting to 0
						switch (id) {
							case UNCHOKE: {
								stats[i].choked = 0;
								verprintf(verbose,
										  "[u] Peer %s unchoked us\n",
										  curr_ip);
								stats[i].mssg_len = 0;
								stats[i].recv_mssg_len = 0;
								if (!stats[i].has_pcs) {
									FD_CLR(curr_sock, &comm_master);
									--left_peers;
								}
								continue;
							}
							case BITFIELD: {
								stats[i].curr_step = STEP_BITFIELD;
								continue;
							}
							case CHOKE: {
								verprintf(
								  verbose, "[o] Peer %s choked us\n", curr_ip);
								if (stats[i].bitfield != NULL) {
									stats[i].has_pcs = 1;
								}
								if (!stats[i].has_pcs) {
									FD_CLR(curr_sock, &comm_master);
									--left_peers;
									continue;
								}
								stats[i].choked = 1;
								stats[i].interested = 0;
								if (curr_pc_idx >= 0) {
									clear_dwnlds(&cl_pcs[curr_pc_idx],
												 num_blcks);
									cl_pcs[curr_pc_idx].status = NONE;
								}
								continue;
							}
							case HAVE: {
								if (stats[i].bitfield == NULL) {
									stats[i].bitfield = calloc(
									  cl_bitf_len, sizeof(unsigned char));
									if (stats[i].bitfield == NULL) {
										verprintf(verbose,
												  "[e] Could not allocate "
												  "bitfield for peer %s\n",
												  curr_ip);
									}
								}
								stats[i].curr_step = STEP_HAVE;
								continue;
							}
							case PIECE: {
								stats[i].recv_mssg_len = 0;
								stats[i].curr_step = STEP_DOWNLOAD;
								continue;
							}
							case INTERESTED: {
								verprintf(
								  verbose,
								  "[?] Got INTERESTED message from peer %s\n",
								  curr_ip);
							}
							// fall through
							case NOT_INTERESTED: {
								verprintf(verbose,
										  "[?] Got NOT INTERESTED message "
										  "from peer %s\n",
										  curr_ip);
							}
							// fall through
							case REQUEST: {
								verprintf(
								  verbose,
								  "[?] Got REQUEST message from peer %s\n",
								  curr_ip);
							}
							// fall through
							case CANCEL: {
								verprintf(
								  verbose,
								  "[?] Got CANCEL message from peer %s\n",
								  curr_ip);
							}
							// fall through
							default: {
								FD_CLR(curr_sock, &comm_master);
								--left_peers;
								continue;
							}
						}
					}
					// =======================================================

					// ====================== BITFIELD =======================
					if (stats[i].curr_step == STEP_BITFIELD) {
						if (stats[i].mssg_len != cl_bitf_len) {
							verprintf(verbose,
									  "[e] Peer %s sent bitfield of invalid "
									  "length %d\n",
									  curr_ip,
									  stats[i].mssg_len);
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							if (curr_pc_idx >= 0) {
								clear_dwnlds(&cl_pcs[curr_pc_idx], num_blcks);
								cl_pcs[curr_pc_idx].status = NONE;
							}
							continue;
						}
						if (mssg_received(stats[i])) {
							verprintf(verbose,
									  "[b] Read bitfield (%d) from peer %s\n",
									  stats[i].recv_mssg_len,
									  curr_ip);
							stats[i].mssg_len = 0;
							stats[i].recv_mssg_len = 0;
							stats[i].has_pcs = 1;
							continue;
						}
						if (stats[i].bitfield == NULL) {
							stats[i].bitfield = malloc(stats[i].mssg_len);
							if (stats[i].bitfield == NULL) {
								verprintf(verbose,
										  "[x] Could not allocate bitfield "
										  "for peer %s\n",
										  curr_ip);
								FD_CLR(curr_sock, &comm_master);
								--left_peers;
								continue;
							}
						}
						int len = stats[i].mssg_len - stats[i].recv_mssg_len;
						if (len > cl_bitf_len) {
							printf("bitf");
							len = 0;
						}
						res = recv(curr_sock,
								   stats[i].bitfield + stats[i].recv_mssg_len,
								   len,
								   MSG_NOSIGNAL);
						if (res <= 0) {
							verprintf(
							  verbose,
							  "[e] Could not read bitfield from peer %s: %s\n",
							  curr_ip,
							  strerror(errno));
							DESTROY(stats[i].bitfield);
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							continue;
						}
						stats[i].recv_mssg_len += res;
						if (mssg_received(stats[i])) {
							verprintf(verbose,
									  "[b] Read bitfield (%d) from peer %s\n",
									  stats[i].recv_mssg_len,
									  curr_ip);
							stats[i].mssg_len = 0;
							stats[i].recv_mssg_len = 0;
							stats[i].has_pcs = 1;
							continue;
						}
						continue;
					}
					// =======================================================

					// ======================== HAVE =========================
					if (stats[i].curr_step == STEP_HAVE) {
						int have_len = stats[i].mssg_len;
						if (have_len != 4) {
							verprintf(
							  verbose,
							  "[e] Peer %s sent HAVE of invalid length %d\n",
							  curr_ip,
							  have_len);
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							continue;
						}
						unsigned char index[have_len];
						uint32_t piece_index = -1;
						res = recv(curr_sock, index, have_len, MSG_NOSIGNAL);
						if (res < 4) {
							verprintf(verbose,
									  "[e] Could not read HAVE from peer %s\n",
									  curr_ip);
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							continue;
						} else {
							piece_index = int_from_bytes(index);
							set_piece(stats[i].bitfield, piece_index);
							if (has_piece(stats[i].bitfield, piece_index)) {
								verprintf(verbose,
										  "[v] Peer %s HAVE piece %d\n",
										  curr_ip,
										  piece_index);
							} else {
								verprintf(
								  verbose,
								  "[e] Could not set HAVE for peer %s\n",
								  curr_ip);
							}
						}
						reset_peer_step(&stats[i]);
						stats[i].has_pcs = 1;
						continue;
					}
					// =======================================================

					// ================== DOWNLOAD BLOCKS ====================
					if (stats[i].curr_step == STEP_DOWNLOAD) {
						if (mssg_received(stats[i])) {
							int blck_idx = stats[i].curr_blck_off / BLOCKLEN;
							block* curr_blocks = cl_pcs[curr_pc_idx].blocks;
							curr_blocks[blck_idx].status = DOWNLOADED;
							verprintf(verbose,
									  "[b] Read piece %d and block %d (%d) "
									  "from peer %s\n",
									  curr_pc_idx,
									  blck_idx,
									  stats[i].recv_mssg_len,
									  curr_ip);

							if (cl_pcs[curr_pc_idx].data != NULL) {
								int blck_off = stats[i].curr_blck_off;
								memcpy(cl_pcs[curr_pc_idx].data + blck_off,
									   stats[i].mssg,
									   stats[i].recv_mssg_len);
							}

							DESTROY(stats[i].mssg);

							res = chck_pc_complete(cl_pcs,
												   &stats[i].curr_pc_idx,
												   &pcs_dwnlded,
												   num_blcks,
												   num_pcs,
												   left_peers,
												   fp);
							if (res == -1) {
								cleanup(stats,
										conn_peers,
										cl_pcs,
										num_pcs,
										sockets,
										total_peers,
										fp);
								return 1;
							}
							if (res == -2) {
								printf("[S] SHA1 for piece #%d from peer %s "
									   "did not match\n",
									   curr_pc_idx,
									   curr_ip);
								printf(
								  "[M] Disconnecting from malicious peer %s\n",
								  curr_ip);
								FD_CLR(curr_sock, &comm_master);
								--left_peers;
								continue;
							}

							stats[i].curr_blck_off = -1;
							reset_peer_step(&stats[i]);
							--stats[i].curr_reqs;
							break;
						}
						if (stats[i].recv_mssg_len == 0 &&
							stats[i].curr_blck_off < 0) {
							unsigned char piece_index_buff[4];
							unsigned char block_offset_buff[4];
							res = recv(
							  curr_sock, piece_index_buff, 4, MSG_NOSIGNAL);
							if (res <= 0 && err_is_ignorable()) {
								continue;
							}
							if (res < 4) {
								verprintf(verbose,
										  "[e] Could not read piece index "
										  "from peer %s: %s\n",
										  curr_ip,
										  strerror(errno));
								if (curr_pc_idx >= 0) {
									clear_dwnlds(&cl_pcs[curr_pc_idx],
												 num_blcks);
									cl_pcs[curr_pc_idx].status = NONE;
								}
								FD_CLR(curr_sock, &comm_master);
								--left_peers;
								DESTROY(stats[i].mssg);
								continue;
							}
							int piece_index = int_from_bytes(piece_index_buff);
							// If got a wrong piece index reset the piece this
							// peer was downloading
							if (piece_index != curr_pc_idx) {
								verprintf(verbose,
										  "[e] Wrong piece index %d (req: %d) "
										  "on peer %s\n",
										  piece_index,
										  curr_pc_idx,
										  curr_ip);
								if (curr_pc_idx >= 0) {
									block* curr_blocks =
									  cl_pcs[curr_pc_idx].blocks;
									for (int j = 0; j < num_blcks; j++) {
										curr_blocks[j].status = NONE;
									}
									cl_pcs[curr_pc_idx].status = NONE;
								}
								DESTROY(stats[i].mssg);
								FD_CLR(curr_sock, &comm_master);
								--left_peers;
								continue;
							}
							res = recv(
							  curr_sock, block_offset_buff, 4, MSG_NOSIGNAL);
							if (res <= 0 && err_is_ignorable()) {
								continue;
							}
							if (res < 4) {
								verprintf(
								  verbose,
								  "[e] Could not read block offset from peer "
								  "%s: %s (Piece %d, Block %lld)\n",
								  curr_ip,
								  strerror(errno),
								  curr_pc_idx,
								  stats[i].curr_blck_off);
								if (curr_pc_idx >= 0) {
									clear_dwnlds(&cl_pcs[curr_pc_idx],
												 num_blcks);
									cl_pcs[curr_pc_idx].status = NONE;
								}
								FD_CLR(curr_sock, &comm_master);
								--left_peers;
								DESTROY(stats[i].mssg);
								continue;
							}
							stats[i].curr_blck_off =
							  int_from_bytes(block_offset_buff);
							stats[i].mssg_len -= 8; // Read 8 bytes already
							DESTROY(stats[i].mssg);
							stats[i].mssg = malloc(stats[i].mssg_len);
							if (stats[i].mssg == NULL) {
								verprintf(
								  verbose,
								  "[x] Could not allocate block for peer %s\n",
								  curr_ip);
								FD_CLR(curr_sock, &comm_master);
								--left_peers;
								continue;
							}
						}
						int len = stats[i].mssg_len - stats[i].recv_mssg_len;
						res = recv(curr_sock,
								   stats[i].mssg + stats[i].recv_mssg_len,
								   len,
								   MSG_NOSIGNAL);
						if (res <= 0 && err_is_ignorable()) {
							continue;
						}
						if (res <= 0) {
							verprintf(
							  verbose,
							  "[e] Could not read block from peer %s: %s\n",
							  curr_ip,
							  strerror(errno));
							int blck_idx = stats[i].curr_blck_off / BLOCKLEN;
							block* curr_blocks = cl_pcs[curr_pc_idx].blocks;
							curr_blocks[blck_idx].status = NONE;
							cl_pcs[curr_pc_idx].status = NONE;
							FD_CLR(curr_sock, &comm_master);
							--left_peers;
							continue;
						}
						stats[i].recv_mssg_len += res;
						if (mssg_received(stats[i])) {
							int blck_idx = stats[i].curr_blck_off / BLOCKLEN;
							block* curr_blocks = cl_pcs[curr_pc_idx].blocks;
							curr_blocks[blck_idx].status = DOWNLOADED;
							verprintf(verbose,
									  "[b] Read piece %d and block %d (%d) "
									  "from peer %s\n",
									  curr_pc_idx,
									  blck_idx,
									  stats[i].recv_mssg_len,
									  curr_ip);

							if (cl_pcs[curr_pc_idx].data != NULL) {
								int blck_off = stats[i].curr_blck_off;
								memcpy(cl_pcs[curr_pc_idx].data + blck_off,
									   stats[i].mssg,
									   stats[i].recv_mssg_len);
							}

							DESTROY(stats[i].mssg);

							res = chck_pc_complete(cl_pcs,
												   &stats[i].curr_pc_idx,
												   &pcs_dwnlded,
												   num_blcks,
												   num_pcs,
												   left_peers,
												   fp);
							if (res == -1) {
								cleanup(stats,
										conn_peers,
										cl_pcs,
										num_pcs,
										sockets,
										total_peers,
										fp);
								return 1;
							}
							if (res == -2) {
								printf("[S] SHA1 for piece #%d from peer %s "
									   "did not match\n",
									   curr_pc_idx,
									   curr_ip);
								printf("[M] Disconnecting from peer %s\n",
									   curr_ip);
								FD_CLR(curr_sock, &comm_master);
								--left_peers;
								continue;
							}

							stats[i].curr_blck_off = -1;
							reset_peer_step(&stats[i]);
							--stats[i].curr_reqs;
							break;
						}
					}
					// =======================================================
				}
			}
		}
		if (pcs_dwnlded == num_pcs) {
			break;
		}
		for (int i = 0; i < conn_peers; i++) {
			int curr_sock = conn_socks[i];
			if (curr_sock == -1) {
				FD_CLR(curr_sock, &comm_master);
				continue;
			}
			char* curr_ip = stats[i].ip;
			// ======================= SEND INTERESTED =======================
			if (!stats[i].interested && stats[i].has_pcs) {
				int intrstd_len = 5;
				// 4 bytes for length and 1 for id
				unsigned char intrstd[5];
				// 1 is length in interested message
				int_to_bytes(&intrstd[0], 1);
				intrstd[4] = INTERESTED;
				res = send_all(curr_sock, intrstd, &intrstd_len);
				if (res < 0) {
					verprintf(verbose,
							  "[e] Could not send data to peer %s (intrstd)\n",
							  curr_ip);
					FD_CLR(curr_sock, &comm_master);
					--left_peers;
				} else {
					verprintf(verbose,
							  "[i] Sent interested message to peer %s\n",
							  curr_ip);
					reset_peer_step(&stats[i]);
					stats[i].interested = 1;
				}
			}
			// ===============================================================

			// ================== UNCHOKED AND CAN REQUEST ===================
			if (!stats[i].choked && stats[i].has_pcs &&
				stats[i].curr_reqs == 0) {
				if (stats[i].curr_pc_idx < 0) {
					int pc_idx = stats[i].curr_pc_idx;
					int found = 0; // If an available piece is found
					for (int j = 0; j < MAX_RETRY; j++) {
						pc_idx = rand() % num_pcs;
						if (cl_pcs[pc_idx].status == NONE &&
							has_piece(stats[i].bitfield, pc_idx)) {
							found = 1;
							break;
						}
					}
					if (!found) {
						for (int j = 0; j < num_pcs; j++) {
							pc_idx = j;
							if (cl_pcs[pc_idx].status == NONE &&
								has_piece(stats[i].bitfield, pc_idx)) {
								found = 1;
								break;
							}
						}
					}
					// ---------------------- ENDGAME ------------------------
					if (!found) {
						for (int j = 0; j < num_pcs; j++) {
							pc_idx = j;
							if (cl_pcs[pc_idx].status == DOWNLOADING &&
								has_piece(stats[i].bitfield, pc_idx)) {
								found = 1;
								break;
							}
						}
					}
					// -------------------------------------------------------
					stats[i].curr_pc_idx = pc_idx;
					if(stats[i].curr_pc_idx < 0) {
						verprintf(verbose,
								  "[e] Peer %s has no pieces to download\n",
								  curr_ip);
						FD_CLR(curr_sock, &comm_master);
						--left_peers;
						continue;
					}
					cl_pcs[stats[i].curr_pc_idx].status = DOWNLOADING;
				}
				block* curr_blocks = cl_pcs[stats[i].curr_pc_idx].blocks;
				int num_reqs = 0;
				int req_indices[SIMULBLOCKS];
				// Indices of blocks which we can request
				for (int j = 0; j < num_blcks && num_reqs < SIMULBLOCKS; j++) {
					if (curr_blocks[j].status == NONE) {
						req_indices[num_reqs] = j;
						++num_reqs;
						curr_blocks[j].status = DOWNLOADING;
					}
				}
				// ------------------------- ENDGAME -------------------------
				if (num_reqs == 0) {
					for (int j = 0; j < num_blcks && num_reqs < SIMULBLOCKS;
						 j++) {
						if (curr_blocks[j].status == DOWNLOADING) {
							req_indices[num_reqs] = j;
							++num_reqs;
							curr_blocks[j].status = DOWNLOADING;
						}
					}
				}
				// -----------------------------------------------------------
				if (num_reqs == 0) {
					cl_pcs[stats[i].curr_pc_idx].status = DOWNLOADED;
					++pcs_dwnlded;
					break;
				}
				stats[i].curr_reqs += num_reqs;
				// 4 bytes for length and 13 for actual request
				int req_len = num_reqs * 17;
				unsigned char request[req_len];
				for (int j = 0; j < num_reqs; j++) {
					int offset = j * (17);
					int index = req_indices[j];
					block block = curr_blocks[index];
					int pc_idx = stats[i].curr_pc_idx;
					int begin = block.offset;
					int len = block.length;
					// 13 is length in request message
					int_to_bytes(&request[offset], 13);
					request[offset + 4] = REQUEST;
					int_to_bytes(&request[offset + 5], pc_idx);
					int_to_bytes(&request[offset + 9], begin);
					int_to_bytes(&request[offset + 13], len);
				}
				res = send_all(curr_sock, request, &req_len);
				if (res < 0 || req_len != num_reqs * 17) {
					verprintf(verbose,
							  "[e] Could not send request to peer %s\n",
							  curr_ip);
					if (stats[i].curr_pc_idx >= 0) {
						clear_dwnlds(&cl_pcs[stats[i].curr_pc_idx], num_blcks);
						cl_pcs[stats[i].curr_pc_idx].status = NONE;
					}
					FD_CLR(curr_sock, &comm_master);
					--left_peers;
				} else {
					verprintf(
					  verbose, "[r] Sent request to peer %s\n", curr_ip);
					if (cl_pcs[stats[i].curr_pc_idx].data == NULL) {
						cl_pcs[stats[i].curr_pc_idx].data =
						  malloc(cl_pcs[stats[i].curr_pc_idx].length);
					}
					stats[i].curr_blck_off = -1;
					reset_peer_step(&stats[i]);
				}
			}
			// ===============================================================
		}
	}
	if (left_peers == 0 && pcs_dwnlded != num_pcs) {
		printf("[e] All peers disconnected. Could not download file\n");
		return -1;
	}
	if (pcs_dwnlded == num_pcs) {
		printf("[!] Download complete\n");
	}

	cleanup(stats, conn_peers, cl_pcs, num_pcs, sockets, total_peers, fp);
	return 0;
}