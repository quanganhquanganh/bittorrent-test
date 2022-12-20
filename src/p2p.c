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
	char *announce_url = "udp://tracker.opentrackr.org:1337/announce";
    node = str_create((unsigned char*)"udp://tracker.opentrackr.org:1337/announce", strlen(announce_url));
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
    unsigned char *pieces = malloc((int)ceil((double)size / PIECELEN) * SHA_DIGEST_LENGTH);
    unsigned char *piece = malloc(PIECELEN);
    unsigned char *hash = malloc(SHA_DIGEST_LENGTH);
    int length = PIECELEN;
	for(size_t i = 0; i < ((double)size / PIECELEN); i++) {
        fread(piece, 1, PIECELEN, fp);
		// Check if we are at the end of the file
		if(i == (size_t)ceil((double)size / PIECELEN) - 1) {
			length = size % PIECELEN == 0 ? PIECELEN : size % PIECELEN;
		}
		SHA1(piece, length, hash);
		memcpy(pieces + i * SHA_DIGEST_LENGTH, hash, SHA_DIGEST_LENGTH);
    }
    node = str_create(pieces, (int)ceil((double)size / PIECELEN) * SHA_DIGEST_LENGTH);
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

int
p2p_start(const char* file, const char* name)
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
	if (name == NULL) {
		val = dict_get(info, (unsigned char*)"name", &type);
		if (val == NULL || type != BE_STR) {
			printf("No name found\n");
			DICT_DESTROY(dict);
			DESTROY(peer_id);
			return 1;
		}
		string = (be_string*)val;
		name = (char*)string->str;
	}
	fp = fopen(name, "w+");
	if (fp == NULL) {
		printf("Could not open file: %s\n", strerror(errno));
		DICT_DESTROY(dict);
		DESTROY(peer_id);
		return 1;
	}

	// -----------------------------------------------------------------------
	num_pcs = length / piece_len + (length % piece_len != 0);
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

	printf("Tracker found: %s\n", annurl);

	snprintf(query,
			 BUFFLEN + 1,
			 "%s?info_hash=%s&peer_id=%s&port=6889&uploaded=0&downloaded=0&"
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
			printf("[E] Error on select() (hndshk): %s\n", strerror(errno));
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
						printf("[c] Connected to peer %s\n", peers[i].ip);

						conn_socks[conn_peers] = curr_sock;
						FD_CLR(curr_sock, &conn_master);
						FD_SET(curr_sock, &comm_master);
						++conn_peers;

						res = send_all(curr_sock, hndshk, &hndshk_len);
						if (res < 0) {
							printf("[e] Could not send data to peer %s\n",
									  peers[i].ip);
						} else {
							printf("[h] Sent handshake to peer %s\n",
									  peers[i].ip);
						}
					} else { // Error
						printf("[e] Error on peer %s: %s (whndshk)\n",
								  peers[i].ip,
								  strerror(res));
						FD_CLR(curr_sock, &conn_master);
					}
				}
			}
		} else {
			printf("[!] Timeout for connecting peers\n");
			break;
		}
	}
	if (left_peers == 0) {
		printf("No peers connected\n");
		close_peer_socks(sockets, total_peers);
		fclose(fp);
		return 1;
	}

	printf("[!] Connected to %d peers\n", conn_peers);
	close_peer_socks(sockets, total_peers);
	fclose(fp);
	return 0;
}

// int seed(int port, int num_pcs, int num_blcks, int blck_len,
// 		 char* file_name) {
// 	// ------------------------- INITIALIZATION -------------------------
// 	int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
// 	if (listen_sock < 0) {
// 		printf("[e] Could not create socket\n");
// 		return -1;
// 	}
// 	struct sockaddr_in serv_addr;
// 	serv_addr.sin_family = AF_INET;
// 	serv_addr.sin_addr.s_addr = INADDR_ANY;
// 	serv_addr.sin_port = htons(port);
// 	if (bind(listen_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) <
// 		0) {
// 		printf("[e] Could not bind socket\n");
// 		return -1;
// 	}
// 	if (listen(listen_sock, 5) < 0) {
// 		printf("[e] Could not listen on socket\n");
// 		return -1;
// 	}
// 	// ------------------------------------------------------------------

// 	// ------------------------- FILE HANDLING --------------------------
// 	FILE* fp = fopen(file_name, "rb");
// 	if (fp == NULL) {
// 		printf("[e] Could not open file %s\n", file_name);
// 		return -1;
// 	}
// 	fseek(fp, 0, SEEK_END);
// 	int file_len = ftell(fp);
// 	fseek(fp, 0, SEEK_SET);
// 	// ------------------------------------------------------------------

// 	// ------------------------- PEER HANDLING --------------------------
// 	int total_peers = 0;
// 	int* sockets = malloc(sizeof(int) * HANDLECOUNT);
// 	// ------------------------------------------------------------------

// 	// ------------------------- COMMUNICATION --------------------------
// 	fd_set comm_master;
// 	fd_set comm_read;
// 	FD_ZERO(&comm_master);
// 	FD_ZERO(&comm_read);
// 	FD_SET(listen_sock, &comm_master);
// 	int max_fd = listen_sock;
// 	// ------------------------------------------------------------------

// // 	// ------------------------- MAIN LOOP ------------------------------
// 	while (1) {
// 		comm_read = comm_master;
// 		int res = select(max_fd + 1, &comm_read, NULL, NULL, NULL);
// 		if (res < 0) {
// 			printf("[e] Could not select\n");
// 			return -1;
// 		}
// 		for (int i = 0; i <= max_fd; i++) {
// 			if (!FD_ISSET(i, &comm_read)) {
// 				continue;
// 			}
// 			if (i == listen_sock) {
// 				// ------------------------- ACCEPT -------------------------
// 				struct sockaddr_in cli_addr;
// 				socklen_t cli_len = sizeof(cli_addr);
// 				int new_sock = accept(listen_sock, (struct sockaddr*)&cli_addr,
// 									  &cli_len);
// 				if (new_sock < 0) {
// 					printf("[e] Could not accept connection\n");
// 					return -1;
// 				}
// 				FD_SET(new_sock, &comm_master);
// 				if (new_sock > max_fd) {
// 					max_fd = new_sock;
// 				}
// 				// ----------------------------------------------------------
// 			} else {
// 				// ------------------------- RECEIVE ------------------------
// 				int curr_sock = i;
// 				char* curr_ip = get_ip(curr_sock);
// 				int curr_port = get_port(curr_sock);
// 				printf(verbose, "[r] Received message from peer %s\n",
						//   curr_ip);
				// char* msg = malloc(sizeof(char) * MSGLEN);
				// int msg_len = recv(curr_sock, msg, MSGLEN, 0);
				// if (msg_len < 0) {
				// 	printf("[e] Could not receive message\n");
				// 	return -1;
				// }
				// if (msg_len == 0) {
				// 	printf(verbose, "[r] Peer %s disconnected\n", curr_ip);
				// 	FD_CLR(curr_sock, &comm_master);
				// 	--total_peers;
				// } else {
				// 	// ------------------------- HANDSHAKE ------------------------
				// 	if (msg[0] == 'H') {
				// 		printf(verbose, "[r] Received handshake from peer %s\n",
				// 				  curr_ip);
				// 		// ------------------------- ACCEPT -------------------------
				// 		if (total_peers < HANDLECOUNT) {
				// 			printf(verbose, "[r] Accepted handshake from peer %s\n",
				// 					  curr_ip);
				// 			sockets[total_peers] = curr_sock;
				// 			++total_peers;
				// 			char* resp = malloc(sizeof(char) * MSGLEN);
				// 			resp[0] = 'A';
				// 			resp[1] = '\0';
				// 			int resp_len = send(curr_sock, resp, MSGLEN, 0);
				// 			if (resp_len < 0) {
				// 				printf("[e] Could not send response\n");
				// 				return -1;
				// 			}
				// 			free(resp);
				// 		}
				// 		// ----------------------------------------------------------
				// 		// ------------------------- REJECT -------------------------
				// 		else {
				// 			printf(verbose, "[r] Rejected handshake from peer %s\n",
				// 					  curr_ip);
				// 			char* resp = malloc(sizeof(char) * MSGLEN);
				// 			resp[0] = 'R';
				// 			resp[1] = '\0';
				// 			int resp_len = send(curr_sock, resp, MSGLEN, 0);
				// 			if (resp_len < 0) {
				// 				printf("[e] Could not send response\n");
				// 				return -1;
				// 			}
				// 			free(resp);
				// 		}
				// 		// ----------------------------------------------------------
				// 	}
				// }
				// free(msg);
				// // ----------------------------------------------------------
	// 		}
	// 	}
	// }
// 	// ------------------------------------------------------------------

	// ------------------------- CLEANUP -------------------------------
// 	free(sockets);
// 	fclose(fp);
// 	// ------------------------------------------------------------------

// 	return 0;
// }