#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

#include "CDetour.h"
#include <stdint.h>

#include <openssl/ssl.h>

#define SERVER_HOSTNAME "fesl.openspy.net"
#define SERVER_PORT 18301


SSL_CTX* g_ssl_ctx = NULL;

SSL* g_ssl = NULL;
BIO* g_read_bio;
BIO* g_write_bio;

typedef struct _SSLStateInfo {
	uint32_t unkptr_1;
	uint32_t unkptr_2;
	uint32_t send_buffer_cursor;
	uint32_t current_send_len;
	uint32_t unkptr_5;
	uint32_t recv_current_len;
	uint32_t recv_expected_len;
	uint32_t recv_buffer_cursor;
	uint8_t unk3[2232];
	uint8_t send_buffer[16384];
	uint8_t recv_buffer[16384];
} SSLStateInfo;

typedef struct _SOCKET_Handler {
	int (*unk_callback_1)(struct _SOCKET_Handler*);
	uint32_t resolved_address; //resolve_callback sets this
	uint32_t(*resolve_callback)(struct _SOCKET_Handler*);
	int (*unk_callback_4)(struct _SOCKET_Handler*);
	char resolve_name[64];
} SOCKETHandler;

typedef struct _FESLSOCKET {
	uint32_t unk[6];
	uint32_t socket;
} FESLSOCKET;

typedef struct _FESLCtx {
	struct _FESLSOCKET* fesl_socket;
	struct _SOCKET_Handler* socket_handler;
	uint32_t unk;
	uint8_t ssl_hostname[256];
	struct sockaddr_in resolved_address;
	uint32_t connection_state;
	uint32_t got_error;
	struct _SSLStateInfo* ssl_state;
} FESLCtx;

class IFESL {
public:
	virtual void unknownFunc1(char a2) = 0;
	virtual int setConnectionDetails(const char *hostname, int a2, int a3) = 0;
	virtual int buildFESLHostname(const char* a2, int a3, const char* a4, int a5, int a6) = 0;
	virtual int otherBuildFESLHostname(int a2, char a3) = 0;
};

class FESLImpl {
public:
	void unknownFunc1(char a2) {

	}
	int setConnectionDetails(const char* hostname, int a2, int a3) {
		return 0;
	}
	int buildFESLHostname(const char* a2, int a3, const char* a4, int a5, int a6) {
		IFESL* real_fesl = (IFESL*)this;
		return real_fesl->setConnectionDetails(SERVER_HOSTNAME, SERVER_PORT, a6);
	}
	int otherBuildFESLHostname(int a2, char a3) {
		return 0;
	}
};

void SSL_Flush(FESLCtx* ctx) {
	int ssl_write_sz = BIO_pending(g_write_bio);
	if (ssl_write_sz == 0) {
		return;
	}
	if (ssl_write_sz > 0) {
		BIO_read(g_write_bio, &ctx->ssl_state->send_buffer, ssl_write_sz);

		if (ssl_write_sz > sizeof(ctx->ssl_state->send_buffer)) {
			ssl_write_sz = sizeof(ctx->ssl_state->send_buffer);
		}

		int r = send(ctx->fesl_socket->socket, (const char*)&ctx->ssl_state->send_buffer, ssl_write_sz, 0);
		if (r < 0) {
			ctx->connection_state = 4099;
			ctx->got_error = 1;
			return;
		}
	}
}
void SSL_Read(FESLCtx* ctx) {
	int r = recv(ctx->fesl_socket->socket, (char*)&ctx->ssl_state->recv_buffer, sizeof(ctx->ssl_state->recv_buffer), 0);
	
	if (r < 0) {
		int wserr = WSAGetLastError();
		if (wserr != WSAEWOULDBLOCK) {
			ctx->connection_state = 4097;
			ctx->got_error = 1;
		}
	}
	else if (r > 0) {
		BIO_write(g_read_bio, (char*)&ctx->ssl_state->recv_buffer, r);
		if (!SSL_is_init_finished(g_ssl)) {
			SSL_Flush(ctx);
		}
	}
}

void SSL_LogicThread(FESLCtx* ctx) {
	int (*socket_query)(SOCKET, uint32_t, sockaddr*, size_t) = (int (*)(SOCKET, uint32_t, sockaddr*, size_t))0xAF86B0;
	if (ctx->connection_state == 1 && ctx->socket_handler->resolve_callback(ctx->socket_handler)) {
		if (ctx->socket_handler->resolved_address) {
			ctx->resolved_address.sin_addr.S_un.S_addr = htonl(ctx->socket_handler->resolved_address);
			ctx->connection_state = 2;
		}
		else {
			ctx->connection_state = 4097;
		}

		ctx->got_error = 0;
		ctx->socket_handler->unk_callback_4(ctx->socket_handler);
		ctx->socket_handler = NULL;
	}
	else if (ctx->connection_state == 2) { //do connect
		if (ctx->resolved_address.sin_port == htons(SERVER_PORT)) { //hack to fudge in the fesl hostname
			strcpy((char *)&ctx->ssl_hostname[0], SERVER_HOSTNAME);
		}
		int r = connect(ctx->fesl_socket->socket, (const sockaddr*)&ctx->resolved_address, sizeof(const sockaddr));
		if (r < 0) {
			int lastErr = WSAGetLastError();
			if (lastErr == WSAEWOULDBLOCK || lastErr == WSAEALREADY || lastErr == WSAEINVAL) {
				return;
			}
			else if (lastErr != WSAEISCONN) {
				ctx->connection_state = 4099;
				ctx->got_error = 1;
				return;
			}			
		}
		ctx->connection_state = 3;
	}
	else if (ctx->connection_state == 3) { //need to do connection
		int query = socket_query((SOCKET)ctx->fesl_socket, 'stat', 0, 0);
		bool got_error = query < 0;
		if (query > 0) {
			ctx->connection_state = ctx->ssl_state != NULL ? 4 : 31;
			ctx->got_error = 0;
		}
		if (got_error) {
			ctx->connection_state = 4098;
			ctx->got_error = 1;
		}
	}
	else if (ctx->connection_state == 4) { //init SSL connection
		SSL_clear(g_ssl);

		SSL_set_tlsext_host_name(g_ssl, ctx->ssl_hostname);
		SSL_set1_host(g_ssl, (const char *)ctx->ssl_hostname);

		SSL_set_connect_state(g_ssl);

		ctx->connection_state = 5;
		//SSL_connect(g_ssl);
	}
	else if (ctx->connection_state == 5) { //in handshake state

		int n = SSL_do_handshake(g_ssl);

		int err = SSL_get_error(g_ssl, n);
		if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
			SSL_Flush(ctx);
			SSL_Read(ctx);
		}
		else if (n == 1) {
			ctx->connection_state = 30;
		}
		else {
			ctx->connection_state = 4097;
			ctx->got_error = 1;
		}

	}
	else if (ctx->connection_state == 30) { //read SSL incoming data
		int recvbuf[256];
		while (true) {
			int r = recv(ctx->fesl_socket->socket, (char*)&recvbuf[0], sizeof(recvbuf), 0);
			if (r <= 0) {
				break;
			}
			BIO_write(g_read_bio, (char*)&recvbuf[0], r);
		}
		int read_len = sizeof(ctx->ssl_state->recv_buffer) - ctx->ssl_state->recv_buffer_cursor;
		while (true) {
			int sr = SSL_read(g_ssl, (void*)&ctx->ssl_state->recv_buffer[ctx->ssl_state->recv_expected_len], read_len);
			if (sr <= 0) {
				break;
			}
			ctx->ssl_state->recv_expected_len += sr;
		}
	}

	if (ctx->connection_state >= 4 && ctx->connection_state != 31) {
		SSL_Flush(ctx);
	}
	
}

int fesl_SSL_Send(FESLCtx* ctx, char* buf, int len) {
	int result = -1;
	if (len < 0) {
		len = strlen(buf);
	}
	if (ctx->connection_state == 30) {
		//show_dump((unsigned char*)buf, len, con_out);
		int r = SSL_write(g_ssl, buf, len);
		result = r;
		SSL_Flush(ctx);
	}
	else if (ctx->connection_state == 31) {
		result = send((SOCKET)ctx->fesl_socket->socket, buf, len, 0);
	}
	return result;
}

int fesl_SSL_recv(FESLCtx* ctx, char* buf, int len) {
	int result = 0;
	if (ctx->connection_state == 30) {
		SSL_LogicThread(ctx);
		if (ctx->ssl_state->recv_expected_len == 0) {
			return 0;
		}
		int read_len = ctx->ssl_state->recv_expected_len - ctx->ssl_state->recv_buffer_cursor;
		if (read_len > len) {
			read_len = len;
		}
		memcpy(buf, (const void*)&ctx->ssl_state->recv_buffer[ctx->ssl_state->recv_buffer_cursor], read_len);
		//show_dump((unsigned char*)buf, read_len, con_out);
		ctx->ssl_state->recv_buffer_cursor += read_len;
		if (ctx->ssl_state->recv_buffer_cursor >= ctx->ssl_state->recv_expected_len) {
			ctx->ssl_state->recv_buffer_cursor = 0;
			ctx->ssl_state->recv_expected_len = 0;
			ctx->ssl_state->recv_current_len = 0;
		}
		result = read_len;
		
	}
	else if (ctx->connection_state == 31) {
		result = recv((SOCKET)ctx->fesl_socket->socket, buf, len, 0);
		if (result < 0) {
			int lastErr = WSAGetLastError();
			if (lastErr == WSAEWOULDBLOCK || lastErr == WSAEALREADY || lastErr == WSAEINVAL) {
				return 0;
			}
		}

	}
	if (result > 0 && result < len)
		buf[result] = 0;

	return result;
}

void install_fesl_patches() {
	//AllocConsole();
	//con_out = fopen("CONOUT$", "wb");
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();


	g_ssl_ctx = SSL_CTX_new(TLS_method());
	SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_PEER, NULL); //call this to enable verification
	SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
	//SSL_CTX_set_max_proto_version(g_ssl_ctx, TLS1_3_VERSION);

	//setup CA store
	X509_STORE* store = X509_STORE_new();
	X509_STORE_set_default_paths(store); //load default openssl cas
	X509_STORE_load_store(store, "org.openssl.winstore://"); //load certs trusted by windows
	SSL_CTX_set_cert_store(g_ssl_ctx, store);

	//

	SSL_CTX_set_cipher_list(g_ssl_ctx, "ALL");
	SSL_CTX_set_options(g_ssl_ctx, SSL_OP_ALL);


	//creating SSL connection ctx in this way assumes the game will only ever establish one SSL connection at a time... but it saves us dealing with memory cleanup
	g_ssl = SSL_new(g_ssl_ctx);
	g_read_bio = BIO_new(BIO_s_mem());
	g_write_bio = BIO_new(BIO_s_mem());
	BIO_set_nbio(g_read_bio, 1);
	BIO_set_nbio(g_write_bio, 1);


	SSL_set_bio(g_ssl, g_read_bio, g_write_bio);


	DWORD old;

	void* feslResolveFuncAddr = (void*)0xC9CE30;
	auto ourFeslResolveAddr = &FESLImpl::buildFESLHostname;
	VirtualProtect(feslResolveFuncAddr, sizeof(void*), PAGE_EXECUTE_READWRITE, &old);
	WriteProcessMemory(GetCurrentProcess(), feslResolveFuncAddr, &ourFeslResolveAddr, sizeof(void*), NULL);
	VirtualProtect(feslResolveFuncAddr, sizeof(void*), old, &old);
	FlushInstructionCache(GetCurrentProcess(), feslResolveFuncAddr, sizeof(void*));

	//AF5200
	void* ssl_logic_calls[] = {
		(void*)0x00AF1784,
		(void*)0x00AF5641,
		(void*)0x00AF56AD,
		(void*)0x00AF9D76,
		(void*)0x00AF9E4F
	};

	CDetour detour;
	for (int i = 0; i < sizeof(ssl_logic_calls) / sizeof(void*); i++) {
		detour.Create((BYTE*)ssl_logic_calls[i], (const BYTE*)SSL_LogicThread, DETOUR_TYPE_CALL_FUNC, 5);
	}

	//AF55E0
	void* ssl_send_data_calls[] = {
		(void*)0xAF180B,
		(void*)0xAF9E73,
	};
	for (int i = 0; i < sizeof(ssl_send_data_calls) / sizeof(void*); i++) {
		detour.Create((BYTE*)ssl_send_data_calls[i], (const BYTE*)fesl_SSL_Send, DETOUR_TYPE_CALL_FUNC, 5);
	}

	//AF5680
	void* ssl_recv_data_calls[] = {
		(void*)0x00AF0EA5,
		(void*)0x00AF1878,
		(void*)0x00AF190B,
		(void*)0x00AF1A0A,
		(void*)0x00AF9EC9,
		(void*)0x00AF9F8E,
	};
	for (int i = 0; i < sizeof(ssl_recv_data_calls) / sizeof(void*); i++) {
		detour.Create((BYTE*)ssl_recv_data_calls[i], (const BYTE*)fesl_SSL_recv, DETOUR_TYPE_CALL_FUNC, 5);
	}

}