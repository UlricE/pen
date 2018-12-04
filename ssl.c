#include "config.h"

#ifdef HAVE_LIBSSL

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include "ssl.h"
#include "client.h"
#include "conn.h"
#include "pen.h"
#include "diag.h"
#include "memory.h"
#include "server.h"

char ssl_compat;
char require_peer_cert;
char ssl_protocol;
char *certfile;
char *keyfile;
char *cacert_dir;
char *cacert_file;
char *ssl_sni_path;
SSL_CTX *ssl_context = NULL;
long ssl_options;
char *ssl_ciphers;
int ssl_session_id_context = 1;
int ssl_client_renegotiation_interval = 3600;	/* one hour, effectively disabled */
unsigned char ocsp_resp_data[OCSP_RESP_MAX];
long ocsp_resp_len = 0;
char *ocsp_resp_file = NULL;

static int ssl_verify_cb(int ok, X509_STORE_CTX *ctx)
{
	char buffer[256];
	X509 *cert = X509_STORE_CTX_get_current_cert(ctx);

	X509_NAME_oneline(X509_get_issuer_name(cert), buffer, sizeof(buffer));
	if (ok) {
		char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
		DEBUG(1, "SSL: Certificate OK: issuer = '%s'", buffer);
		DEBUG(1, "Subject: %s", subj);
		OPENSSL_free(subj);
	} else {
		switch (X509_STORE_CTX_get_error(ctx)) {
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			DEBUG(1, "SSL: Cert error: CA not known: %s", buffer);
			break;
		case X509_V_ERR_CERT_NOT_YET_VALID:
			DEBUG(1, "SSL: Cert error: Cert not yet valid: %s",
				buffer);
			break;
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			DEBUG(1, "SSL: Cert error: illegal \'not before\' field: %s",
				buffer);
			break;
		case X509_V_ERR_CERT_HAS_EXPIRED:
			DEBUG(1, "SSL: Cert error: Cert expired: %s", buffer);
			break;
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			DEBUG(1, "SSL: Cert error: invalid \'not after\' field: %s",
				buffer);
			break;
		default:
			DEBUG(1, "SSL: Cert error: unknown error %d in %s",
				X509_STORE_CTX_get_error(ctx), buffer);
			break;
		}
	}
	return ok;
}

static RSA *ssl_temp_rsa_cb(SSL *ssl, int export, int keylength)
{
	static RSA *rsa = NULL;

	if (rsa == NULL) {
		RSA *rsa = RSA_new();
		BIGNUM *bn = BN_new();
		if (rsa == NULL ||
		    bn == NULL ||
		    !BN_set_word(bn, RSA_F4) ||
		    !RSA_generate_key_ex(rsa, 512, bn, NULL)) {
			BN_free(bn);
			RSA_free(rsa); rsa = NULL;
		}
	}
	return rsa;
}

static void ssl_info_cb(const SSL *ssl, int where, int ret)
{
#if defined SSL3_ST_SR_CLNT_HELLO_A || defined SSL23_ST_SR_CLNT_HELLO_A
	int st = SSL_get_state(ssl);
#endif
	const char *state = SSL_state_string_long(ssl);
	const char *type = SSL_alert_type_string_long(ret);
	const char *desc = SSL_alert_desc_string_long(ret);
	connection *conn = SSL_get_app_data(ssl);
	int renegotiating = 0;
	DEBUG(3, "ssl_info_cb(ssl=%p, where=%d, ret=%d)", ssl, where, ret);
	if (where & SSL_CB_LOOP) DEBUG(3, "\tSSL_CB_LOOP");
	if (where & SSL_CB_EXIT) DEBUG(3, "\tSSL_CB_EXIT");
	if (where & SSL_CB_READ) DEBUG(3, "\tSSL_CB_READ");
	if (where & SSL_CB_WRITE) DEBUG(3, "\tSSL_CB_WRITE");
	if (where & SSL_CB_ALERT) DEBUG(3, "\tSSL_CB_ALERT");
	if (where & SSL_CB_READ_ALERT) DEBUG(3, "\tSSL_CB_READ_ALERT");
	if (where & SSL_CB_WRITE_ALERT) DEBUG(3, "\tSSL_CB_WRITE_ALERT");
	if (where & SSL_CB_ACCEPT_LOOP) DEBUG(3, "\tSSL_CB_ACCEPT_LOOP");
	if (where & SSL_CB_ACCEPT_EXIT) DEBUG(3, "\tSSL_CB_ACCEPT_EXIT");
	if (where & SSL_CB_CONNECT_LOOP) DEBUG(3, "\tSSL_CB_CONNECT_LOOP");
	if (where & SSL_CB_CONNECT_EXIT) DEBUG(3, "\tSSL_CB_CONNECT_EXIT");
	if (where & SSL_CB_HANDSHAKE_START) DEBUG(3, "\tSSL_CB_HANDSHAKE_START");
	if (where & SSL_CB_HANDSHAKE_DONE) DEBUG(3, "\tSSL_CB_HANDSHAKE_DONE");
	DEBUG(3, "SSL state = %s", state);
	DEBUG(3, "Alert type = %s", type);
	DEBUG(3, "Alert description = %s", desc);
#ifdef SSL3_ST_SR_CLNT_HELLO_A
	if (st == SSL3_ST_SR_CLNT_HELLO_A) {
		DEBUG(3, "\tSSL3_ST_SR_CLNT_HELLO_A");
		renegotiating = 1;
	}
#endif
#ifdef SSL23_ST_SR_CLNT_HELLO_A
	if (st == SSL23_ST_SR_CLNT_HELLO_A) {
		DEBUG(3, "\tSSL23_ST_SR_CLNT_HELLO_A");
		renegotiating = 1;
	}
#endif
	if (conn == NULL) {
		debug("Whoops, no conn info");
	} else {
		DEBUG(3, "Connection in state %d from client %d to server %d",
			conn->state, conn->client, conn->server);
		if (renegotiating) {
			int reneg_time = now-conn->reneg;
			conn->reneg = now;
			DEBUG(3, "Client asks for renegotiation");
			DEBUG(3, "Last time was %d seconds ago", reneg_time);
			if (reneg_time < ssl_client_renegotiation_interval) {
				debug("That's more often than we care for");
				conn->state = CS_CLOSED;
			}
		}
	}
}

static struct sni {
	char *name;
	SSL_CTX *ssl_context;
	unsigned char ocsp_resp_data[OCSP_RESP_MAX];
	int ocsp_resp_len;
	time_t ocsp_resp_time;
	struct sni *next;
} *sni_list;

static SSL_CTX *ssl_create_context(char *keyfile, char *certfile,
		char *cacert_dir, char *cacert_file);

static struct sni *lookup_sni(const char *name)
{
	struct sni *s;
	for (s = sni_list; s; s = s->next)
		if (!strcmp(s->name, name)) break;

	if (s == NULL) {
		char keyfile[1024], certfile[1024], cacert_file[1024];
		s = pen_malloc(sizeof *s);
		s->name = pen_strdup(name);
		s->next = sni_list;
		sni_list = s;
		snprintf(keyfile, sizeof keyfile, "%s/%s.key", ssl_sni_path, name);
		snprintf(certfile, sizeof certfile, "%s/%s.crt", ssl_sni_path, name);
		snprintf(cacert_file, sizeof cacert_file, "%s/%s.ca", ssl_sni_path, name);
		s->ocsp_resp_len = 0;
		s->ocsp_resp_time = 0;	/* never */
		s->ssl_context = ssl_create_context(keyfile, certfile, NULL, cacert_file);
	}
	return s;
}

static long read_ocsp(const char *fn, unsigned char *data)
{
	int f = open(fn, O_RDONLY);
	long len = 0;
	DEBUG(3, "Read ocsp response from '%s'", fn);
	if (f == -1) {
		DEBUG(3, "Can't read file");
	} else {
		len = read(f, data, OCSP_RESP_MAX);
		DEBUG(3, "Read %ld bytes of ocsp response", len);
		close(f);
	}
	if (len < 0) len = 0;
	return len;
}

static int ssl_stapling_cb(SSL *ssl, void *p)
{
	connection *conn = SSL_get_app_data(ssl);
	unsigned char *data, *ocsp_resp_copy;
	long len = 0;

	if (conn == NULL) {
		debug("Whoops, no conn info");
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	} else {
		DEBUG(3, "ssl_stapling_cb() called for connection from client %d to server %d",
			conn->client, conn->server);
	}
	if (SSL_get_SSL_CTX(ssl) != ssl_context) {
		const char *n;
		char ocsp_file[1024];
		struct sni *s;
		DEBUG(3, "stapling for sni context");
		n = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
		if (n == NULL) {
			DEBUG(3, "SNI hostname null, giving up");
			return SSL_TLSEXT_ERR_NOACK;
		}
		s = lookup_sni(n);
		if (now-s->ocsp_resp_time > 3600) {	/* seems about right */
			snprintf(ocsp_file, sizeof ocsp_file, "%s/%s.ocsp", ssl_sni_path, n);
			s->ocsp_resp_len = read_ocsp(ocsp_file, s->ocsp_resp_data);
			s->ocsp_resp_time = now;
		}
		len = s->ocsp_resp_len;
		data = s->ocsp_resp_data;
	} else {
		DEBUG(3, "stapling for default context");
		if (ocsp_resp_file) {
			ocsp_resp_len = read_ocsp(ocsp_resp_file, ocsp_resp_data);
			free(ocsp_resp_file);
			ocsp_resp_file = NULL;
		}
		len = ocsp_resp_len;
		data = ocsp_resp_data;
	}
	if (len == 0) {
		DEBUG(3, "No ocsp data");
		return SSL_TLSEXT_ERR_NOACK;
	}
	ocsp_resp_copy = pen_malloc(len);
	memcpy(ocsp_resp_copy, data, len);
	SSL_set_tlsext_status_ocsp_resp(ssl, ocsp_resp_copy, len);
	return SSL_TLSEXT_ERR_OK;
}

static int ssl_sni_cb(SSL *ssl, int *foo, void *arg)
{
	const char *n;
	struct sni *s;

	n = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (n == NULL) {
		DEBUG(3, "SNI hostname null, giving up");
		return SSL_TLSEXT_ERR_NOACK;
	}
	DEBUG(3, "ssl_sni_cb() => name = '%s'", n);
	if (ssl_sni_path == NULL) {
		DEBUG(3, "ssl_sni_path not set, giving up");
		return SSL_TLSEXT_ERR_NOACK;
	}
	s = lookup_sni(n);
	if (s->ssl_context == NULL) return SSL_TLSEXT_ERR_NOACK;
	SSL_set_SSL_CTX(ssl, s->ssl_context);
	return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *ssl_create_context(char *keyfile, char *certfile,
	char *cacert_dir, char *cacert_file)
{
	int n, err;
	SSL_CTX *ssl_context;

	if (certfile == NULL || *certfile == 0) {
		debug("SSL: No cert file specified in config file!");
		debug("The server MUST have a certificate!");
		return NULL;
	}
	if (keyfile == NULL || *keyfile == 0)
		keyfile = certfile;
	if (cacert_dir != NULL && *cacert_dir == 0)
		cacert_dir = NULL;
	if (cacert_file != NULL && *cacert_file == 0)
		cacert_file = NULL;

	ssl_context = SSL_CTX_new(SSLv23_method());
	if (ssl_context == NULL) {
		err = ERR_get_error();
		debug("SSL: Error allocating context: %s",
			ERR_error_string(err, NULL));
		return NULL;
	}
	switch (ssl_protocol) {
#ifndef OPENSSL_NO_SSL3
	case SRV_SSL_V3:
		ssl_options |= SSL_OP_NO_SSLv2;
		break;
#endif
	case SRV_SSL_TLS1:
		ssl_options |= SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
		break;
	}
	DEBUG(1, "ssl_options = 0x%lx", ssl_options);
	if (ssl_options) {
		SSL_CTX_set_options(ssl_context, ssl_options);
	}
	if (ssl_compat) {
		SSL_CTX_set_options(ssl_context, SSL_OP_ALL);
	}
	DEBUG(1, "ssl_ciphers = '%s'", ssl_ciphers);
	if (ssl_ciphers) {
		n = SSL_CTX_set_cipher_list(ssl_context, ssl_ciphers);
		if (n == 0) {
			err = ERR_get_error();
			DEBUG(3, "SSL_CTX_set_cipher_list(ssl_context, %s) returns %d (%s)",
				ssl_ciphers, n, err);
		}
	}

	if (!SSL_CTX_use_certificate_file(ssl_context, certfile,
					SSL_FILETYPE_PEM)) {
		err = ERR_get_error();
		debug("SSL: error reading certificate from file %s: %s",
			certfile, ERR_error_string(err, NULL));
		return NULL;
	}
	if (!SSL_CTX_use_PrivateKey_file(ssl_context, keyfile,
					SSL_FILETYPE_PEM)) {
		err = ERR_get_error();
		debug("SSL: error reading private key from file %s: %s",
			keyfile, ERR_error_string(err, NULL));
		return NULL;
	}
	if (!SSL_CTX_check_private_key(ssl_context)) {
		debug("SSL: Private key does not match public key in cert!");
		return NULL;
	}

	if (cacert_dir != NULL || cacert_file != NULL) {
		if (!SSL_CTX_load_verify_locations(ssl_context,
					cacert_file, cacert_dir)) {
			err = ERR_get_error();
			debug("SSL: Error error setting CA cert locations: %s",
				ERR_error_string(err, NULL));
			cacert_file = cacert_dir = NULL;
		}
	}
	if (cacert_dir == NULL && cacert_file == NULL) {  /* no verify locations loaded */
		debug("SSL: No verify locations, trying default");
		if (!SSL_CTX_set_default_verify_paths(ssl_context)) {
			err = ERR_get_error();
			debug("SSL: Error error setting default CA cert location: %s",
				ERR_error_string(err, NULL));
			debug("continuing anyway...");
		}
	}
	SSL_CTX_set_tmp_rsa_callback(ssl_context, ssl_temp_rsa_cb);
	SSL_CTX_set_info_callback(ssl_context, ssl_info_cb);
	SSL_CTX_set_tlsext_status_cb(ssl_context, ssl_stapling_cb);
	SSL_CTX_set_tlsext_servername_callback(ssl_context, ssl_sni_cb);
	if (require_peer_cert) {
		SSL_CTX_set_verify(ssl_context,
			SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			ssl_verify_cb);
	} else {
		SSL_CTX_set_verify(ssl_context,
			SSL_VERIFY_NONE,
			ssl_verify_cb);
	}

	SSL_CTX_set_client_CA_list(ssl_context,
			SSL_load_client_CA_file(certfile));

	/* permit large writes to be split up in several records */
	SSL_CTX_set_mode(ssl_context, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	DEBUG(3, "SSL_CTX_get_session_cache_mode() returns %d",
		SSL_CTX_get_session_cache_mode(ssl_context));
	SSL_CTX_set_session_cache_mode(ssl_context, SSL_SESS_CACHE_SERVER);

#if defined(HAVE_EC_KEY) && defined(NID_X9_62_prime256v1)
	EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (ecdh == NULL) {
		debug("EC_KEY_new_by_curve_name failure");
	} else {
		if (SSL_CTX_set_tmp_ecdh(ssl_context, ecdh) != 1) {
			debug("SSL_CTX_set_tmp_ecdh failure");
		} else {
			DEBUG(1, "ECDH Initialized with NIST P-256");
		}
		EC_KEY_free(ecdh);
	}
#endif

	SSL_CTX_set_session_id_context(ssl_context, (void *)&ssl_session_id_context,
		sizeof ssl_session_id_context);

	return ssl_context;
}

int ssl_init(void)
{
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	ssl_context = ssl_create_context(keyfile, certfile, cacert_dir, cacert_file);
	if (ssl_context == NULL) {
		error("Unable to create default context");
	}

	return 0;
}

#endif  /* HAVE_LIBSSL */
