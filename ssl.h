#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SRV_SSL_V23 0
#define SRV_SSL_V2 1
#define SRV_SSL_V3 2
#define SRV_SSL_TLS1 3

#define OCSP_RESP_MAX 10000

extern char ssl_compat;
extern char require_peer_cert;
extern char ssl_protocol;
extern char *certfile;
extern char *keyfile;
extern char *cacert_dir;
extern char *cacert_file;
extern SSL_CTX *ssl_context;
extern long ssl_options;
extern char *ssl_ciphers;
extern int ssl_session_id_context;
extern int ssl_client_renegotiation_interval;
extern unsigned char ocsp_resp_data[OCSP_RESP_MAX];
extern long ocsp_resp_len;
extern char *ocsp_resp_file;

extern int ssl_init(void);

#endif	/* HAVE_LIBSSL */
