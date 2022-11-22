package gmtls

/*
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static long _BIO_set_conn_hostname(BIO *b, char *name) {
	return BIO_set_conn_hostname(b, name);
}
static int _BIO_do_connect(BIO *b) {
	return BIO_do_connect(b);
}
static int _BIO_do_handshake(BIO *b) {
	return BIO_do_handshake(b);
}

static long _BIO_get_ssl(BIO *b, SSL **sslp) {
	return BIO_get_ssl(b, sslp);
}
static int _SSL_set_tlsext_host_name(SSL *ssl, char *name) {
	return SSL_set_tlsext_host_name(ssl, name);
}
static long _SSL_CTX_set_options(SSL_CTX *ctx, long options) {
	return SSL_CTX_set_options(ctx, options);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type TlsConnection struct {
	ctx    *C.SSL_CTX
	bio    *C.BIO
	ssl    *C.SSL
	sockfd C.int
}

func NewTlsContext(version int, caFile string) (*TlsConnection, error) {

	if version != VersionTLS12 {
		return nil, fmt.Errorf("tls version must use TLSv1.2")
	}
	C.SSL_library_init()
	// 设置错误类型为string
	C.SSL_load_error_strings()
	var conn TlsConnection
	conn.ctx = C.SSL_CTX_new(C.TLSv1_2_client_method())
	caCert := C.CString(caFile)
	defer C.free(unsafe.Pointer(caCert))

	// 客户端验证服务器证书
	C.SSL_CTX_set_verify(conn.ctx, C.SSL_VERIFY_PEER, nil)
	// 禁止 Session Ticket
	C._SSL_CTX_set_options(conn.ctx, C.SSL_OP_NO_SSLv2|C.SSL_OP_NO_SSLv3|C.SSL_OP_NO_COMPRESSION|C.SSL_OP_NO_TICKET)

	if res := C.SSL_CTX_load_verify_locations(conn.ctx, caCert, nil); res != 1 {
		return nil, fmt.Errorf("faied to load verify locations")
	}

	// 设置超时时间(10s)
	C.SSL_CTX_set_timeout(conn.ctx, 10)

	return &conn, nil
}

//SetCertificate 签名证书
func (conn *TlsConnection) SetCertificate(cert, key string) error {

	signCert := C.CString(cert)
	defer C.free(unsafe.Pointer(signCert))
	if err := C.SSL_CTX_use_certificate_chain_file(conn.ctx, signCert); err != 1 {
		return fmt.Errorf("failed to set certificate chain file: %v", GetErrors())
	}

	signKey := C.CString(key)
	defer C.free(unsafe.Pointer(signKey))
	if err := C.SSL_CTX_use_PrivateKey_file(conn.ctx, signKey, C.SSL_FILETYPE_PEM); err != 1 {
		return fmt.Errorf("failed to set private key: %v", GetErrors())
	}
	if err := C.SSL_CTX_check_private_key(conn.ctx); err != 1 {
		return fmt.Errorf("failed to check private key:: %v", GetErrors())
	}

	return nil
}

// SetEncryptCertificate 加密证书
func (conn *TlsConnection) SetEncryptCertificate(enSslCert, enSslKey string) error {

	enCert := C.CString(enSslCert)
	defer C.free(unsafe.Pointer(enCert))
	if err := C.SSL_CTX_use_certificate_file(conn.ctx, enCert, C.SSL_FILETYPE_PEM); err != 1 {
		return fmt.Errorf("failed to set certificate file: %v", GetErrors())
	}

	enKey := C.CString(enSslKey)
	defer C.free(unsafe.Pointer(enKey))
	if err := C.SSL_CTX_use_enc_PrivateKey_file(conn.ctx, enKey, C.SSL_FILETYPE_PEM); err != 1 {
		return fmt.Errorf("failed to set encrypt private key: %v", GetErrors())
	}

	if err := C.SSL_CTX_check_enc_private_key(conn.ctx); err != 1 {
		return fmt.Errorf("failed to check encrypt private key: %v", GetErrors())
	}

	return nil
}

func (conn *TlsConnection) Connection(host string) error {
	addr := C.CString(host)
	defer C.free(unsafe.Pointer(addr))

	conn.bio = C.BIO_new_ssl_connect(conn.ctx)
	if conn.bio == nil {
		return fmt.Errorf("failed to new ssl connect: %v", GetErrors())
	}

	if res := C._BIO_set_conn_hostname(conn.bio, addr); res <= 0 {
		return fmt.Errorf("failed to set connect hostname: %v", GetErrors())
	}

	C._BIO_get_ssl(conn.bio, &conn.ssl)
	if conn.ssl == nil {
		return fmt.Errorf("failed to bio get ssl: %v", GetErrors())
	}
	if res := C._BIO_do_connect(conn.bio); res <= 0 {
		return fmt.Errorf("failed to bio connect: %v", GetErrors())
	}

	return nil
}

func (conn *TlsConnection) GetPeerCertificates() (*Certificate, error) {

	x509 := C.SSL_get_peer_certificate(conn.ssl)
	if x509 == nil {
		return nil, GetErrors()
	}

	return &Certificate{X509: x509}, nil
}

func (conn *TlsConnection) GetVerifyResult() (int64, error) {
	var ssl *C.SSL
	C._BIO_get_ssl(conn.bio, &ssl)
	if ssl == nil {
		return -1, GetErrors()
	}
	result := C.SSL_get_verify_result(ssl)
	if result != C.X509_V_OK {
		return int64(result), GetErrors()
	}
	return int64(result), nil
}

func (conn *TlsConnection) WriteString(s string) {
	data := C.CString(fmt.Sprintf("%s\n", s))
	C.SSL_write(conn.ssl, unsafe.Pointer(data), C.int(42))
}

func (conn *TlsConnection) Write(data []byte) (int, error) {

	n := C.SSL_write(conn.ssl, unsafe.Pointer(&data[0]), C.int(len(data)))
	if n < 0 {
		return int(n), GetErrors()
	}

	return int(n), nil
}
func (conn *TlsConnection) Read(buf []byte) (int, error) {
	n := C.SSL_read(conn.ssl, unsafe.Pointer(&buf[0]), C.int(len(buf)))
	if n <= 0 {
		return 0, GetErrors()
	}
	return int(n), nil
}

func (conn *TlsConnection) Close() error {
	if conn.ssl != nil {
		C.SSL_shutdown(conn.ssl)
		C.SSL_clear(conn.ssl)
		C.SSL_CTX_free(conn.ctx)
	}

	return nil
}
