package gmtls

/*
#include <openssl/ssl.h>
*/
import "C"

// SetReadDeadline 心跳处理
func (conn *TlsConnection) SetReadDeadline(t int) error {
	C.SSL_CTX_set_timeout(conn.ctx, C.long(t))
	return nil
}

func (conn *TlsConnection) SetWriteDeadline(t int) error {
	C.SSL_CTX_set_timeout(conn.ctx, C.long(t))
	return nil
}
