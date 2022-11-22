// go:build darwin

package gmtls

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR}/libs/darwin -lcrypto -lssl -ldl

#include <openssl/bio.h>
#include <openssl/crypto.h>

long _BIO_get_mem_data(BIO *b, char **pp) {
	return BIO_get_mem_data(b, pp);
}

void _OPENSSL_free(void *addr) {
	OPENSSL_free(addr);
}
*/
import "C"
