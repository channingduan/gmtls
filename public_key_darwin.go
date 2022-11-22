// go:build darwin

package gmtls

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR}/libs/darwin -lcrypto -lssl
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/objects.h>
#include <openssl/opensslconf.h>
*/
import "C"

type PublicKey struct {
	Pkey *C.EVP_PKEY
}

func (pkey *PublicKey) GetText() {

}

func (pkey *PublicKey) Encrypt() {
}

func (pkey *PublicKey) Sign() {

}
