/* +build cgo */
package gmtls

/*
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/objects.h>
#include <openssl/opensslconf.h>

extern long _BIO_get_mem_data(BIO *b, char **pp);
extern void _OPENSSL_free(void *addr);
*/
import "C"
import (
	"runtime"
	"unsafe"
)

type Certificate struct {
	X509 *C.X509
}

func (cert *Certificate) GetText() (string, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return "", GetErrors()
	}
	defer C.BIO_free(bio)
	if 0 >= C.X509_print(bio, cert.X509) {
		return "", GetErrors()
	}
	var p *C.char
	l := C._BIO_get_mem_data(bio, &p)
	if l <= 0 {
		return "", GetErrors()
	}
	return C.GoString(p)[:l], nil
}

func (cert *Certificate) GetIssuer() (string, error) {
	name := C.X509_get_issuer_name(cert.X509)
	if name == nil {
		return "", GetErrors()
	}
	str := C.X509_NAME_oneline(name, nil, 0)
	if str == nil {
		return "", GetErrors()
	}
	defer C._OPENSSL_free(unsafe.Pointer(str))
	return C.GoString(str), nil
}

func (cert *Certificate) GetPublicKey() (*PublicKey, error) {
	pkey := C.X509_get_pubkey(cert.X509)
	if pkey == nil {
		return nil, GetErrors()
	}
	ret := &PublicKey{Pkey: pkey}
	runtime.SetFinalizer(ret, func(ret *PublicKey) {
		C.EVP_PKEY_free(ret.Pkey)
	})
	return ret, nil
}
