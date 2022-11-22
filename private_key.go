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
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/objects.h>
#include <openssl/opensslconf.h>
*/
import "C"

type PrivateKey struct {
	Pkey *C.EVP_PKEY
}

func (pkey *PrivateKey) GetText() {

}

func (pkey *PrivateKey) Decrypt() {

}

func (pkey *PrivateKey) Verify() {

}
