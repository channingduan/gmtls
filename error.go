/* +build cgo */
package gmtls

/*
#include <openssl/err.h>
#include <openssl/bio.h>

extern long _BIO_get_mem_data(BIO *b, char **pp);
*/
import "C"

import (
	"fmt"
)

func GetErrors() error {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return fmt.Errorf("bio is null")
	}
	defer C.BIO_free(bio)
	C.ERR_print_errors(bio)
	var p *C.char
	l := C._BIO_get_mem_data(bio, &p)
	if l <= 0 {
		return fmt.Errorf("get mem data err")
	}
	return fmt.Errorf(C.GoString(p))
}
