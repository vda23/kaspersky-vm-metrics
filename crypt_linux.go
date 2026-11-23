//go:build linux && cgo

package main

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
typedef char *(*crypt_fn)(const char *, const char *);
static crypt_fn system_crypt;
static int load_crypt(void) {
 const char *libs[] = {"libcrypt.so.1", "libcrypt.so.2", "libcrypt.so", NULL};
 for (int i=0; libs[i]; i++) {
  void *lib=dlopen(libs[i], RTLD_NOW|RTLD_LOCAL);
  if (!lib) continue;
  system_crypt=(crypt_fn)dlsym(lib,"crypt");
  if (system_crypt) return 1;
  dlclose(lib);
 }
 return 0;
}
static char *call_crypt(char *password, char *salt) {return system_crypt(password,salt);}
*/
import "C"
import (
	"crypto/subtle"
	"strings"
	"sync"
	"unsafe"
)

var cryptInit sync.Once
var cryptFound bool
var cryptMutex sync.Mutex

func cryptAvailable() bool {
	cryptInit.Do(func() { cryptFound = C.load_crypt() != 0 })
	return cryptFound
}
func verifyHash(password, hash string) bool {
	if password == "" || len(password) > 1024 || strings.ContainsRune(password, 0) || !cryptAvailable() {
		return false
	}
	pass := C.CString(password)
	defer C.free(unsafe.Pointer(pass))
	salt := C.CString(hash)
	defer C.free(unsafe.Pointer(salt))
	// crypt(3) returns a pointer to shared storage owned by libcrypt.
	cryptMutex.Lock()
	defer cryptMutex.Unlock()
	result := C.call_crypt(pass, salt)
	if result == nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(C.GoString(result)), []byte(hash)) == 1
}
