package jedi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/immesys/wave/eapi"
	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/engine"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/serdes"
	"github.com/samkumar/reqcache"
	"github.com/ucbrise/jedi-pairing/lang/go/bls12381"
	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
)

// CacheSize is the size (in bytes) of JEDI's cache.
const CacheSize = (32 << 20)

// CacheEntry stores cached data to accelerate encryption for certain URIs.
type CacheEntry struct {
	lock         sync.RWMutex
	lastUpdated  time.Time
	slots        [][]byte
	pattern      wkdibe.AttributeList
	key          [AESKeySize]byte
	encryptedKey *wkdibe.Ciphertext
	precomputed  *wkdibe.PreparedAttributeList
}

// CiphertextEntry stores the cached decryption of a ciphertext.
type CiphertextEntry struct {
	lock      sync.RWMutex
	decrypted [AESKeySize]byte
	populated bool
}

/* Key type identifiers for cache. */
const (
	KeyTypeURI = iota
	KeyTypeNamespace
	KeyTypeCiphertext
)

func nskey(ns []byte) string {
	var b strings.Builder
	b.WriteByte(KeyTypeNamespace)
	b.Write(ns)
	return b.String()
}

func urikey(ns []byte, uri [][]byte) string {
	var b strings.Builder
	b.WriteByte(KeyTypeURI)

	var buffer [4]byte
	binary.LittleEndian.PutUint32(buffer[:], uint32(len(ns)))

	b.Write(buffer[:])
	b.Write(ns)

	for _, component := range uri {
		b.Write(component)
		b.WriteByte('/')
	}

	return b.String()
}

func ctkey(ciphertext []byte) string {
	var b strings.Builder
	b.WriteByte(KeyTypeCiphertext)
	b.Write(ciphertext)
	return b.String()
}

func parsekey(key string) (keytype byte, content []byte) {
	keybytes := []byte(key)
	keytype = keybytes[0]
	switch keytype {
	case KeyTypeNamespace:
		content = keybytes[1:]
	case KeyTypeURI:
		nslen := binary.LittleEndian.Uint32(keybytes[1:5])
		content = keybytes[5 : 5+nslen]
	case KeyTypeCiphertext:
		content = keybytes[1:]
	}
	return
}

func lookupEntity(eng *engine.Engine, namespace []byte, location *pb.Location) (*iapi.Entity, error) {
	ctx := context.Background()
	nsHash := iapi.HashSchemeInstanceFromMultihash(namespace)
	if !nsHash.Supported() {
		return nil, errors.New("could not parse namespace")
	}
	nsLoc, err := eapi.LocationSchemeInstance(location)
	if err != nil {
		return nil, fmt.Errorf("could not parse namespace location: %s", err.Error())
	}
	if nsLoc == nil {
		nsLoc = iapi.SI().DefaultLocation(ctx)
	}
	ns, val, uerr := eng.LookupEntity(ctx, nsHash, nsLoc)
	if uerr != nil {
		return nil, fmt.Errorf("could not resolve namespace: %s", uerr.Error())
	}
	if !val.Valid {
		return nil, errors.New("namespace entity is no longer valid")
	}
	return ns, nil
}

// NewCache creates a new cache for JEDI.
func NewCache(eng *engine.Engine) *reqcache.LRUCache {
	return reqcache.NewLRUCache(CacheSize,
		func(ctx context.Context, key interface{}) (interface{}, uint64, error) {
			keystring := key.(string)
			keytype, contentbytes := parsekey(keystring)
			switch keytype {
			case KeyTypeNamespace:
				/* Get the namespace entity. */
				namespace, err := lookupEntity(eng, contentbytes, nil)
				if err != nil {
					return nil, 0, err
				}

				/* Get the WKD-IBE public parameters from the namespace entity. */
				params := new(wkdibe.Params)
				var size uint64
				for _, kr := range namespace.Keys {
					wrapped, ok := kr.(*iapi.EntityKey_OAQUE_BLS12381_S20_Params)
					if ok {
						marshalled := wrapped.SerdesForm.Key.Content.(serdes.EntityParamsOQAUE_BLS12381_s20)
						if !params.Unmarshal(marshalled, true, false) {
							continue
						}
						size = uint64(unsafe.Sizeof(params)) +
							uint64(uintptr(params.NumAttributes())*unsafe.Sizeof(bls12381.G1Zero))
						break
					}
				}
				if size == 0 {
					return nil, 0, errors.New("namespace lacks WKD-IBE params")
				}

				return params, uint64(len(keystring)) + size, nil
			case KeyTypeURI:
				entry := new(CacheEntry)
				/*
				 * Since these cache entries are mutable anyway, we just rely
				 * on an internal lock (needed for mutability) for
				 * initialization.
				 */
				size := unsafe.Sizeof(entry) + unsafe.Sizeof(*entry.encryptedKey) + unsafe.Sizeof(*entry.precomputed)
				return entry, uint64(len(keystring)) + uint64(size), nil
			case KeyTypeCiphertext:
				entry := new(CiphertextEntry)
				/*
				 * We don't populate it here because, if there's an error, we
				 * want another thread to be able to try. This could happen if
				 * a malicious party "steals" an honest party's ciphertext and
				 * tries to have an honest subscriber decrypt it with the wrong
				 * URI/time combo. Unless we have a cached decryption, we want
				 * all threads to try, even if a different thread has
				 * previously encountered a failure or error.
				 */
				size := unsafe.Sizeof(entry)
				return entry, uint64(len(keystring)) + uint64(size), nil
			default:
				panic(fmt.Sprintf("Unknown key type: %d", int(keytype)))
			}
		}, func(evicted []*reqcache.LRUCacheEntry) {
		})
}
