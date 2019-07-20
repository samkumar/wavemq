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

	"github.com/immesys/wave/engine"
	"github.com/immesys/wave/iapi"
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

/* Key type identifiers for cache. */
const (
	KeyTypeURI = iota
	KeyTypeNamespace
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

func parsekey(key string) (keytype byte, ns []byte) {
	keybytes := []byte(key)
	keytype = keybytes[0]
	switch keytype {
	case KeyTypeNamespace:
		ns = keybytes[1:]
	case KeyTypeURI:
		nslen := binary.LittleEndian.Uint32(keybytes[1:5])
		ns = keybytes[5 : 5+nslen]
		// 	start := int(5 + nslen)
		// 	end := start
		// outerloop:
		// 	for {
		// 		for key[end] != '/' {
		// 			end++
		// 			if end == len(key) {
		// 				break outerloop
		// 			}
		// 		}
		// 		uri = append(uri, keybytes[start:end])
		// 		end++
		// 		start = end
		// 	}
	}
	return
}

// NewCache creates a new cache for JEDI.
func NewCache(eng *engine.Engine) *reqcache.LRUCache {
	return reqcache.NewLRUCache(CacheSize,
		func(ctx context.Context, key interface{}) (interface{}, uint64, error) {
			keytype, namespacebytes := parsekey(key.(string))
			switch keytype {
			case KeyTypeNamespace:
				/* Get the namespace entity. */
				namespace, err := lookupEntity(eng, namespacebytes, nil)
				if err != nil {
					return nil, 0, err
				}

				/* Get the WKD-IBE public parameters from the namespace entity. */
				params := new(wkdibe.Params)
				var size uint64
				for _, kr := range namespace.Keys {
					wrapped, ok := kr.(*iapi.EntityKey_OAQUE_BLS12381_S20_Params)
					if ok {
						marshalled := wrapped.SerdesForm.Key.Content.([]byte)
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

				return params, size, nil
			case KeyTypeURI:
				entry := new(CacheEntry)
				/*
				 * Since these cache entries are mutable anyway, we just rely
				 * on an internal lock (needed for mutability) for
				 * initialization.
				 */
				size := unsafe.Sizeof(entry) + unsafe.Sizeof(*entry.encryptedKey) + unsafe.Sizeof(*entry.precomputed)
				return entry, uint64(size), nil
			default:
				panic(fmt.Sprintf("Unknown key type: %d", int(keytype)))
			}
		}, func(evicted []*reqcache.LRUCacheEntry) {
		})
}
