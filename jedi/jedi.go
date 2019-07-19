package jedi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/gogo/protobuf/proto"
	"github.com/immesys/wave/eapi"
	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/engine"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wavemq/mqpb"
	"github.com/samkumar/reqcache"
	"github.com/ucbrise/jedi-pairing/lang/go/bls12381"
	"github.com/ucbrise/jedi-pairing/lang/go/cryptutils"
	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
)

// AESKeySize is the key size to use with AES, in bytes.
const AESKeySize = 16

// NamespaceParamsCacheSize is the size (in bytes) of the cache of namespace
// parameters.
const NamespaceParamsCacheSize = (32 << 20)

// MaxURIComponents is the maximum number of components in a URI.
const MaxURIComponents = 11

// State stores the state used by JEDI for end-to-end encryption.
type State struct {
	cache *reqcache.LRUCache
}

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

// NewState creates a new JEDI context for end-to-end encryption.
func NewState(wave *eapi.EAPI) *State {
	eng := wave.GetEngineNoPerspective()

	var cache *reqcache.LRUCache
	cache = reqcache.NewLRUCache(NamespaceParamsCacheSize,
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
	return &State{
		cache: cache,
	}
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

func aesCTREncryptInMem(dst []byte, src []byte, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	iv := dst[:aes.BlockSize]
	if _, err = rand.Read(iv); err != nil {
		return err
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(dst[aes.BlockSize:], src)
	return nil
}

func parseURI(uri string) ([][]byte, error) {
	components := strings.SplitN(uri, "/", MaxURIComponents+1)
	if len(components) > MaxURIComponents {
		return nil, fmt.Errorf("URI contains %d components (max %d)", len(components), MaxURIComponents)
	}
	uribytes := make([][]byte, len(components))
	for i, comp := range components {
		if len(comp) == 0 {
			return nil, fmt.Errorf("URI contains empty component at index %d", i)
		}
		uribytes[i] = []byte(comp)
	}
	return uribytes, nil
}

// Encrypt encrypts a message's payload using JEDI.
func (s *State) Encrypt(p *mqpb.PublishParams) ([]*mqpb.PayloadObject, error) {
	var err error
	ctx := context.Background()

	/* Get WKD-IBE public parameters for the specified namespace. */
	paramsInt, err := s.cache.Get(ctx, nskey(p.GetNamespace()))
	if err != nil {
		return nil, err
	}
	params := paramsInt.(*wkdibe.Params)

	/* Parse the URI. */
	var uribytes [][]byte
	if uribytes, err = parseURI(p.GetUri()); err != nil {
		return nil, err
	}
	uribytes = uribytes[:p.GetJediOptions().GetPartitionSize()]

	/* Get the cached state (if any) for this URI. */
	entryInt, err := s.cache.Get(ctx, urikey(p.Namespace, uribytes))
	if err != nil {
		return nil, err
	}
	entry := entryInt.(*CacheEntry)

	var key [AESKeySize]byte
	var encryptedKey []byte
	var pattern wkdibe.AttributeList

	/* Compute the slots for the URI and current time.. */
	now := time.Now()
	slots, werr := iapi.CalculateWR1Partition(now, now, uribytes)
	if werr != nil {
		return nil, werr.Cause()
	}

	/*
	 * Optimistically assume that our slots will be identical to the cached
	 * ones.
	 */
	identical := true
	entry.lock.RLock()
	if entry.slots == nil {
		identical = false
	} else {
		/* Check if the entry was updated before we could grab entry.lock. */
		if entry.lastUpdated.After(now) {
			now = entry.lastUpdated
			slots, werr = iapi.CalculateWR1Partition(now, now, uribytes)
			if werr != nil {
				entry.lock.RUnlock()
				return nil, werr.Cause()
			}
		}

		/* Check if the slots for URI/time match those in the cache. */
		for i, slot := range slots {
			if !bytes.Equal(slot, entry.slots[i]) {
				identical = false
				break
			}
		}

		/* If they match, then save the key so we can use it to encrypt. */
		if identical {
			copy(key[:], entry.key[:])
			encryptedKey = entry.encryptedKey.Marshal(true)
		}
	}
	entry.lock.RUnlock()

	/*
	 * If they don't match, then grab the exclusive lock and do precomputation
	 * with adjustment.
	 */
	if !identical {
		entry.lock.Lock()

		/* Check if the entry was updated before we could grab entry.lock. */
		if entry.lastUpdated.After(now) {
			now = entry.lastUpdated
			slots, werr = iapi.CalculateWR1Partition(now, now, uribytes)
			if werr != nil {
				entry.lock.RUnlock()
				return nil, werr.Cause()
			}
		}

		/* Get the diff between our slots and the ones we have cached. */
		for i, slot := range slots {
			if !bytes.Equal(slot, entry.slots[i]) {
				if pattern == nil {
					/* This runs once if there's a diff. */
					pattern = make(wkdibe.AttributeList)
				}
				if slot != nil {
					pattern[wkdibe.AttributeIndex(i)] = cryptutils.HashToZp(new(big.Int), slot)
				}
			}
		}

		/* Check if there's a diff now before proceeding. */
		if pattern != nil {
			/* Complete pattern by copying hashed elements. */
			for j, hash := range entry.pattern {
				i := int(j)
				if bytes.Equal(slots[i], entry.slots[i]) {
					pattern[j] = hash
				}
			}

			/* Adjust the precomputed value. */
			wkdibe.AdjustPreparedAttributeList(entry.precomputed, params, entry.pattern, pattern)
			entry.slots = slots
			entry.pattern = pattern

			/* Sample a new key and compute the new encrypted key. */
			_, encryptable := cryptutils.GenerateKey(entry.key[:])
			entry.encryptedKey = wkdibe.EncryptPrepared(encryptable, params, entry.precomputed)

			/* Updated the lastUpdated field. */
			entry.lastUpdated = now
		}

		copy(key[:], entry.key[:])
		encryptedKey = entry.encryptedKey.Marshal(true)

		entry.lock.Unlock()
	}

	/* Encrypt message and send it as a single PO. */
	payload := &mqpb.Payload{Objects: p.GetContent()}
	message, err := proto.Marshal(payload)
	if err != nil {
		return nil, errors.New("could not marshal payload objects")
	}
	encryptedPayloadContents := make([]byte, aes.BlockSize+len(message))
	err = aesCTREncryptInMem(encryptedPayloadContents, message, key[:])
	if err != nil {
		return nil, err
	}
	contentPO := &mqpb.PayloadObject{
		Schema:  "jedi:contents",
		Content: encryptedPayloadContents,
	}

	// TODO: Come up with a protocol to avoid attaching this to every message.
	keyPO := &mqpb.PayloadObject{
		Schema:  "jedi:encryptedkey",
		Content: encryptedKey,
	}
	return []*mqpb.PayloadObject{keyPO, contentPO}, nil
}

func (s *State) Decrypt() {
	// TODO
}

func (s *State) Sign() {
	// TODO
}

func (s *State) Verify() {
	// TODO
}
