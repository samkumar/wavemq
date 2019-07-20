package jedi

import (
	"bytes"
	"context"
	"crypto/aes"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/immesys/wave/eapi"
	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/engine"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wavemq/mqpb"
	"github.com/samkumar/reqcache"
	"github.com/ucbrise/jedi-pairing/lang/go/cryptutils"
	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
)

// MaxURIComponents is the maximum number of components in a URI.
const MaxURIComponents = 11

// State stores the state used by JEDI for end-to-end encryption.
type State struct {
	cache  *reqcache.LRUCache
	engine *engine.Engine
	wave   *eapi.EAPI
}

// NewState creates a new JEDI context for end-to-end encryption.
func NewState(wave *eapi.EAPI) *State {
	eng := wave.GetEngineNoPerspective()
	return &State{
		cache:  NewCache(eng),
		engine: eng,
		wave:   wave,
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

// Decrypt decrypts a message's payload using JEDI
func (s *State) Decrypt(p *pb.Perspective, opt *mqpb.JEDIOptions, message []*mqpb.PayloadObject) ([]*mqpb.PayloadObject, error) {
	ctx := context.Background()

	pattern := make(wkdibe.AttributeList)
	for i, slot := range opt.GetSlots() {
		if len(slot) != 0 {
			pattern[wkdibe.AttributeIndex(i)] = cryptutils.HashToZp(new(big.Int), slot)
		}
	}

	if message[0].GetSchema() != "jedi:encryptedkey" {
		panic("First PO has wrong schema")
	}

	ciphertext := new(wkdibe.Ciphertext)
	if !ciphertext.Unmarshal(message[0].GetContent(), true, false) {
		panic("Could not unmarshal ciphertext")
	}

	eng, werr := s.wave.GetEngine(ctx, p)
	if werr != nil {
		return nil, werr.Cause()
	}
	//secret := eng.Perspective()
	// slottedSecretKey, err := secret.WR1BodyKey(ctx, opt.GetSlots(), false)
	dctx := engine.NewEngineDecryptionContext(eng)
	dctx.AutoLoadPartitionSecrets(true)

	var found bool
	secretkey := new(wkdibe.SecretKey)
	err := dctx.WR1OAQUEKeysForContent(ctx, iapi.HashSchemeInstanceFromMultihash(opt.GetNamespace()), false, opt.GetSlots(), func(k iapi.SlottedSecretKey) bool {
		wrapped, ok := k.(*iapi.EntitySecretKey_OAQUE_BLS12381_S20)
		if ok {
			marshalled := wrapped.SerdesForm.Private.Content.([]byte)
			if !secretkey.Unmarshal(marshalled, true, false) {
				return true
			}
			secretkey = wkdibe.NonDelegableQualifyKey(wrapped.Params, secretkey, pattern)
			found = true
			return false
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	if !found {
		panic("Could not find suitable key to decrypt")
	}

	encryptable := wkdibe.Decrypt(ciphertext, secretkey)
	key := encryptable.HashToSymmetricKey(make([]byte, AESKeySize))

	fmt.Printf("Got symmetric key: %v\n", key)
	if message[1].GetSchema() != "jedi:contents" {
		panic("Second PO has wrong schema")
	}
	encrypted := message[1].GetContent()
	decrypted := make([]byte, len(encrypted)-aes.BlockSize)
	err = aesCTRDecryptInMem(decrypted, encrypted, key)
	if err != nil {
		return nil, err
	}
	payload := new(mqpb.Payload)
	err = proto.Unmarshal(decrypted, payload)
	if err != nil {
		return nil, err
	}

	return payload.GetObjects(), nil
}

func (s *State) Sign() {
	// TODO
}

func (s *State) Verify() {
	// TODO
}
