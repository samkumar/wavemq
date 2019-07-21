package jedi

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/ddreyer/wave/consts"
	"github.com/immesys/wave/eapi"
	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/localdb/lls"
	"github.com/immesys/wave/localdb/poc"
	"github.com/immesys/wave/storage/overlay"
	"github.com/immesys/wave/waved"
	"github.com/immesys/wavemq/mqpb"
)

var wave *eapi.EAPI
var nshash []byte
var nspersp *mqpb.Perspective
var nspbpersp *pb.Perspective
var targethash []byte
var targetpersp *mqpb.Perspective
var targetpbpersp *pb.Perspective

const (
	quote1 = "Ability is what you're capable of doing. Motivation determines what you do. Attitude determines how well you do it. --Lou Holtz"
	quote2 = "Today is your day! / Your mountain is waiting. / So... get on your way! --Theodor Seuss Geisel"
)

func wavepublish(ctx context.Context, publicDER []byte) {
	pubresp, err := wave.PublishEntity(ctx, &pb.PublishEntityParams{
		DER: publicDER,
	})
	if err != nil {
		panic(err)
	}
	if perr := pubresp.GetError(); perr != nil {
		panic(perr.GetMessage())
	}
}

func wavepublishatt(ctx context.Context, der []byte) {
	pubresp, err := wave.PublishAttestation(ctx, &pb.PublishAttestationParams{
		DER: der,
	})
	if err != nil {
		panic(err)
	}
	if perr := pubresp.GetError(); perr != nil {
		panic(perr.GetMessage())
	}
}

func waveperspective(secretDER []byte) (*mqpb.Perspective, *pb.Perspective) {
	return &mqpb.Perspective{
			EntitySecret: &mqpb.EntitySecret{
				DER: secretDER,
			},
		}, &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: secretDER,
			},
		}
}

func TestMain(m *testing.M) {
	ctx := context.Background()

	cfg := &waved.Configuration{
		Database:     "/tmp/waved",
		ListenIP:     "127.0.0.1:4410",
		HTTPListenIP: "127.0.0.1:4411",
		Storage:      make(map[string]map[string]string),
	}
	cfg.Storage["default"] = make(map[string]string)
	cfg.Storage["default"]["provider"] = "http_v1"
	cfg.Storage["default"]["url"] = "https://standalone.storage.bwave.io/v1"
	cfg.Storage["default"]["version"] = "1"

	llsdb, err := lls.NewLowLevelStorage(cfg.Database)
	if err != nil {
		panic(err)
	}
	si, err := overlay.NewOverlay(cfg.Storage)
	if err != nil {
		fmt.Printf("storage overlay error: %v\n", err)
		panic(err)
	}
	iapi.InjectStorageInterface(si)
	ws := poc.NewPOC(llsdb)
	wave = eapi.NewEAPI(ws)

	/* Create namespace entity for tests. */
	nsresp, err := wave.CreateEntity(ctx, &pb.CreateEntityParams{})
	if err != nil {
		panic(err)
	}
	wavepublish(ctx, nsresp.GetPublicDER())
	nshash = nsresp.GetHash()
	nspersp, nspbpersp = waveperspective(nsresp.GetSecretDER())

	/* Create target entity for decryptor. */
	targetresp, err := wave.CreateEntity(ctx, &pb.CreateEntityParams{})
	if err != nil {
		panic(err)
	}
	wavepublish(ctx, targetresp.GetPublicDER())

	/* Grant attestation conveying decryption keys. */
	wavePSET, err := base64.URLEncoding.DecodeString(consts.WaveBuiltinPSET)
	if err != nil {
		panic(err)
	}
	targethash = targetresp.GetHash()
	targetpersp, targetpbpersp = waveperspective(targetresp.GetSecretDER())
	attresp, err := wave.CreateAttestation(ctx, &pb.CreateAttestationParams{
		Perspective: nspbpersp,
		SubjectHash: targethash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: nshash,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: wavePSET,
						Permissions:   []string{consts.WaveBuiltinE2EE},
						Resource:      "*",
					},
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	if attresp.GetError() != nil {
		panic(attresp.GetError().GetMessage())
	}
	wavepublishatt(ctx, attresp.GetDER())

	resyncresp, err := wave.ResyncPerspectiveGraph(ctx, &pb.ResyncPerspectiveGraphParams{Perspective: targetpbpersp})
	if err != nil {
		panic(err)
	}
	if resyncresp.GetError() != nil {
		panic(resyncresp.GetError().GetMessage())
	}

	os.Exit(m.Run())
}

func TestParseURI(t *testing.T) {
	uri := "first/second/third"
	parsed, err := parseURI(uri)
	if err != nil {
		panic(err)
	}
	if len(parsed) != 4 {
		t.Fatal("Parsed URI has the wrong length")
	}
	if string(parsed[0]) != "\x00e2ee" {
		t.Fatal("Parsed URI has the wrong identifier")
	}
	if !(string(parsed[1]) == "first" && string(parsed[2]) == "second" && string(parsed[3]) == "third") {
		t.Fatal("Parsed URI is incorrect")
	}
}

func TestEncrypt(t *testing.T) {
	state := NewState(wave)

	opt := &mqpb.JEDIOptions{
		PartitionSize: 2,
	}

	encrypted, err := state.Encrypt(&mqpb.PublishParams{
		Namespace: nshash,
		Uri:       "first/second",
		Content: []*mqpb.PayloadObject{
			&mqpb.PayloadObject{
				Schema:  "quote1",
				Content: []byte(quote1),
			},
			&mqpb.PayloadObject{
				Schema:  "quote2",
				Content: []byte(quote2),
			},
		},
		JediOptions: opt,
	})
	if err != nil {
		panic(err)
	}

	decrypted, err := state.Decrypt(targetpbpersp, opt, encrypted)
	if err != nil {
		panic(err)
	}

	if len(decrypted) != 2 {
		t.Fatal("Number of payload objects changed after encryption and decryption")
	}

	if decrypted[0].Schema != "quote1" || string(decrypted[0].Content) != quote1 {
		t.Log("First payload object is different after encryption and decryption")
		t.Fail()
	}

	if decrypted[1].Schema != "quote2" || string(decrypted[1].Content) != quote2 {
		t.Log("Second payload object is different after encryption and decryption")
		t.Fail()
	}
}
