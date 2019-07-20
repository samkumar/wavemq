package jedi

import (
	"fmt"
	"os"
	"testing"

	"github.com/immesys/wave/eapi"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/localdb/lls"
	"github.com/immesys/wave/localdb/poc"
	"github.com/immesys/wave/storage/overlay"
	"github.com/immesys/wave/waved"
)

var wave *eapi.EAPI

func TestMain(m *testing.M) {
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
	os.Exit(m.Run())
}

func TestParseURI(t *testing.T) {
	uri := "first/second/third"
	parsed, err := parseURI(uri)
	if err != nil {
		panic(err)
	}
	if !(string(parsed[0]) == "first" && string(parsed[1]) == "second" && string(parsed[2]) == "third") {
		t.Fatal("Parsed URI is incorrect")
	}
}
