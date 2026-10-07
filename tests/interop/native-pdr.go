//go:build ignore

// Run from bft-core 8745b71942eb7d81d89e4142baf5eae30e34a14d with:
// GOMAXPROCS=4 go run -p 4 /absolute/path/to/tests/interop/native-pdr.go
// This independent native-codec regression fixture is not the canonical PR2 corpus.
package main

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-go-base/types"
)

func main() {
	key, err := hex.DecodeString("032160ecd85a90d96d47d90b5aea50355361e20b33b51d9b596483538ecbd02d12")
	if err != nil {
		panic(err)
	}
	p := types.PartitionDescriptionRecord{
		Version: 1, NetworkID: 3, PartitionID: 7, ShardID: types.ShardID{},
		PartitionTypeID: 1, TypeIDLen: 0, UnitIDLen: 256,
		SummaryTrustBase: []byte{}, T2Timeout: 2_500_000_000,
		PartitionParams: map[string]string{"chainId": "7777"}, Epoch: 5,
		Validators: []*types.NodeInfo{{NodeID: "evm-1", SigKey: key, Stake: 1}},
	}
	native, err := types.Cbor.Marshal(&p)
	if err != nil {
		panic(err)
	}
	full, err := p.Hash(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	cfg, err := evmassign.ConfigHash(&p)
	if err != nil {
		panic(err)
	}
	p.Epoch, p.EpochStart, p.Validators = 0, 0, nil
	neutral, err := types.Cbor.Marshal(&p)
	if err != nil {
		panic(err)
	}
	v := map[string]string{
		"native": hex.EncodeToString(native), "fullHash": hex.EncodeToString(full),
		"neutralized": hex.EncodeToString(neutral), "configHash": hex.EncodeToString(cfg[:]),
		"source": "bft-go-base v1.1.1-0.20260421100318-01ab63a83bf5; bft-core 8745b71942eb7d81d89e4142baf5eae30e34a14d evmassign.ConfigHash",
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
}
