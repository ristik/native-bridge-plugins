// Run from the pinned aggregator-go checkout: this links its SDK3 leaf/path code.
// Certificates are synthetic. This does not start a service or authenticate a deployment.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/unicitynetwork/aggregator-go/pkg/api"
)

type path struct{ Name, Sid, TxHash, T, Value, Root, Certificate, Proof string }

func hx(s string) []byte { b, err := hex.DecodeString(s); must(err); return b }
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func need(ok bool, name string) {
	if !ok {
		panic(name)
	}
}
func main() {
	b, err := os.ReadFile(os.Args[1])
	must(err)
	var input struct{ Paths []path }
	must(json.Unmarshal(b, &input))
	need(len(input.Paths) >= 9, "missing joined paths")
	for _, p := range input.Paths {
		sid, tx, root := hx(p.Sid), hx(p.TxHash), hx(p.Root)
		t, err := strconv.ParseUint(p.T, 10, 64)
		must(err)
		value := api.LeafValue(tx, t)
		need(bytes.Equal(value, hx(p.Value)), p.Name+": SDK3 leaf drift")
		var cert api.InclusionCert
		must(cert.UnmarshalBinary(hx(p.Certificate)))
		must(cert.Verify(sid, value, root, api.SHA256))
		var proof api.InclusionProofV2
		must(proof.UnmarshalCBOR(hx(p.Proof)))
		need(proof.ReferenceTime != nil && *proof.ReferenceTime == t, "proof lost referenceTime")
		need(bytes.Equal(proof.CertificationData.TransactionHash.DataBytes(), tx), "proof txHash drift")
		need(bytes.Equal(proof.CertificateBytes, hx(p.Certificate)), "proof path drift")
		wire, err := proof.MarshalCBOR()
		must(err)
		need(bytes.Equal(wire, hx(p.Proof)), "SDK/aggregator proof codec drift")
		// Each mutation is independent and must hit the exported sentinel.
		need(errors.Is(cert.Verify(sid, tx, root, api.SHA256), api.ErrCertRootMismatch), "txHash-as-value accepted")
		need(errors.Is(cert.Verify(sid, api.LeafValue(tx, t+1), root, api.SHA256), api.ErrCertRootMismatch), "changed time accepted")
		wrong := bytes.Clone(root)
		wrong[0] ^= 1
		need(errors.Is(cert.Verify(sid, value, wrong, api.SHA256), api.ErrCertRootMismatch), "wrong root accepted")
		fmt.Printf("PASS %s: SDK codec, leaf, membership; 3 isolated sentinel rejections\n", p.Name)
	}
}
