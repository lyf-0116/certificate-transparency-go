package ct_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
)

// externalLog bundles a generated key with its RFC 6962 id.
type externalLog struct {
	priv *ecdsa.PrivateKey
	id   ct.LogID
}

func newExternalLog(t *testing.T) externalLog {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	id, err := ct.LogIDFromPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("LogIDFromPublicKey: %v", err)
	}
	return externalLog{priv: priv, id: id}
}

// externalEntry builds an entry whose certificate bytes are arbitrary: SCT
// signature verification only signs the serialized entry, it never parses the
// certificate, so policy logic can be exercised without a real chain.
func externalEntry() ct.LogEntry {
	return ct.LogEntry{
		Leaf: ct.MerkleTreeLeaf{
			Version:  ct.V1,
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: &ct.TimestampedEntry{
				EntryType: ct.X509LogEntryType,
				X509Entry: &ct.ASN1Cert{Data: []byte("policy-probe-cert-bytes")},
			},
		},
	}
}

func signExternalSCT(t *testing.T, entry ct.LogEntry, log externalLog, ts time.Time) *ct.SignedCertificateTimestamp {
	t.Helper()
	sct := &ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      log.id,
		Timestamp:  uint64(ts.UnixMilli()),
	}
	data, err := ct.SerializeSCTSignatureInput(*sct, entry)
	if err != nil {
		t.Fatalf("SerializeSCTSignatureInput: %v", err)
	}
	sig, err := tls.CreateSignature(*log.priv, tls.SHA256, data)
	if err != nil {
		t.Fatalf("CreateSignature: %v", err)
	}
	sct.Signature = ct.DigitallySigned(sig)
	return sct
}

// TestReceiptPolicyExternalProbe demonstrates the full API from outside
// package ct, mirroring what a standalone verification probe can do.
func TestReceiptPolicyExternalProbe(t *testing.T) {
	entry := externalEntry()
	a := newExternalLog(t)
	b := newExternalLog(t)
	now := time.Date(2024, time.May, 1, 0, 0, 0, 0, time.UTC)

	// Pubkey-only default: a single valid receipt is enough.
	defaultPolicy, err := ct.NewReceiptPolicy(&a.priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	one, err := defaultPolicy.Verify(entry, []*ct.Receipt{signExternalSCT(t, entry, a, now)}, ct.ReceiptValidity{})
	if err != nil || !one.Satisfied {
		t.Fatalf("default verify satisfied=%v err=%v", one.Satisfied, err)
	}

	// Two-log policy with one valid + one tampered: policy gap and signature
	// failure are both reported, yet separable.
	policy, err := ct.NewReceiptPolicy(&a.priv.PublicKey, &b.priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	policy.Require(2).WithWindow(ct.TimeWindow{CheckNotBeforeOrder: true})

	notBefore := now.Add(-time.Hour)
	validity := ct.ReceiptValidity{NotBefore: notBefore, NotAfter: notBefore.Add(400 * 24 * time.Hour)}

	good := signExternalSCT(t, entry, a, now)
	bad := signExternalSCT(t, entry, b, now)
	bad.Signature.Signature[0] ^= 0xff

	result, err := policy.Verify(entry, []*ct.Receipt{good, bad}, validity)
	if result.Satisfied || result.Required != 2 || result.Valid != 1 || result.Gap != 1 {
		t.Fatalf("report = sat:%v req:%d valid:%d gap:%d", result.Satisfied, result.Required, result.Valid, result.Gap)
	}
	if len(result.SignatureFailures) != 1 {
		t.Fatalf("SignatureFailures=%d want 1", len(result.SignatureFailures))
	}
	if !errors.Is(err, ct.ErrPolicyNotSatisfied) || !errors.Is(err, ct.ErrReceiptSignature) {
		t.Fatalf("err=%v want both sentinels", err)
	}

	// Lifetime tier raises the requirement to 3 for the long-lived cert.
	tiered, err := ct.NewReceiptPolicy(&a.priv.PublicKey, &b.priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tiered.RequireLifetimeTiers(
		ct.LifetimeTier{MaxLifetime: 180 * 24 * time.Hour, MinLogs: 2},
		ct.LifetimeTier{MaxLifetime: 0, MinLogs: 3},
	)
	if n, _ := tiered.RequiredCount(validity); n != 3 {
		t.Fatalf("long-lived RequiredCount=%d want 3", n)
	}
}
