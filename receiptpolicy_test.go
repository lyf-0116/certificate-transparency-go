package ct

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/tls"
)

type rpLog struct {
	priv *ecdsa.PrivateKey
	pub  crypto.PublicKey
	id   LogID
	name string
}

func rpNewLog(t *testing.T, name string) rpLog {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(%q): %v", name, err)
	}
	id, err := LogIDFromPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("LogIDFromPublicKey(%q): %v", name, err)
	}
	return rpLog{priv: priv, pub: &priv.PublicKey, id: id, name: name}
}

func rpPolicy(t *testing.T, logs ...rpLog) *ReceiptPolicy {
	t.Helper()
	keys := make([]crypto.PublicKey, 0, len(logs))
	for _, log := range logs {
		keys = append(keys, log.pub)
	}
	policy, err := NewReceiptPolicy(keys...)
	if err != nil {
		t.Fatalf("NewReceiptPolicy: %v", err)
	}
	for _, log := range logs {
		trusted := policy.Logs[SHA256Hash(log.id.KeyID)]
		if trusted == nil {
			t.Fatalf("log %q missing from policy map", log.name)
		}
		trusted.Name = log.name
	}
	return policy
}

// rpSignAs builds an SCT claiming claimedID and signs its serialized
// CertificateTimestamp with signer. It mirrors how a real log produces an SCT.
func rpSignAs(t *testing.T, entry LogEntry, claimedID LogID, signer rpLog, ts time.Time) *Receipt {
	t.Helper()
	sct := &Receipt{
		SCTVersion: V1,
		LogID:      claimedID,
		Timestamp:  uint64(ts.UnixMilli()),
	}
	data, err := SerializeSCTSignatureInput(*sct, entry)
	if err != nil {
		t.Fatalf("SerializeSCTSignatureInput: %v", err)
	}
	digitallySigned, err := tls.CreateSignature(*signer.priv, tls.SHA256, data)
	if err != nil {
		t.Fatalf("CreateSignature: %v", err)
	}
	sct.Signature = DigitallySigned(digitallySigned)
	return sct
}

func rpReceipt(t *testing.T, entry LogEntry, log rpLog, ts time.Time) *Receipt {
	t.Helper()
	return rpSignAs(t, entry, log.id, log, ts)
}

func rpTamper(receipt *Receipt) *Receipt {
	if len(receipt.Signature.Signature) == 0 {
		panic("cannot tamper empty signature")
	}
	receipt.Signature.Signature[0] ^= 0x01
	return receipt
}

func TestReceiptLogIDMatchesRepositoryVector(t *testing.T) {
	id, err := LogIDFromPublicKey(sigTestECPublicKey(t))
	if err != nil {
		t.Fatalf("LogIDFromPublicKey: %v", err)
	}
	if got := encodeHexID(id); got != sigTestKeyIDEC {
		t.Fatalf("LogIDFromPublicKey = %q, want repository vector %q", got, sigTestKeyIDEC)
	}
}

func encodeHexID(id LogID) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(id.KeyID)*2)
	for _, b := range id.KeyID {
		out = append(out, hexdigits[b>>4], hexdigits[b&0x0f])
	}
	return string(out)
}

func TestVerifyReceiptSinglePublicKeyTier(t *testing.T) {
	entry := sigTestCertLogEntry(t)
	log := rpNewLog(t, "single")
	ts := time.Date(2024, time.March, 1, 12, 0, 0, 0, time.UTC)
	good := rpReceipt(t, entry, log, ts)

	if err := VerifyReceipt(entry, good, log.pub); err != nil {
		t.Fatalf("VerifyReceipt(good) returned error: %v", err)
	}
	if err := VerifyReceipt(entry, nil, log.pub); err == nil {
		t.Fatal("VerifyReceipt(nil) = nil, want error")
	}
	bad := rpTamper(rpReceipt(t, entry, log, ts))
	if err := VerifyReceipt(entry, bad, log.pub); err == nil {
		t.Fatal("VerifyReceipt(tampered) = nil, want signature error")
	}

	// Pubkey-only batch entry point degrades to one-valid-receipt behavior.
	result, err := VerifyReceipts(entry, []*Receipt{good}, log.pub)
	if err != nil {
		t.Fatalf("VerifyReceipts: %v", err)
	}
	if !result.Satisfied || result.Required != 1 || result.Valid != 1 || result.Gap != 0 {
		t.Fatalf("default result = %+v, want satisfied 1/1 gap 0", result)
	}
}

func TestReceiptPolicyRequiresDistinctLogsAndReportsGap(t *testing.T) {
	entry := sigTestCertLogEntry(t)
	a := rpNewLog(t, "a")
	b := rpNewLog(t, "b")
	c := rpNewLog(t, "c")

	notBefore := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	validity := ReceiptValidity{NotBefore: notBefore, NotAfter: notBefore.Add(90 * 24 * time.Hour)}
	ts := notBefore.Add(time.Hour)

	policy := rpPolicy(t, a, b, c).Require(3)

	two, err := policy.Verify(entry, []*Receipt{
		rpReceipt(t, entry, a, ts),
		rpReceipt(t, entry, b, ts.Add(time.Minute)),
	}, validity)
	if !errors.Is(err, ErrPolicyNotSatisfied) {
		t.Fatalf("two-log err = %v, want ErrPolicyNotSatisfied", err)
	}
	if errors.Is(err, ErrReceiptSignature) {
		t.Fatalf("two-log err unexpectedly matches ErrReceiptSignature: %v", err)
	}
	if two.Satisfied || two.Required != 3 || two.Valid != 2 || two.Gap != 1 {
		t.Fatalf("two-log report = {sat:%v req:%d valid:%d gap:%d}, want false/3/2/1",
			two.Satisfied, two.Required, two.Valid, two.Gap)
	}
	if len(two.SignatureFailures) != 0 {
		t.Fatalf("SignatureFailures = %d, want 0", len(two.SignatureFailures))
	}

	three, err := policy.Verify(entry, []*Receipt{
		rpReceipt(t, entry, a, ts),
		rpReceipt(t, entry, b, ts.Add(time.Minute)),
		rpReceipt(t, entry, c, ts.Add(2*time.Minute)),
	}, validity)
	if err != nil {
		t.Fatalf("three-log Verify error: %v", err)
	}
	if !three.Satisfied || three.Valid != 3 || three.Gap != 0 {
		t.Fatalf("three-log report = {sat:%v valid:%d gap:%d}, want true/3/0",
			three.Satisfied, three.Valid, three.Gap)
	}
}

func TestReceiptPolicyCountsEachLogOnce(t *testing.T) {
	entry := sigTestCertLogEntry(t)
	a := rpNewLog(t, "a")
	b := rpNewLog(t, "b")
	notBefore := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	validity := ReceiptValidity{NotBefore: notBefore}

	policy := rpPolicy(t, a, b).Require(2)
	a1 := rpReceipt(t, entry, a, notBefore.Add(time.Hour))
	a2 := rpReceipt(t, entry, a, notBefore.Add(2*time.Hour))

	oneLog, err := policy.Verify(entry, []*Receipt{a1, a2}, validity)
	if !errors.Is(err, ErrPolicyNotSatisfied) {
		t.Fatalf("duplicate-only err = %v, want policy error", err)
	}
	if oneLog.Valid != 1 || oneLog.Gap != 1 {
		t.Fatalf("duplicate-only valid/gap = %d/%d, want 1/1", oneLog.Valid, oneLog.Gap)
	}
	if len(oneLog.Duplicates) != 1 || oneLog.Duplicates[0].Issue != IssueDuplicateLog {
		t.Fatalf("Duplicates = %+v, want one IssueDuplicateLog", oneLog.Duplicates)
	}

	b1 := rpReceipt(t, entry, b, notBefore.Add(3*time.Hour))
	withB, err := policy.Verify(entry, []*Receipt{
		rpReceipt(t, entry, a, notBefore.Add(time.Hour)),
		rpReceipt(t, entry, a, notBefore.Add(2*time.Hour)),
		b1,
	}, validity)
	if err != nil {
		t.Fatalf("a,a,b Verify error: %v", err)
	}
	if !withB.Satisfied || withB.Valid != 2 {
		t.Fatalf("a,a,b satisfied=%v valid=%d, want true/2", withB.Satisfied, withB.Valid)
	}
	if len(withB.Duplicates) != 1 {
		t.Fatalf("Duplicates = %d, want 1", len(withB.Duplicates))
	}
}

func TestReceiptPolicySeparatesUnknownLogAndBadSignature(t *testing.T) {
	entry := sigTestCertLogEntry(t)
	a := rpNewLog(t, "a")
	b := rpNewLog(t, "b")
	outsider := rpNewLog(t, "outsider")
	ts := time.Date(2024, time.June, 1, 0, 0, 0, 0, time.UTC)

	policy := rpPolicy(t, a, b).Require(2)

	// Receipt from a log that is not on the recognized list.
	unknown, err := policy.Verify(entry, []*Receipt{
		rpReceipt(t, entry, a, ts),
		rpReceipt(t, entry, outsider, ts.Add(time.Minute)),
	}, ReceiptValidity{})
	if err == nil || !errors.Is(err, ErrPolicyNotSatisfied) {
		t.Fatalf("unknown-log err = %v, want policy error", err)
	}
	if errors.Is(err, ErrReceiptSignature) {
		t.Fatalf("unknown-log err matches signature sentinel: %v", err)
	}
	if len(unknown.Unrecognized) != 1 || unknown.Unrecognized[0].Issue != IssueUnknownLog {
		t.Fatalf("Unrecognized = %+v, want one IssueUnknownLog", unknown.Unrecognized)
	}
	if len(unknown.SignatureFailures) != 0 {
		t.Fatalf("SignatureFailures = %d for unknown log, want 0", len(unknown.SignatureFailures))
	}
	if unknown.Valid != 1 || unknown.Gap != 1 {
		t.Fatalf("unknown-log valid/gap = %d/%d, want 1/1", unknown.Valid, unknown.Gap)
	}

	// Recognized LogID but a tampered signature: cryptographic failure bucket.
	badB := rpTamper(rpReceipt(t, entry, b, ts))
	sigResult, sigErr := policy.Verify(entry, []*Receipt{
		rpReceipt(t, entry, a, ts),
		badB,
	}, ReceiptValidity{})
	if len(sigResult.SignatureFailures) != 1 {
		t.Fatalf("SignatureFailures = %d, want 1", len(sigResult.SignatureFailures))
	}
	if sigResult.SignatureFailures[0].Issue != IssueBadSignature {
		t.Fatalf("issue = %q, want %q", sigResult.SignatureFailures[0].Issue, IssueBadSignature)
	}
	if sigResult.SignatureError() == nil || !errors.Is(sigResult.SignatureError(), ErrReceiptSignature) {
		t.Fatalf("SignatureError = %v, want ErrReceiptSignature", sigResult.SignatureError())
	}
	if !errors.Is(sigErr, ErrReceiptSignature) || !errors.Is(sigErr, ErrPolicyNotSatisfied) {
		t.Fatalf("combined err = %v, want both signature and policy sentinels", sigErr)
	}
	var sigTyped *SignatureVerificationError
	if !errors.As(sigErr, &sigTyped) {
		t.Fatalf("errors.As missing *SignatureVerificationError in %v", sigErr)
	}
	var policyTyped *PolicyNotSatisfiedError
	if !errors.As(sigErr, &policyTyped) || policyTyped.Gap != 1 {
		t.Fatalf("errors.As policy error/gap wrong in %v", sigErr)
	}

	// Policy met despite one extra bad receipt: compliance and signature
	// reporting stay independent.
	lenient := rpPolicy(t, a, b).Require(1)
	met, metErr := lenient.Verify(entry, []*Receipt{
		rpReceipt(t, entry, a, ts),
		rpTamper(rpReceipt(t, entry, b, ts.Add(time.Minute))),
	}, ReceiptValidity{})
	if !met.Satisfied {
		t.Fatal("lenient policy should be satisfied by the single good receipt")
	}
	if len(met.SignatureFailures) != 1 {
		t.Fatalf("SignatureFailures = %d, want 1", len(met.SignatureFailures))
	}
	if metErr == nil || !errors.Is(metErr, ErrReceiptSignature) || errors.Is(metErr, ErrPolicyNotSatisfied) {
		t.Fatalf("met-with-bad-sig err = %v, want signature-only error", metErr)
	}
}

func TestReceiptPolicyFallbackForMismatchedLogID(t *testing.T) {
	entry := sigTestCertLogEntry(t)
	a := rpNewLog(t, "a")
	policy := rpPolicy(t, a).Require(1)

	// Hand-built receipt carries a zero LogID but is signed by recognized key a.
	mislabeled := rpSignAs(t, entry, LogID{}, a, time.Date(2024, time.May, 1, 0, 0, 0, 0, time.UTC))
	result, err := policy.Verify(entry, []*Receipt{mislabeled}, ReceiptValidity{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	check := result.Checks[0]
	if !check.SignatureOK || !check.Recognized || !check.Counts {
		t.Fatalf("mismatched-id check = %+v, want verified/recognized/counting", check)
	}
	if check.LogID != a.id {
		t.Fatal("receipt should be re-attributed to the key that verified it")
	}
}

func TestReceiptPolicyLifetimeTiers(t *testing.T) {
	entry := sigTestCertLogEntry(t)
	a := rpNewLog(t, "a")
	b := rpNewLog(t, "b")
	c := rpNewLog(t, "c")

	jan := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	short := ReceiptValidity{NotBefore: jan, NotAfter: jan.Add(90 * 24 * time.Hour)}
	long := ReceiptValidity{NotBefore: jan, NotAfter: jan.Add(400 * 24 * time.Hour)}

	policy := rpPolicy(t, a, b, c).RequireLifetimeTiers(
		LifetimeTier{Name: "up-to-180-days", MaxLifetime: 180 * 24 * time.Hour, MinLogs: 2},
		LifetimeTier{Name: "longer-lived", MaxLifetime: 0, MinLogs: 3},
	)

	if n, tier := policy.RequiredCount(short); n != 2 || tier != "up-to-180-days" {
		t.Fatalf("short count/tier = %d/%q, want 2/up-to-180-days", n, tier)
	}
	if n, tier := policy.RequiredCount(long); n != 3 || tier != "longer-lived" {
		t.Fatalf("long count/tier = %d/%q, want 3/longer-lived", n, tier)
	}

	ts := jan.Add(time.Hour)
	twoLong, err := policy.Verify(entry, []*Receipt{
		rpReceipt(t, entry, a, ts),
		rpReceipt(t, entry, b, ts.Add(time.Minute)),
	}, long)
	if !errors.Is(err, ErrPolicyNotSatisfied) {
		t.Fatalf("long/two err = %v, want policy error", err)
	}
	if twoLong.Required != 3 || twoLong.Valid != 2 || twoLong.Gap != 1 || twoLong.Tier != "longer-lived" {
		t.Fatalf("long/two = req %d valid %d gap %d tier %q", twoLong.Required, twoLong.Valid, twoLong.Gap, twoLong.Tier)
	}

	threeLong, err := policy.Verify(entry, []*Receipt{
		rpReceipt(t, entry, a, ts),
		rpReceipt(t, entry, b, ts.Add(time.Minute)),
		rpReceipt(t, entry, c, ts.Add(2*time.Minute)),
	}, long)
	if err != nil || !threeLong.Satisfied {
		t.Fatalf("long/three satisfied=%v err=%v, want true/nil", threeLong.Satisfied, err)
	}

	twoShort, err := policy.Verify(entry, []*Receipt{
		rpReceipt(t, entry, a, ts),
		rpReceipt(t, entry, b, ts.Add(time.Minute)),
	}, short)
	if err != nil || !twoShort.Satisfied {
		t.Fatalf("short/two satisfied=%v err=%v, want true/nil", twoShort.Satisfied, err)
	}
}

func TestReceiptPolicyCountForCalendarRule(t *testing.T) {
	a := rpNewLog(t, "a")
	policy := rpPolicy(t, a).Require(1)
	policy.CountFor = func(v ReceiptValidity) int {
		if !v.NotBefore.IsZero() && v.NotBefore.Year() >= 2025 {
			return 2
		}
		return -1 // fall through to MinLogs
	}

	if n, _ := policy.RequiredCount(ReceiptValidity{NotBefore: time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)}); n != 2 {
		t.Fatalf("2025 count = %d, want 2", n)
	}
	if n, _ := policy.RequiredCount(ReceiptValidity{NotBefore: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)}); n != 1 {
		t.Fatalf("2024 count = %d, want default 1", n)
	}
}

func TestReceiptPolicyTimeWindowNotBeforeOrdering(t *testing.T) {
	entry := sigTestCertLogEntry(t)
	a := rpNewLog(t, "a")
	notBefore := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(90 * 24 * time.Hour)
	validity := ReceiptValidity{NotBefore: notBefore, NotAfter: notAfter}

	strict := rpPolicy(t, a).Require(1).WithWindow(TimeWindow{CheckNotBeforeOrder: true})

	cases := []struct {
		name       string
		ts         time.Time
		wantCount  bool
		wantTiming ReceiptTiming
	}{
		{"one second before", notBefore.Add(-time.Second), false, TimingBeforeNotBefore},
		{"exactly not-before", notBefore, true, TimingAtNotBefore},
		{"one hour after", notBefore.Add(time.Hour), true, TimingAfterNotBefore},
	}
	for _, tc := range cases {
		t.Run("strict/"+tc.name, func(t *testing.T) {
			result, _ := strict.Verify(entry, []*Receipt{rpReceipt(t, entry, a, tc.ts)}, validity)
			gotCount := result.Valid == 1 && result.Satisfied
			if gotCount != tc.wantCount {
				t.Fatalf("count=%v want %v (valid=%d satisfied=%v issue=%q)",
					gotCount, tc.wantCount, result.Valid, result.Satisfied, result.Checks[0].Issue)
			}
			if result.Checks[0].Timing != tc.wantTiming {
				t.Fatalf("timing=%q want %q", result.Checks[0].Timing, tc.wantTiming)
			}
		})
	}

	grace := rpPolicy(t, a).Require(1).WithWindow(TimeWindow{
		CheckNotBeforeOrder: true,
		AllowEarly:          time.Hour,
	})
	for _, tc := range []struct {
		name      string
		offset    time.Duration
		wantCount bool
	}{
		{"30m early inside grace", -30 * time.Minute, true},
		{"exactly grace boundary", -time.Hour, true},
		{"2h early outside grace", -2 * time.Hour, false},
	} {
		t.Run("grace/"+tc.name, func(t *testing.T) {
			ts := notBefore.Add(tc.offset)
			result, _ := grace.Verify(entry, []*Receipt{rpReceipt(t, entry, a, ts)}, validity)
			if counted := result.Checks[0].Counts; counted != tc.wantCount {
				t.Fatalf("Counts=%v want %v issue=%q", counted, tc.wantCount, result.Checks[0].Issue)
			}
			if result.Checks[0].Timing != TimingBeforeNotBefore {
				t.Fatalf("early receipt timing=%q want before-not-before", result.Checks[0].Timing)
			}
		})
	}

	// A zero window imposes no restriction but still reports the ordering.
	noWindow := rpPolicy(t, a).Require(1)
	before := rpReceipt(t, entry, a, notBefore.Add(-24*time.Hour))
	result, err := noWindow.Verify(entry, []*Receipt{before}, validity)
	if err != nil || !result.Satisfied {
		t.Fatalf("zero window should accept pre-NotBefore receipt, satisfied=%v err=%v", result.Satisfied, err)
	}
	if result.Checks[0].Timing != TimingBeforeNotBefore {
		t.Fatalf("timing=%q want before-not-before even without enforcement", result.Checks[0].Timing)
	}
}

func TestReceiptPolicyTimeWindowNotAfterAndFuture(t *testing.T) {
	entry := sigTestCertLogEntry(t)
	a := rpNewLog(t, "a")
	notBefore := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(90 * 24 * time.Hour)

	upper := rpPolicy(t, a).Require(1).WithWindow(TimeWindow{CheckNotAfter: true})
	validity := ReceiptValidity{NotBefore: notBefore, NotAfter: notAfter}

	after, _ := upper.Verify(entry, []*Receipt{rpReceipt(t, entry, a, notAfter.Add(time.Minute))}, validity)
	if after.Checks[0].Counts || after.Checks[0].Issue != IssueOutsideWindow {
		t.Fatalf("post-NotAfter check = %+v, want outside window", after.Checks[0])
	}
	at, err := upper.Verify(entry, []*Receipt{rpReceipt(t, entry, a, notAfter)}, validity)
	if err != nil || !at.Satisfied {
		t.Fatalf("at-NotAfter should count, satisfied=%v err=%v", at.Satisfied, err)
	}

	now := notBefore.Add(40 * 24 * time.Hour)
	futurePolicy := rpPolicy(t, a).Require(1).WithWindow(TimeWindow{AllowFuture: 5 * time.Minute})
	futureValidity := ReceiptValidity{NotBefore: notBefore, NotAfter: notAfter, Now: now}

	tooFuture, _ := futurePolicy.Verify(entry, []*Receipt{rpReceipt(t, entry, a, now.Add(10*time.Minute))}, futureValidity)
	if tooFuture.Checks[0].Counts || tooFuture.Checks[0].Issue != IssueFutureTimestamp {
		t.Fatalf("future check = %+v, want future-timestamp", tooFuture.Checks[0])
	}
	nearFuture, err := futurePolicy.Verify(entry, []*Receipt{rpReceipt(t, entry, a, now.Add(time.Minute))}, futureValidity)
	if err != nil || !nearFuture.Satisfied {
		t.Fatalf("near-future should count, satisfied=%v err=%v", nearFuture.Satisfied, err)
	}
}

func TestReceiptPolicyDefaultDegradesToSingle(t *testing.T) {
	a := rpNewLog(t, "a")
	policy, err := NewReceiptPolicy(a.pub)
	if err != nil {
		t.Fatal(err)
	}
	if policy.MinLogs != 1 {
		t.Fatalf("MinLogs=%d want 1", policy.MinLogs)
	}
	if n, _ := policy.RequiredCount(ReceiptValidity{}); n != 1 {
		t.Fatalf("RequiredCount=%d want 1", n)
	}
	var zero ReceiptPolicy
	if n, _ := zero.RequiredCount(ReceiptValidity{}); n != 1 {
		t.Fatalf("zero policy RequiredCount=%d want 1", n)
	}
}

func TestReceiptPolicyDistinguishesAuditorsFromSelfBuiltLog(t *testing.T) {
	entry := sigTestCertLogEntry(t)
	ts := time.Date(2024, time.August, 1, 0, 0, 0, 0, time.UTC)

	auditor1 := rpNewLog(t, "auditor-1")
	auditor2 := rpNewLog(t, "auditor-2")
	auditor3 := rpNewLog(t, "auditor-3")
	auditPolicy := rpPolicy(t, auditor1, auditor2, auditor3).Named("three-auditors").Require(3)
	auditResult, err := auditPolicy.Verify(entry, []*Receipt{
		rpReceipt(t, entry, auditor1, ts),
		rpReceipt(t, entry, auditor2, ts.Add(time.Minute)),
		rpReceipt(t, entry, auditor3, ts.Add(2*time.Minute)),
	}, ReceiptValidity{})
	if err != nil {
		t.Fatalf("audit Verify: %v", err)
	}

	selfBuilt := rpNewLog(t, "self-built")
	selfPolicy := rpPolicy(t, selfBuilt).Named("self-built").Require(1)
	selfResult, err := selfPolicy.Verify(entry, []*Receipt{
		rpReceipt(t, entry, selfBuilt, ts),
	}, ReceiptValidity{})
	if err != nil {
		t.Fatalf("self Verify: %v", err)
	}

	if auditResult.Required == selfResult.Required || auditResult.Valid == selfResult.Valid {
		t.Fatalf("policies indistinguishable: audit req/valid=%d/%d self req/valid=%d/%d",
			auditResult.Required, auditResult.Valid, selfResult.Required, selfResult.Valid)
	}
	if auditResult.Required != 3 || auditResult.Valid != 3 {
		t.Fatalf("audit req/valid=%d/%d want 3/3", auditResult.Required, auditResult.Valid)
	}
	if selfResult.Required != 1 || selfResult.Valid != 1 {
		t.Fatalf("self req/valid=%d/%d want 1/1", selfResult.Required, selfResult.Valid)
	}
}

func TestReceiptPolicyReportsMissingLogs(t *testing.T) {
	entry := sigTestCertLogEntry(t)
	a := rpNewLog(t, "a")
	b := rpNewLog(t, "b")
	c := rpNewLog(t, "c")
	policy := rpPolicy(t, a, b, c).Require(3)

	result, _ := policy.Verify(entry, []*Receipt{
		rpReceipt(t, entry, a, time.Date(2024, time.September, 1, 0, 0, 0, 0, time.UTC)),
	}, ReceiptValidity{})

	if len(result.MissingLogs) != 2 {
		t.Fatalf("MissingLogs=%v, want b and c", result.MissingLogs)
	}
	if result.MissingLogs[0] != "b" || result.MissingLogs[1] != "c" {
		t.Fatalf("MissingLogs=%v, want sorted [b c]", result.MissingLogs)
	}
}

func TestReceiptPolicyAbsoluteWindow(t *testing.T) {
	entry := sigTestCertLogEntry(t)
	a := rpNewLog(t, "a")

	start := time.Date(2024, time.March, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(30 * 24 * time.Hour)
	policy := rpPolicy(t, a).Require(1).WithWindow(TimeWindow{Start: start, End: end})

	cases := []struct {
		name string
		ts   time.Time
		want bool
	}{
		{"before start", start.Add(-time.Second), false},
		{"at start", start, true},
		{"inside", start.Add(10 * 24 * time.Hour), true},
		{"at end", end, true},
		{"after end", end.Add(time.Second), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, _ := policy.Verify(entry, []*Receipt{rpReceipt(t, entry, a, tc.ts)}, ReceiptValidity{})
			if got := result.Checks[0].Counts; got != tc.want {
				t.Fatalf("Counts=%v want %v issue=%q", got, tc.want, result.Checks[0].Issue)
			}
		})
	}
}
