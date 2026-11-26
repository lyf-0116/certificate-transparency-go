package ct

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/certificate-transparency-go/x509"
)

// Receipt is a Certificate Transparency receipt, i.e. a Signed Certificate
// Timestamp (SCT). It is the per-log promise that a certificate or
// pre-certificate was submitted to that log.
//
// The alias exists so callers describing receipt verification and callers
// using the historical SCT terminology refer to the same type.
type Receipt = SignedCertificateTimestamp

// Sentinel errors that let callers tell a policy shortfall apart from a
// cryptographic signature failure with errors.Is.
var (
	// ErrReceiptSignature is wrapped by SignatureVerificationError when at
	// least one receipt claiming to come from a recognized log fails
	// signature verification.
	ErrReceiptSignature = errors.New("ct: receipt signature verification failed")

	// ErrPolicyNotSatisfied is wrapped by PolicyNotSatisfiedError when the
	// set of cryptographically valid, recognized, in-window receipts does
	// not meet the policy's required number of distinct logs.
	ErrPolicyNotSatisfied = errors.New("ct: receipt policy not satisfied")
)

// LogIDFromPublicKey returns the RFC 6962 log identifier for a log public
// key: SHA-256 over the DER encoding of the SubjectPublicKeyInfo. This is the
// same value that appears in SignedCertificateTimestamp.LogID.
func LogIDFromPublicKey(pub crypto.PublicKey) (LogID, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return LogID{}, fmt.Errorf("ct: marshal public key for log id: %w", err)
	}
	return LogID{KeyID: sha256.Sum256(der)}, nil
}

// TrustedLog is a log that a ReceiptPolicy recognizes: its identity and the
// verifier used to check receipts signed by it.
type TrustedLog struct {
	// ID is the log's RFC 6962 LogID.
	ID LogID
	// Name is an optional human readable label used in reports.
	Name string
	// Verifier checks signatures produced by the log.
	Verifier *SignatureVerifier
}

// NewTrustedLog builds a recognized log from its label and public key,
// deriving ID with LogIDFromPublicKey and validating the key for CT use.
func NewTrustedLog(name string, pub crypto.PublicKey) (*TrustedLog, error) {
	id, err := LogIDFromPublicKey(pub)
	if err != nil {
		return nil, err
	}
	verifier, err := NewSignatureVerifier(pub)
	if err != nil {
		return nil, err
	}
	return &TrustedLog{ID: id, Name: name, Verifier: verifier}, nil
}

// ReceiptIssue explains why a single receipt did not count towards a policy.
// The empty value means the receipt counted without any issue.
type ReceiptIssue string

const (
	// IssueOK marks a receipt that counted towards the policy.
	IssueOK ReceiptIssue = ""
	// IssueNilReceipt marks a nil entry in the receipt slice.
	IssueNilReceipt ReceiptIssue = "nil-receipt"
	// IssueUnknownLog marks a receipt whose LogID is not on the recognized
	// log list (and whose signature does not verify under any listed key).
	IssueUnknownLog ReceiptIssue = "unrecognized-log"
	// IssueBadSignature marks a receipt from a recognized log whose
	// signature did not verify.
	IssueBadSignature ReceiptIssue = "bad-signature"
	// IssueOutsideWindow marks a valid signature whose timestamp falls
	// outside the policy TimeWindow.
	IssueOutsideWindow ReceiptIssue = "outside-time-window"
	// IssueFutureTimestamp marks a receipt timestamp too far ahead of the
	// verification clock.
	IssueFutureTimestamp ReceiptIssue = "future-timestamp"
	// IssueDuplicateLog marks a second or later valid receipt from a log
	// that already contributed one counted receipt.
	IssueDuplicateLog ReceiptIssue = "duplicate-log"
)

// ReceiptTiming locates a receipt timestamp relative to the certificate's
// NotBefore (its moment of validity). CT pre-certificate receipts are often
// minted shortly before NotBefore, so the ordering is reported explicitly
// instead of being collapsed into a generic pass/fail.
type ReceiptTiming string

const (
	// TimingUnknown means no NotBefore was supplied, so ordering is undefined.
	TimingUnknown ReceiptTiming = "unknown"
	// TimingBeforeNotBefore means the receipt timestamp is strictly before NotBefore.
	TimingBeforeNotBefore ReceiptTiming = "before-not-before"
	// TimingAtNotBefore means the receipt timestamp equals NotBefore.
	TimingAtNotBefore ReceiptTiming = "at-not-before"
	// TimingAfterNotBefore means the receipt timestamp is strictly after NotBefore.
	TimingAfterNotBefore ReceiptTiming = "after-not-before"
)

// ReceiptValidity carries the certificate time bounds used to select a
// lifetime tier and to evaluate the policy TimeWindow. The zero value means
// the bounds are unknown: tier selection falls back to ReceiptPolicy.MinLogs
// and certificate-relative window checks are skipped.
type ReceiptValidity struct {
	NotBefore time.Time
	NotAfter  time.Time
	// Now is the verification clock used for future-timestamp checks. The
	// zero value resolves to time.Now when needed.
	Now time.Time
}

// ValidityFromCertificate extracts the validity window of cert.
func ValidityFromCertificate(cert *x509.Certificate) ReceiptValidity {
	if cert == nil {
		return ReceiptValidity{}
	}
	return ReceiptValidity{NotBefore: cert.NotBefore, NotAfter: cert.NotAfter}
}

// LifetimeTier sets MinLogs for certificates whose lifetime
// (NotAfter - NotBefore) is at most MaxLifetime. Tiers are evaluated in slice
// order; the first matching tier wins. A tier with MaxLifetime <= 0 matches
// every lifetime and is therefore useful as the final catch-all for
// long-lived certificates.
//
// This is the extension point for rules such as "certificates valid for at
// most 180 days need two logs, longer-lived certificates need three".
type LifetimeTier struct {
	// Name is an optional label reported as ReceiptVerification.Tier.
	Name string
	// MaxLifetime is the inclusive lifetime upper bound; <= 0 means catch-all.
	MaxLifetime time.Duration
	// MinLogs is the required number of distinct recognized logs.
	MinLogs int
}

// TimeWindow binds a timestamp window to a ReceiptPolicy. The zero value
// enforces no certificate-relative restriction, so merely attaching a
// window never changes the default single-receipt behavior. Individual rules
// are switched on explicitly.
//
// The NotBefore rule makes the ordering between receipt submission time and
// certificate validity start observable: with CheckNotBeforeOrder and
// AllowEarly == 0 a receipt must not predate NotBefore; a positive
// AllowEarly tolerates the small lead time normal for pre-certificate SCTs.
type TimeWindow struct {
	// Start, when non-zero, is the inclusive earliest allowed receipt time.
	// It expresses an absolute window location ("时间窗起点").
	Start time.Time
	// End, when non-zero, is the inclusive latest allowed receipt time.
	End time.Time

	// CheckNotBeforeOrder enables the lower-bound check against NotBefore.
	CheckNotBeforeOrder bool
	// AllowEarly is the inclusive amount by which a receipt timestamp may
	// precede NotBefore and still count. Only used when CheckNotBeforeOrder.
	AllowEarly time.Duration
	// CheckNotAfter enables the inclusive upper-bound check against NotAfter.
	CheckNotAfter bool
	// AllowFuture, when positive, rejects timestamps more than this far in
	// the future relative to ReceiptValidity.Now (or time.Now).
	AllowFuture time.Duration
}

func (w TimeWindow) timing(ts time.Time, validity ReceiptValidity) ReceiptTiming {
	if validity.NotBefore.IsZero() {
		return TimingUnknown
	}
	switch {
	case ts.Before(validity.NotBefore):
		return TimingBeforeNotBefore
	case ts.Equal(validity.NotBefore):
		return TimingAtNotBefore
	default:
		return TimingAfterNotBefore
	}
}

// evaluate returns whether the timestamp is in window, the issue code when it
// is not, and its ordering relative to NotBefore.
func (w TimeWindow) evaluate(ts time.Time, validity ReceiptValidity) (bool, ReceiptIssue, ReceiptTiming) {
	timing := w.timing(ts, validity)

	if !w.Start.IsZero() && ts.Before(w.Start) {
		return false, IssueOutsideWindow, timing
	}
	if !w.End.IsZero() && ts.After(w.End) {
		return false, IssueOutsideWindow, timing
	}
	if w.CheckNotBeforeOrder && !validity.NotBefore.IsZero() {
		earliest := validity.NotBefore.Add(-w.AllowEarly)
		if ts.Before(earliest) { // earliest itself is allowed (inclusive)
			return false, IssueOutsideWindow, timing
		}
	}
	if w.CheckNotAfter && !validity.NotAfter.IsZero() && ts.After(validity.NotAfter) {
		return false, IssueOutsideWindow, timing
	}
	if w.AllowFuture > 0 {
		now := validity.Now
		if now.IsZero() {
			now = time.Now()
		}
		if ts.After(now.Add(w.AllowFuture)) {
			return false, IssueFutureTimestamp, timing
		}
	}
	return true, IssueOK, timing
}

// ReceiptPolicy is the verification-side policy layer: which logs are
// recognized, how many distinct logs are required (possibly depending on
// certificate lifetime), and the timestamp window receipts must fall in.
//
// It maps directly to the three policy concepts in the task: Logs is the
// recognized-log list (认可的日志清单), RequiredCount/MinLogs/LifetimeTiers
// are the required number of distinct logs (最少家数, including different
// counts for different validity lifetimes), and Window is the bound time
// window (与策略绑定的时间窗). ReceiptVerification.Gap reports the missing
// count (缺口), while ReceiptVerification.SignatureFailures keeps signature
// failures (签名失败) separate from policy non-compliance (不满足策略).
//
// The zero value and NewReceiptPolicy() both degrade to the historical
// single-tier behavior: one validly signed receipt from any supplied public
// key is sufficient, with no lifetime or window restriction.
type ReceiptPolicy struct {
	// Name labels the policy in reports and errors.
	Name string

	// Logs is the recognized-log list keyed by LogID. Use NewReceiptPolicy
	// or AddLog to populate it so IDs and verifiers stay consistent.
	Logs map[SHA256Hash]*TrustedLog

	// MinLogs is the baseline number of distinct recognized logs required.
	// Values <= 0 resolve to 1 when no tier or CountFor overrides them.
	MinLogs int

	// LifetimeTiers optionally varies the requirement by certificate lifetime.
	LifetimeTiers []LifetimeTier

	// CountFor is an optional escape hatch for rules that do not fit the
	// lifetime tiers, such as requirements keyed by calendar validity
	// windows. It receives the certificate bounds and returns the required
	// number of logs; return a negative value to fall through to
	// LifetimeTiers and MinLogs.
	CountFor func(validity ReceiptValidity) int

	// Window is the timestamp rule bound to this policy.
	Window TimeWindow
}

// DefaultPolicyName is the name given to the backward-compatible policy.
const DefaultPolicyName = "default-single-receipt"

// NewReceiptPolicy builds the default policy over the supplied log public
// keys: every key is a recognized log and one valid receipt from any of them
// satisfies the policy. This is the pubkey-only entry point for existing
// callers; tighten it with Require, RequireLifetimeTiers and WithWindow.
func NewReceiptPolicy(keys ...crypto.PublicKey) (*ReceiptPolicy, error) {
	p := &ReceiptPolicy{
		Name:    DefaultPolicyName,
		MinLogs: 1,
		Logs:    make(map[SHA256Hash]*TrustedLog, len(keys)),
	}
	for i, key := range keys {
		if err := p.AddLog(fmt.Sprintf("key-%d", i+1), key); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// AddLog registers another recognized log.
func (p *ReceiptPolicy) AddLog(name string, pub crypto.PublicKey) error {
	if p == nil {
		return errors.New("ct: AddLog called on nil ReceiptPolicy")
	}
	log, err := NewTrustedLog(name, pub)
	if err != nil {
		return err
	}
	if p.Logs == nil {
		p.Logs = make(map[SHA256Hash]*TrustedLog)
	}
	p.Logs[SHA256Hash(log.ID.KeyID)] = log
	return nil
}

// Require sets the number of distinct recognized logs and returns p.
func (p *ReceiptPolicy) Require(minDistinctLogs int) *ReceiptPolicy {
	p.MinLogs = minDistinctLogs
	return p
}

// RequireLifetimeTiers sets lifetime-based count tiers and returns p.
func (p *ReceiptPolicy) RequireLifetimeTiers(tiers ...LifetimeTier) *ReceiptPolicy {
	p.LifetimeTiers = tiers
	return p
}

// WithWindow attaches a TimeWindow and returns p.
func (p *ReceiptPolicy) WithWindow(window TimeWindow) *ReceiptPolicy {
	p.Window = window
	return p
}

// Named sets the policy name and returns p.
func (p *ReceiptPolicy) Named(name string) *ReceiptPolicy {
	p.Name = name
	return p
}

func nonNegativeOrOne(n int) int {
	if n <= 0 {
		return 1
	}
	return n
}

// RequiredCount reports how many distinct recognized, valid receipts the
// policy demands for a certificate with the supplied validity, along with
// the matching LifetimeTier name (or "custom" for CountFor). It never
// returns a value below 1 so the default stays a single-receipt check.
func (p *ReceiptPolicy) RequiredCount(validity ReceiptValidity) (int, string) {
	if p != nil && p.CountFor != nil {
		if n := p.CountFor(validity); n >= 0 {
			if n < 1 {
				n = 1
			}
			return n, "custom"
		}
	}
	if p != nil && len(p.LifetimeTiers) > 0 && !validity.NotBefore.IsZero() && !validity.NotAfter.IsZero() {
		lifetime := validity.NotAfter.Sub(validity.NotBefore)
		for _, tier := range p.LifetimeTiers {
			if tier.MaxLifetime <= 0 || lifetime <= tier.MaxLifetime {
				return nonNegativeOrOne(tier.MinLogs), tier.Name
			}
		}
		longest := p.LifetimeTiers[0]
		for _, tier := range p.LifetimeTiers[1:] {
			if tier.MaxLifetime > longest.MaxLifetime {
				longest = tier
			}
		}
		return nonNegativeOrOne(longest.MinLogs), longest.Name
	}
	if p != nil && p.MinLogs > 0 {
		return p.MinLogs, ""
	}
	return 1, ""
}

// ReceiptCheck is the per-receipt verdict produced by ReceiptPolicy.Verify.
type ReceiptCheck struct {
	// Index is the position of the receipt in the input slice.
	Index int
	// Receipt is the checked receipt (nil when the input entry was nil).
	Receipt *Receipt
	// LogID is the LogID used for lookup: the receipt's own ID when known,
	// otherwise the ID of the key that verified it through the fallback.
	LogID LogID
	// LogName is the recognized log label when available.
	LogName string

	Recognized  bool
	SignatureOK bool
	InWindow    bool
	Timing      ReceiptTiming
	Counts      bool
	Issue       ReceiptIssue
	VerifyError error
}

// ReceiptVerification is the policy-aware report. It keeps cryptographic
// signature failures (SignatureFailures / SignatureError) separate from
// policy compliance (Satisfied / Gap / PolicyError).
type ReceiptVerification struct {
	Policy   *ReceiptPolicy
	Required int
	// Valid is the number of distinct recognized logs that contributed a
	// valid, in-window receipt.
	Valid int
	// Gap is the number of additional distinct logs required: max(0, Required-Valid).
	Gap int
	// Satisfied reports whether Valid >= Required.
	Satisfied bool
	// Tier is the LifetimeTier name selected for the certificate validity.
	Tier string

	Checks []*ReceiptCheck

	// SignatureFailures holds only recognized receipts that failed signature
	// verification. It never contains policy/list/window shortfalls.
	SignatureFailures []*ReceiptCheck
	// Unrecognized holds receipts whose LogID is not on the log list and
	// whose signature matched no listed key.
	Unrecognized []*ReceiptCheck
	// WindowFailures holds validly signed receipts rejected by the TimeWindow.
	WindowFailures []*ReceiptCheck
	// Duplicates holds extra valid receipts from an already counted log.
	Duplicates []*ReceiptCheck

	// MissingLogs lists recognized logs that did not contribute a counted
	// receipt. It is diagnostic: the compliance gap is the Gap field.
	MissingLogs []string
}

// SignatureVerificationError aggregates per-receipt signature failures and
// wraps ErrReceiptSignature for errors.Is.
type SignatureVerificationError struct {
	Failures []*ReceiptCheck
}

func (e *SignatureVerificationError) Error() string {
	return fmt.Sprintf("%v: %d receipt(s) failed signature verification", ErrReceiptSignature, len(e.Failures))
}

// Unwrap exposes ErrReceiptSignature.
func (e *SignatureVerificationError) Unwrap() error { return ErrReceiptSignature }

// PolicyNotSatisfiedError describes the compliance gap independently of any
// signature failure and wraps ErrPolicyNotSatisfied for errors.Is.
type PolicyNotSatisfiedError struct {
	PolicyName string
	Required   int
	Valid      int
	Gap        int
	// Result is the full report, including separated signature failures.
	Result *ReceiptVerification
}

func (e *PolicyNotSatisfiedError) Error() string {
	name := e.PolicyName
	if name == "" {
		name = "receipt"
	}
	return fmt.Sprintf("%v: policy %q requires %d distinct log receipt(s), have %d, missing %d",
		ErrPolicyNotSatisfied, name, e.Required, e.Valid, e.Gap)
}

// Unwrap exposes ErrPolicyNotSatisfied.
func (e *PolicyNotSatisfiedError) Unwrap() error { return ErrPolicyNotSatisfied }

// SignatureError returns the signature-failure aggregate when there are
// signature failures, or nil. It lets callers handle cryptographic failures
// separately from the policy verdict.
func (r *ReceiptVerification) SignatureError() error {
	if r == nil || len(r.SignatureFailures) == 0 {
		return nil
	}
	return &SignatureVerificationError{Failures: r.SignatureFailures}
}

// PolicyError returns the PolicyNotSatisfiedError when the policy is not
// satisfied, or nil.
func (r *ReceiptVerification) PolicyError() error {
	if r == nil || r.Satisfied {
		return nil
	}
	return &PolicyNotSatisfiedError{
		PolicyName: r.policyName(),
		Required:   r.Required,
		Valid:      r.Valid,
		Gap:        r.Gap,
		Result:     r,
	}
}

func (r *ReceiptVerification) policyName() string {
	if r.Policy != nil {
		return r.Policy.Name
	}
	return ""
}

// VerifyReceipt is the original single-receipt tier: it verifies receipt's
// signature over entry with pub and returns the verification error unchanged.
// It performs no log-list, count, lifetime or window check, so existing
// callers that only supply a public key keep their exact behavior.
func VerifyReceipt(entry LogEntry, receipt *Receipt, pub crypto.PublicKey) error {
	if receipt == nil {
		return errors.New("ct: nil receipt")
	}
	verifier, err := NewSignatureVerifier(pub)
	if err != nil {
		return err
	}
	return verifier.VerifySCTSignature(*receipt, entry)
}

// VerifyReceipts is the pubkey-only batch entry point with the default policy:
// every supplied key is recognized and one valid receipt from any of them is
// enough. It is the policy-aware equivalent of "verify each signature and
// count the ones that pass". For count tiers, log restrictions or time
// windows, build a ReceiptPolicy with NewReceiptPolicy and call Verify.
func VerifyReceipts(entry LogEntry, receipts []*Receipt, keys ...crypto.PublicKey) (*ReceiptVerification, error) {
	policy, err := NewReceiptPolicy(keys...)
	if err != nil {
		return nil, err
	}
	return policy.Verify(entry, receipts, ReceiptValidity{})
}

// Verify checks every receipt against the policy and returns a full report.
//
// The report is always non-nil when the policy itself is usable. The returned
// error joins two independent conditions: a *SignatureVerificationError when
// recognized receipts fail signature checks, and a *PolicyNotSatisfiedError
// when the distinct-log requirement is unmet. Use res.Satisfied,
// res.SignatureFailures, errors.As and errors.Is to tell them apart.
func (p *ReceiptPolicy) Verify(entry LogEntry, receipts []*Receipt, validity ReceiptValidity) (*ReceiptVerification, error) {
	if p == nil {
		p = &ReceiptPolicy{}
	}
	res := &ReceiptVerification{
		Policy:   p,
		Required: 0,
		Checks:   make([]*ReceiptCheck, 0, len(receipts)),
	}
	res.Required, res.Tier = p.RequiredCount(validity)

	counted := make(map[SHA256Hash]bool)

	for i, receipt := range receipts {
		check := &ReceiptCheck{Index: i, Receipt: receipt, InWindow: true, Timing: TimingUnknown}
		res.Checks = append(res.Checks, check)

		if receipt == nil {
			check.Issue = IssueNilReceipt
			check.InWindow = false
			continue
		}

		check.LogID = receipt.LogID
		claimedID := SHA256Hash(receipt.LogID.KeyID)
		trusted, known := p.Logs[claimedID]

		signatureOK := false
		var verifyErr error

		if known && trusted != nil && trusted.Verifier != nil {
			check.Recognized = true
			check.LogName = trusted.Name
			verifyErr = trusted.Verifier.VerifySCTSignature(*receipt, entry)
			if verifyErr == nil {
				signatureOK = true
			}
		} else {
			// Backward-compatible fallback: hand-built or older receipts may
			// carry a zero or mismatched LogID. Try every supplied key and
			// attribute the receipt to the one that verifies it.
			var lastErr error
			for _, candidate := range p.Logs {
				if candidate == nil || candidate.Verifier == nil {
					continue
				}
				if err := candidate.Verifier.VerifySCTSignature(*receipt, entry); err == nil {
					signatureOK = true
					trusted = candidate
					break
				} else {
					lastErr = err
				}
			}
			verifyErr = lastErr
			if signatureOK && trusted != nil {
				check.Recognized = true
				check.LogID = trusted.ID
				check.LogName = trusted.Name
			}
		}

		if !signatureOK {
			check.SignatureOK = false
			check.VerifyError = verifyErr
			if known {
				check.Issue = IssueBadSignature
			} else {
				check.Issue = IssueUnknownLog
			}
			continue
		}
		check.SignatureOK = true

		ts := TimestampToTime(receipt.Timestamp)
		inWindow, issue, timing := p.Window.evaluate(ts, validity)
		check.Timing = timing
		check.InWindow = inWindow
		if !inWindow {
			check.Issue = issue
			continue
		}

		logID := SHA256Hash(trusted.ID.KeyID)
		if counted[logID] {
			check.Issue = IssueDuplicateLog
			continue
		}
		counted[logID] = true
		check.Counts = true
		res.Valid++
	}

	for _, check := range res.Checks {
		switch check.Issue {
		case IssueBadSignature:
			res.SignatureFailures = append(res.SignatureFailures, check)
		case IssueUnknownLog:
			res.Unrecognized = append(res.Unrecognized, check)
		case IssueOutsideWindow, IssueFutureTimestamp:
			res.WindowFailures = append(res.WindowFailures, check)
		case IssueDuplicateLog:
			res.Duplicates = append(res.Duplicates, check)
		}
	}

	res.Gap = res.Required - res.Valid
	if res.Gap < 0 {
		res.Gap = 0
	}
	res.Satisfied = res.Valid >= res.Required

	missing := make([]string, 0)
	for id, log := range p.Logs {
		if counted[id] {
			continue
		}
		if log != nil && log.Name != "" {
			missing = append(missing, log.Name)
			continue
		}
		missing = append(missing, hex.EncodeToString(id[:]))
	}
	sort.Strings(missing)
	res.MissingLogs = missing

	var errs []error
	if sigErr := res.SignatureError(); sigErr != nil {
		errs = append(errs, sigErr)
	}
	if policyErr := res.PolicyError(); policyErr != nil {
		errs = append(errs, policyErr)
	}
	return res, errors.Join(errs...)
}
