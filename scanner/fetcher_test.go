// Copyright 2026 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scanner

import (
	"context"
	"errors"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
)

// fakeLogClient implements LogClient over a fixed-size fake log.
type fakeLogClient struct {
	treeSize uint64
	// maxBatch caps how many entries a single GetRawEntries call returns.
	// Zero makes the client return empty responses.
	maxBatch int64
	fetchErr error
}

func (c *fakeLogClient) BaseURI() string { return "fake://log" }

func (c *fakeLogClient) GetSTH(context.Context) (*ct.SignedTreeHead, error) {
	return &ct.SignedTreeHead{TreeSize: c.treeSize}, nil
}

func (c *fakeLogClient) GetRawEntries(_ context.Context, start, end int64) (*ct.GetEntriesResponse, error) {
	if c.fetchErr != nil {
		return nil, c.fetchErr
	}
	if c.maxBatch == 0 {
		return &ct.GetEntriesResponse{}, nil
	}
	if end-start+1 > c.maxBatch {
		end = start + c.maxBatch - 1
	}
	if maxEnd := int64(c.treeSize) - 1; end > maxEnd {
		end = maxEnd
	}
	if end < start {
		return &ct.GetEntriesResponse{}, nil
	}
	return &ct.GetEntriesResponse{Entries: make([]ct.LeafEntry, end-start+1)}, nil
}

// newTestFetcher creates a Fetcher with fast backoff and few attempts, so
// that failure-path tests terminate quickly.
func newTestFetcher(client LogClient, opts *FetcherOptions) *Fetcher {
	f := NewFetcher(client, opts)
	f.maxFetchAttempts = 3
	f.fetchBackoffMin = time.Millisecond
	f.fetchBackoffMax = 10 * time.Millisecond
	return f
}

func TestFetcherEmptyResponseFails(t *testing.T) {
	f := newTestFetcher(&fakeLogClient{treeSize: 10}, &FetcherOptions{BatchSize: 10, ParallelFetch: 1})
	if err := f.Run(context.Background(), func(EntryBatch) {}); err == nil {
		t.Fatal("Run() = nil, want error for a log that returns no entries")
	}
}

func TestFetcherPersistentErrorFails(t *testing.T) {
	client := &fakeLogClient{treeSize: 10, maxBatch: 10, fetchErr: errors.New("boom")}
	f := newTestFetcher(client, &FetcherOptions{BatchSize: 10, ParallelFetch: 1})
	if err := f.Run(context.Background(), func(EntryBatch) {}); err == nil {
		t.Fatal("Run() = nil, want error for a log whose fetches keep failing")
	}
}

func TestFetcherPartialBatches(t *testing.T) {
	f := newTestFetcher(&fakeLogClient{treeSize: 10, maxBatch: 3}, &FetcherOptions{BatchSize: 10, ParallelFetch: 1})
	var got []EntryBatch
	if err := f.Run(context.Background(), func(b EntryBatch) { got = append(got, b) }); err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}
	// The batches must cover [0, 10) contiguously, however small they are.
	next := int64(0)
	for _, b := range got {
		if b.Start != next {
			t.Fatalf("Got batch starting at %d, want %d", b.Start, next)
		}
		next += int64(len(b.Entries))
	}
	if want := int64(10); next != want {
		t.Fatalf("Fetched %d entries, want %d", next, want)
	}
}

func TestScanLogReturnsProcessedCount(t *testing.T) {
	client := &fakeLogClient{treeSize: 10, maxBatch: 100}
	opts := ScannerOptions{
		FetcherOptions: FetcherOptions{
			BatchSize:     100,
			ParallelFetch: 1,
			StartIndex:    3,
		},
		Matcher:    &MatchAll{},
		NumWorkers: 1,
	}
	scanner := NewScanner(client, opts)

	count, err := scanner.ScanLog(context.Background(), func(*ct.RawLogEntry) {}, func(*ct.RawLogEntry) {})
	if err != nil {
		t.Fatalf("ScanLog() = %v, want nil", err)
	}
	// The scanned range is [3, 10), so the count must not be the range end.
	if want := int64(7); count != want {
		t.Fatalf("ScanLog() count = %d, want %d", count, want)
	}
}
