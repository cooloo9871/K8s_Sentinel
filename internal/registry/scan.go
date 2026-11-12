package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Scans running at once, across every registry.
const maxConcurrentScans = 3

type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

// Finding is one vulnerability in one image. The JSON keys are also what the
// scan pod prints, one object per line.
type Finding struct {
	ID               string `json:"id"`
	Severity         string `json:"severity"`
	Package          string `json:"package"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion"`
	Title            string `json:"title"`
	Link             string `json:"link"`
}

// ImageResult is one image of a registry and how its last scan went.
type ImageResult struct {
	Image string `json:"image"`
	// False with Error set when the scan failed. A failed scan must never read
	// as an image with nothing wrong.
	Scanned   bool   `json:"scanned"`
	Counts    Counts `json:"counts"`
	Fixable   int    `json:"fixable"`
	ScannedAt string `json:"scannedAt,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Run is the latest scan of a registry, in progress or finished.
type Run struct {
	Running    bool   `json:"running"`
	StartedAt  string `json:"startedAt,omitempty"`
	FinishedAt string `json:"finishedAt,omitempty"`
	// Images this run covers and how many are done.
	Total int `json:"total"`
	Done  int `json:"done"`
	// Images the filters cover. More than Total when the run was capped.
	Matched int `json:"matched"`
	// Why the run scanned nothing or stopped early: the registry could not be
	// listed, or the scan pods could not run.
	Error string `json:"error,omitempty"`
}

// Report is everything kept about one registry's scans.
type Report struct {
	Run    Run           `json:"run"`
	Images []ImageResult `json:"images"`
}

type scanFunc func(ctx context.Context, cfg Config, image string) ([]Finding, error)
type resolveFunc func(ctx context.Context, cfg Config) ([]string, int, error)

// Scanner runs the scans, on schedule and on demand, and keeps the results
// under dir: {id}/index.json for the Report, and one file per image beside it
// for the findings, which are only read when someone asks for them.
type Scanner struct {
	store   *Store
	dir     string
	scan    scanFunc
	resolve resolveFunc
	now     func() time.Time
	sem     chan struct{}

	mu      sync.Mutex
	reports map[string]*Report
	cancels map[string]context.CancelFunc
	// The scheduler's context, so a run started from a request outlives it.
	base context.Context
}

func NewScanner(store *Store, dir string, scan scanFunc) *Scanner {
	s := &Scanner{
		store:   store,
		dir:     dir,
		scan:    scan,
		resolve: Resolve,
		now:     time.Now,
		sem:     make(chan struct{}, maxConcurrentScans),
		reports: map[string]*Report{},
		cancels: map[string]context.CancelFunc{},
		base:    context.Background(),
	}
	for _, c := range store.List() {
		var r Report
		if data, err := os.ReadFile(s.indexPath(c.ID)); err == nil && json.Unmarshal(data, &r) == nil {
			// A run cut short by a restart: its Jobs are gone. With no finish
			// time it is due again at once.
			r.Run.Running = false
			s.reports[c.ID] = &r
		}
	}
	return s
}

func (s *Scanner) indexPath(id string) string { return filepath.Join(s.dir, id, "index.json") }

func (s *Scanner) findingsPath(id, image string) string {
	sum := sha256.Sum256([]byte(image))
	return filepath.Join(s.dir, id, hex.EncodeToString(sum[:8])+".json")
}

// save writes a registry's report. Called with mu held.
func (s *Scanner) save(id string) {
	if err := os.MkdirAll(filepath.Join(s.dir, id), 0750); err != nil {
		log.Printf("registry: saving results: %v", err)
		return
	}
	if err := writeJSON(s.indexPath(id), s.reports[id]); err != nil {
		log.Printf("registry: saving results: %v", err)
	}
}

// Report returns a copy of what is known about a registry's scans.
func (s *Scanner) Report(id string) Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.reports[id]
	if r == nil {
		return Report{Images: []ImageResult{}}
	}
	out := Report{Run: r.Run, Images: append([]ImageResult{}, r.Images...)}
	sortResults(out.Images)
	return out
}

// Findings returns the findings of one scanned image.
func (s *Scanner) Findings(id, image string) ([]Finding, bool) {
	data, err := os.ReadFile(s.findingsPath(id, image))
	if err != nil {
		return nil, false
	}
	findings := []Finding{}
	if json.Unmarshal(data, &findings) != nil {
		return nil, false
	}
	return findings, true
}

// Run is the scheduler: it starts a registry's scan when one is due, checking
// once a minute, until ctx ends.
func (s *Scanner) Run(ctx context.Context) {
	s.mu.Lock()
	s.base = ctx
	s.mu.Unlock()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		for _, c := range s.store.List() {
			if s.due(c) {
				_ = s.Start(c.ID)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// due reports whether a registry should be scanned now: it never finished a
// run, or the last one began more than its interval ago.
func (s *Scanner) due(c Config) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.reports[c.ID]
	if r == nil || r.Run.FinishedAt == "" {
		return r == nil || !r.Run.Running
	}
	if r.Run.Running {
		return false
	}
	wait := time.Duration(c.IntervalDays) * 24 * time.Hour
	if r.Run.Error != "" {
		// A run that scanned nothing is not a reason to wait days for the next.
		wait = retryAfterError
	}
	started, err := time.Parse(time.RFC3339, r.Run.StartedAt)
	return err != nil || !s.now().Before(started.Add(wait))
}

// How soon a run that could not list the registry, or could not run its pods,
// is tried again.
const retryAfterError = time.Hour

var ErrAlreadyRunning = errors.New("a scan of this registry is already running")
var ErrNotFound = errors.New("no such registry")

// Start begins a scan of one registry in the background.
func (s *Scanner) Start(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Read under the lock, so a registry deleted or edited at this moment is
	// seen as it now is, and Forget cannot be overtaken.
	cfg, ok := s.store.Get(id)
	if !ok {
		return ErrNotFound
	}
	if _, busy := s.cancels[id]; busy {
		return ErrAlreadyRunning
	}
	r := s.reports[id]
	if r == nil {
		r = &Report{Images: []ImageResult{}}
		s.reports[id] = r
	}
	r.Run = Run{Running: true, StartedAt: s.now().UTC().Format(time.RFC3339)}
	ctx, cancel := context.WithCancel(s.base)
	s.cancels[id] = cancel
	s.save(id)

	go s.run(ctx, cancel, cfg)
	return nil
}

// Restart cancels a registry's running scan, if any, and starts a new one. For
// when its filters or credentials have just changed.
func (s *Scanner) Restart(id string) {
	s.stop(id)
	_ = s.Start(id)
}

// Forget cancels a registry's scan and removes what was kept about it.
func (s *Scanner) Forget(id string) {
	s.stop(id)
	s.mu.Lock()
	delete(s.reports, id)
	s.mu.Unlock()
	if err := os.RemoveAll(filepath.Join(s.dir, id)); err != nil {
		log.Printf("registry: removing results: %v", err)
	}
}

// stop cancels a running scan and waits until it has let go of the report.
func (s *Scanner) stop(id string) {
	s.mu.Lock()
	cancel := s.cancels[id]
	s.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	for {
		s.mu.Lock()
		_, running := s.cancels[id]
		s.mu.Unlock()
		if !running {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// How long listing a registry may take before the run gives up.
const resolveTimeout = 10 * time.Minute

func (s *Scanner) run(ctx context.Context, cancel context.CancelFunc, cfg Config) {
	id := cfg.ID
	defer cancel()
	// update applies a change to the report, if the registry still has one,
	// and saves.
	update := func(f func(r *Report)) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if r := s.reports[id]; r != nil {
			f(r)
			s.save(id)
		}
	}
	// finish is the run's last word. The report stops saying "running" and the
	// run gives up its place in one step, so nothing can start in between and
	// have its own place taken away.
	finish := func(f func(r *Report)) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if r := s.reports[id]; r != nil {
			r.Run.Running = false
			f(r)
			s.save(id)
		}
		delete(s.cancels, id)
	}
	stamp := func() string { return s.now().UTC().Format(time.RFC3339) }

	listCtx, listDone := context.WithTimeout(ctx, resolveTimeout)
	images, matched, err := s.resolve(listCtx, cfg)
	listDone()
	if ctx.Err() != nil {
		finish(func(*Report) {}) // cancelled: no finish time, so it is due again
		return
	}
	if err != nil {
		finish(func(r *Report) { r.Run.Error, r.Run.FinishedAt = err.Error(), stamp() })
		return
	}
	update(func(r *Report) { r.Run.Total, r.Run.Matched = len(images), matched })

	// Set when a scan pod could not run at all. The rest of the run would fail
	// the same way, one timeout at a time, so it stops there.
	var infraMu sync.Mutex
	infra := ""

	var wg sync.WaitGroup
	for _, image := range images {
		acquired := false
		select {
		case s.sem <- struct{}{}:
			acquired = true
		case <-ctx.Done():
		}
		if !acquired {
			break
		}
		if ctx.Err() != nil {
			<-s.sem
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-s.sem }()
			findings, err := s.scan(ctx, cfg, image)
			if ctx.Err() != nil {
				return // cancelled, not failed: say nothing about the image
			}
			var ie *InfraError
			if errors.As(err, &ie) {
				infraMu.Lock()
				if infra == "" {
					infra = ie.Error()
				}
				infraMu.Unlock()
				cancel()
				return // says nothing about the image either
			}
			res := ImageResult{Image: image, ScannedAt: stamp()}
			if err != nil {
				res.Error = err.Error()
				_ = os.Remove(s.findingsPath(id, image))
			} else {
				res.Scanned = true
				res.Counts, res.Fixable = summarize(findings)
				sortFindings(findings)
			}
			update(func(r *Report) {
				if err == nil {
					if werr := writeJSON(s.findingsPath(id, image), findings); werr != nil {
						res.Scanned, res.Error = false, "the findings could not be saved: "+werr.Error()
					}
				}
				r.Run.Done++
				for i := range r.Images {
					if r.Images[i].Image == image {
						r.Images[i] = res
						return
					}
				}
				r.Images = append(r.Images, res)
			})
		}()
	}
	wg.Wait()

	if infra != "" {
		finish(func(r *Report) {
			r.Run.Error = "The scan was stopped because its pods cannot run: " + infra
			r.Run.FinishedAt = stamp()
		})
		return
	}
	if ctx.Err() != nil {
		finish(func(*Report) {})
		return
	}
	finish(func(r *Report) {
		// Images the filters no longer cover leave the list with this run.
		current := make(map[string]bool, len(images))
		for _, image := range images {
			current[image] = true
		}
		kept := r.Images[:0]
		for _, img := range r.Images {
			if current[img.Image] {
				kept = append(kept, img)
			} else {
				_ = os.Remove(s.findingsPath(id, img.Image))
			}
		}
		r.Images = kept
		r.Run.FinishedAt = stamp()
	})
}

var severityRank = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

// sortFindings puts the worst first and, within a severity, the ones with a
// fix first: the same order the workload list uses. Only the top of a long
// list is shown until asked, so the order decides what is seen.
func sortFindings(findings []Finding) {
	rank := func(f Finding) int {
		if r, ok := severityRank[f.Severity]; ok {
			return r
		}
		return len(severityRank)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		if af, bf := a.FixedVersion != "", b.FixedVersion != ""; af != bf {
			return af
		}
		return a.ID < b.ID
	})
}

func summarize(findings []Finding) (Counts, int) {
	var c Counts
	fixable := 0
	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL":
			c.Critical++
		case "HIGH":
			c.High++
		case "MEDIUM":
			c.Medium++
		case "LOW":
			c.Low++
		default:
			c.Unknown++
		}
		if f.FixedVersion != "" {
			fixable++
		}
	}
	return c, fixable
}

// sortResults puts what to look at first on top: by how bad, then the scans
// that failed ahead of the images with nothing found, since those are unknown.
func sortResults(images []ImageResult) {
	sort.SliceStable(images, func(i, j int) bool {
		a, b := images[i], images[j]
		if a.Counts.Critical != b.Counts.Critical {
			return a.Counts.Critical > b.Counts.Critical
		}
		if a.Counts.High != b.Counts.High {
			return a.Counts.High > b.Counts.High
		}
		if a.Scanned != b.Scanned {
			return !a.Scanned
		}
		return a.Image < b.Image
	})
}
