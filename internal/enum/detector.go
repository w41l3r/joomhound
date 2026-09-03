package enum

import (
	"context"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"sync"

	"github.com/w41l3r/joomhound/internal/http"
	"github.com/w41l3r/joomhound/internal/models"
)

// Regexes are compiled once at package init. The previous code called
// regexp.MustCompile inside functions invoked per-request, recompiling the
// same pattern thousands of times per scan.
var (
	// reGenerator matches the Joomla generator meta tag. This is the only
	// truly Joomla-specific HTML signal.
	reGenerator = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']Joomla!?\s*([0-9][0-9.]*)?[^"']*["']`)

	// reJoomlaJS matches Joomla's JavaScript namespace, present on almost
	// every Joomla page.
	reJoomlaJS = regexp.MustCompile(`(?i)(Joomla\.(submitbutton|JText|Text|Event|Request)|/media/system/js/core(\.min)?\.js|/media/jui/js/)`)

	// reManifestVersion extracts <version> from an XML manifest.
	reManifestVersion = regexp.MustCompile(`(?s)<version>\s*([0-9]+(?:\.[0-9]+)+)\s*</version>`)

	// reHTMLCommentVersion matches a version leaked in an HTML comment.
	reHTMLCommentVersion = regexp.MustCompile(`(?i)<!--\s*Joomla!?\s*([0-9]+(?:\.[0-9]+)+)[^>]*-->`)

	// reTemplateDir matches template directory names in an index listing or
	// in asset URLs on the rendered page.
	reTemplateDir = regexp.MustCompile(`(?i)/templates/([a-z0-9_\-]+)/`)

	// reJoomlaCookie matches Joomla's md5-named session cookie.
	reJoomlaCookie = regexp.MustCompile(`^[a-f0-9]{32}=`)

	// reDirListing matches subdirectory links in an Apache-style index page.
	reDirListing = regexp.MustCompile(`(?i)href=["']([a-z0-9_\-]+)/["']`)
)

// joomlaComponents is the component enumeration wordlist. Names are stored
// with the canonical com_ prefix exactly once.
//
// The old list mixed bare names ("banners") with prefixed ones
// ("com_contact") and then unconditionally prepended "com_", producing
// requests for /administrator/components/com_com_contact/ - which 404 on
// every real target, so half the list could never match.
var joomlaComponents = []string{
	"com_admin", "com_ajax", "com_banners", "com_cache", "com_categories",
	"com_checkin", "com_config", "com_contact", "com_content", "com_cpanel",
	"com_fields", "com_finder", "com_installer", "com_joomlaupdate",
	"com_languages", "com_login", "com_mailto", "com_media", "com_menus",
	"com_messages", "com_modules", "com_newsfeeds", "com_plugins",
	"com_postinstall", "com_privacy", "com_redirect", "com_search",
	"com_tags", "com_templates", "com_users", "com_weblinks", "com_workflow",
	"com_wrapper", "com_actionlogs", "com_associations", "com_scheduler",
	"com_guidedtours",
}

// knownTemplates are stock and widely-deployed Joomla templates worth probing
// directly when directory listing is disabled.
var knownTemplates = []string{
	"cassiopeia", "atum", "protostar", "beez3", "beez_20", "isis",
	"hathor", "system", "rhuk_milkyway", "ja_purity",
}

// Detector performs Joomla fingerprinting and enumeration.
//
// It caches GET responses for the duration of a scan: the five detection
// methods used to fetch the site root five separate times.
type Detector struct {
	client *http.Client

	mu        sync.Mutex
	cache     map[string]*cachedResp
	soft404   map[string]*soft404Profile
	threads   int
	Verbose   bool
	OnMessage func(string)
}

type cachedResp struct {
	resp *http.Response
	err  error
}

// soft404Profile records how a target responds to a path that cannot exist,
// so we can tell a real 200 from a catch-all 200.
type soft404Profile struct {
	alwaysOK bool
	bodyLen  int
}

// NewDetector creates a Detector.
func NewDetector(client *http.Client) *Detector {
	return &Detector{
		client:  client,
		cache:   make(map[string]*cachedResp),
		soft404: make(map[string]*soft404Profile),
		threads: 10,
	}
}

// SetThreads sets the enumeration concurrency.
func (d *Detector) SetThreads(n int) {
	if n > 0 {
		d.threads = n
	}
}

func (d *Detector) logf(format string, args ...any) {
	if d.OnMessage != nil {
		d.OnMessage(fmt.Sprintf(format, args...))
	}
}

// NormalizeTarget trims trailing slashes and supplies a scheme when missing.
func NormalizeTarget(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return t
	}
	if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
		t = "http://" + t
	}
	return strings.TrimRight(t, "/")
}

// get fetches a URL, memoizing the result (including errors) for the scan.
func (d *Detector) get(ctx context.Context, rawURL string) (*http.Response, error) {
	d.mu.Lock()
	if c, ok := d.cache[rawURL]; ok {
		d.mu.Unlock()
		return c.resp, c.err
	}
	d.mu.Unlock()

	resp, err := d.client.Get(ctx, rawURL)

	d.mu.Lock()
	d.cache[rawURL] = &cachedResp{resp: resp, err: err}
	d.mu.Unlock()

	return resp, err
}

// profileSoft404 learns how the target answers a guaranteed-missing path.
func (d *Detector) profileSoft404(ctx context.Context, base string) *soft404Profile {
	d.mu.Lock()
	if p, ok := d.soft404[base]; ok {
		d.mu.Unlock()
		return p
	}
	d.mu.Unlock()

	p := &soft404Profile{}
	probe := fmt.Sprintf("%s/administrator/components/com_joomhound%d/", base, rand.Int63())
	if resp, err := d.get(ctx, probe); err == nil && resp.StatusCode == 200 {
		p.alwaysOK = true
		p.bodyLen = len(resp.Body)
	}

	d.mu.Lock()
	d.soft404[base] = p
	d.mu.Unlock()
	return p
}

// pathExists interprets a response as evidence that a path is present.
//
// 403 is treated as existence: a hardened Joomla install returns Forbidden
// for component directories that are definitely there. The old code only
// accepted 200 and therefore missed most real installations.
func pathExists(resp *http.Response, profile *soft404Profile) bool {
	if resp == nil {
		return false
	}
	switch {
	case resp.StatusCode == 403:
		return true
	case resp.StatusCode == 200:
		if profile != nil && profile.alwaysOK {
			// Catch-all 200: only trust it if the body differs meaningfully
			// from the known-bogus baseline.
			if abs(len(resp.Body)-profile.bodyLen) < 32 {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// DetectJoomla reports whether the target runs Joomla, along with the signals
// that fired. It requires a Joomla-specific signal: the previous version
// matched on `<meta property="og:image">` and `name="viewport"`, which appear
// on virtually every website and made detection always return true.
func (d *Detector) DetectJoomla(ctx context.Context, targetURL string) (bool, []string) {
	base := NormalizeTarget(targetURL)
	var signals []string

	// 1. Rendered homepage: generator tag + Joomla JS namespace.
	if resp, err := d.get(ctx, base+"/"); err == nil && resp.StatusCode < 400 {
		body := resp.String()
		if reGenerator.MatchString(body) {
			signals = append(signals, "meta-generator")
		}
		if reJoomlaJS.MatchString(body) {
			signals = append(signals, "joomla-js-namespace")
		}
		if strings.Contains(body, "/media/system/js/") || strings.Contains(body, "option=com_") {
			signals = append(signals, "joomla-asset-paths")
		}
		if resp.GetHeader("X-Joomla") != "" {
			signals = append(signals, "x-joomla-header")
		}
		for _, c := range resp.Headers.Values("Set-Cookie") {
			// Joomla session cookies are 32 hex chars named after an md5 of
			// the site secret.
			if strings.Contains(c, "joomla_user_state") || reJoomlaCookie.MatchString(c) {
				signals = append(signals, "joomla-session-cookie")
				break
			}
		}
	}

	// 2. robots.txt shipped with Joomla lists its exact directory set.
	if resp, err := d.get(ctx, base+"/robots.txt"); err == nil && resp.StatusCode == 200 {
		body := resp.String()
		hits := 0
		for _, p := range []string{"/administrator/", "/components/", "/modules/", "/plugins/", "/templates/", "/libraries/", "/cache/"} {
			if strings.Contains(body, "Disallow: "+p) {
				hits++
			}
		}
		// A generic robots.txt may disallow /administrator/; the full Joomla
		// set is distinctive.
		if hits >= 4 {
			signals = append(signals, "joomla-robots-txt")
		}
	}

	// 3. The core manifest is definitive when readable.
	if v, ok := d.detectViaManifest(ctx, base); ok && v != "" {
		signals = append(signals, "core-manifest")
	}

	return len(signals) > 0, signals
}

// DetectVersion attempts version detection, most reliable method first.
func (d *Detector) DetectVersion(ctx context.Context, targetURL string) *models.VersionInfo {
	base := NormalizeTarget(targetURL)
	info := &models.VersionInfo{Methods: []string{}}

	type method struct {
		name       string
		confidence float64
		fn         func(context.Context, string) (string, bool)
	}

	for _, m := range []method{
		{"core-manifest", 0.98, d.detectViaManifest},
		{"language-manifest", 0.92, d.detectViaLanguageFile},
		{"changelog", 0.90, d.detectViaChangelog},
		{"meta-generator", 0.80, d.detectViaGeneratorTag},
		{"html-comment", 0.70, d.detectViaHTMLComment},
	} {
		if v, ok := m.fn(ctx, base); ok && v != "" {
			info.Version = v
			info.Detected = true
			info.Confidence = m.confidence
			info.Methods = append(info.Methods, m.name)
			return info
		}
	}

	// Last resort: a coarse major-branch guess. Flagged with low confidence
	// and an imprecise version string so CVE range matching skips it rather
	// than treating "3.x" as "0.0.0" and matching every advisory.
	if branch, ok := d.detectMajorBranch(ctx, base); ok {
		info.Version = branch
		info.Detected = true
		info.Confidence = 0.35
		info.Methods = append(info.Methods, "branch-heuristic")
	}

	return info
}

// detectViaManifest reads the core XML manifest.
func (d *Detector) detectViaManifest(ctx context.Context, base string) (string, bool) {
	paths := []string{
		"/administrator/manifests/files/joomla.xml",
		"/administrator/manifests/files/joomla-core-files.xml",
	}
	for _, p := range paths {
		resp, err := d.get(ctx, base+p)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		// Guard against a catch-all HTML page being parsed as XML.
		if !strings.Contains(resp.String(), "<extension") && !strings.Contains(resp.String(), "<install") {
			continue
		}
		if m := reManifestVersion.FindStringSubmatch(resp.String()); len(m) > 1 {
			return m[1], true
		}
	}
	return "", false
}

// detectViaLanguageFile reads the en-GB language pack manifest, which tracks
// the core version and is often left readable when the core manifest is not.
// (Technique borrowed from droopescan / joomscan.)
func (d *Detector) detectViaLanguageFile(ctx context.Context, base string) (string, bool) {
	paths := []string{
		"/language/en-GB/en-GB.xml",
		"/language/en-GB/langmetadata.xml",
		"/administrator/language/en-GB/en-GB.xml",
		"/administrator/language/en-GB/langmetadata.xml",
	}
	for _, p := range paths {
		resp, err := d.get(ctx, base+p)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		if !strings.Contains(resp.String(), "<metafile") && !strings.Contains(resp.String(), "<extension") {
			continue
		}
		if m := reManifestVersion.FindStringSubmatch(resp.String()); len(m) > 1 {
			return m[1], true
		}
	}
	return "", false
}

// detectViaChangelog parses the shipped changelog, whose first <version>
// entry is the installed release.
func (d *Detector) detectViaChangelog(ctx context.Context, base string) (string, bool) {
	for _, p := range []string{"/administrator/components/com_admin/changelog.xml", "/CHANGELOG.php", "/README.txt"} {
		resp, err := d.get(ctx, base+p)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		if m := reManifestVersion.FindStringSubmatch(resp.String()); len(m) > 1 {
			return m[1], true
		}
	}
	return "", false
}

// detectViaGeneratorTag reads the version from the generator meta tag.
func (d *Detector) detectViaGeneratorTag(ctx context.Context, base string) (string, bool) {
	resp, err := d.get(ctx, base+"/")
	if err != nil || resp.StatusCode >= 400 {
		return "", false
	}
	if m := reGenerator.FindStringSubmatch(resp.String()); len(m) > 1 && m[1] != "" {
		return m[1], true
	}
	return "", false
}

// detectViaHTMLComment reads a version leaked in an HTML comment.
func (d *Detector) detectViaHTMLComment(ctx context.Context, base string) (string, bool) {
	resp, err := d.get(ctx, base+"/")
	if err != nil || resp.StatusCode >= 400 {
		return "", false
	}
	if m := reHTMLCommentVersion.FindStringSubmatch(resp.String()); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// detectMajorBranch distinguishes the 4.x/5.x line from 3.x by looking for
// files that only exist in one of them.
func (d *Detector) detectMajorBranch(ctx context.Context, base string) (string, bool) {
	// media/vendor exists in Joomla 4+; media/jui is 3.x-only.
	if resp, err := d.get(ctx, base+"/media/vendor/joomla-custom-elements/js/joomla-alert.min.js"); err == nil && resp.StatusCode == 200 {
		return "4.x", true
	}
	if resp, err := d.get(ctx, base+"/media/jui/js/jquery.min.js"); err == nil && resp.StatusCode == 200 {
		return "3.x", true
	}
	return "", false
}

// EnumerateComponents probes for installed components concurrently.
func (d *Detector) EnumerateComponents(ctx context.Context, targetURL string) []models.Component {
	base := NormalizeTarget(targetURL)
	profile := d.profileSoft404(ctx, base)

	var (
		mu  sync.Mutex
		out []models.Component
		wg  sync.WaitGroup
	)

	sem := make(chan struct{}, d.threads)

	for _, name := range joomlaComponents {
		select {
		case <-ctx.Done():
			wg.Wait()
			return out
		default:
		}

		wg.Add(1)
		// Acquire before launching so we never hold more goroutines than the
		// concurrency limit. The old code spawned one goroutine per wordlist
		// entry up front and only then blocked on the semaphore.
		sem <- struct{}{}

		go func(comp string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Probe both the admin-side and site-side component directories.
			candidates := []string{
				fmt.Sprintf("%s/administrator/components/%s/", base, comp),
				fmt.Sprintf("%s/components/%s/", base, comp),
			}

			for _, u := range candidates {
				resp, err := d.get(ctx, u)
				if err != nil {
					continue
				}
				if !pathExists(resp, profile) {
					continue
				}

				c := models.Component{
					Name:      comp,
					Type:      "component",
					Path:      strings.TrimPrefix(u, base),
					Detected:  true,
					Installed: true,
				}
				// A readable manifest gives us the extension version.
				if v, ok := d.componentVersion(ctx, base, comp); ok {
					c.Version = v
				}

				mu.Lock()
				out = append(out, c)
				mu.Unlock()
				return
			}
		}(name)
	}

	wg.Wait()
	return out
}

// componentVersion reads a component's own XML manifest when exposed.
func (d *Detector) componentVersion(ctx context.Context, base, comp string) (string, bool) {
	short := strings.TrimPrefix(comp, "com_")
	for _, p := range []string{
		fmt.Sprintf("/administrator/components/%s/%s.xml", comp, short),
		fmt.Sprintf("/components/%s/%s.xml", comp, short),
	} {
		resp, err := d.get(ctx, base+p)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		if m := reManifestVersion.FindStringSubmatch(resp.String()); len(m) > 1 {
			return m[1], true
		}
	}
	return "", false
}

// EnumerateTemplates finds installed templates via directory listing, asset
// references on the rendered page, and direct probes of known template names.
func (d *Detector) EnumerateTemplates(ctx context.Context, targetURL string) []models.Template {
	base := NormalizeTarget(targetURL)
	profile := d.profileSoft404(ctx, base)

	found := make(map[string]models.Template)

	// 1. Template names referenced by the homepage's own asset URLs. This is
	//    the highest-signal source and costs no extra request.
	if resp, err := d.get(ctx, base+"/"); err == nil && resp.StatusCode < 400 {
		for _, m := range reTemplateDir.FindAllStringSubmatch(resp.String(), -1) {
			if len(m) > 1 {
				name := strings.ToLower(m[1])
				found[name] = models.Template{Name: name, Path: "/templates/" + name + "/"}
			}
		}
	}

	// 2. Directory listing, when the server leaks one.
	if resp, err := d.get(ctx, base+"/templates/"); err == nil && resp.StatusCode == 200 {
		for _, m := range reDirListing.FindAllStringSubmatch(resp.String(), -1) {
			if len(m) > 1 {
				name := strings.ToLower(m[1])
				if name == ".." || name == "." {
					continue
				}
				found[name] = models.Template{Name: name, Path: "/templates/" + name + "/"}
			}
		}
	}

	// 3. Direct probes for known template names not already found.
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	sem := make(chan struct{}, d.threads)

	for _, name := range knownTemplates {
		mu.Lock()
		_, seen := found[name]
		mu.Unlock()
		if seen {
			continue
		}

		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(tpl string) {
			defer wg.Done()
			defer func() { <-sem }()

			resp, err := d.get(ctx, fmt.Sprintf("%s/templates/%s/", base, tpl))
			if err != nil || !pathExists(resp, profile) {
				return
			}
			mu.Lock()
			found[tpl] = models.Template{Name: tpl, Path: "/templates/" + tpl + "/"}
			mu.Unlock()
		}(name)
	}
	wg.Wait()

	// Enrich with versions from templateDetails.xml.
	out := make([]models.Template, 0, len(found))
	for _, t := range found {
		if resp, err := d.get(ctx, base+t.Path+"templateDetails.xml"); err == nil && resp.StatusCode == 200 {
			if m := reManifestVersion.FindStringSubmatch(resp.String()); len(m) > 1 {
				t.Version = m[1]
			}
		}
		out = append(out, t)
	}
	return out
}
