package enum

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/lfgrillo83/joomhound/internal/http"
	"github.com/lfgrillo83/joomhound/internal/models"
)

type Detector struct {
	client *http.Client
}

func NewDetector(client *http.Client) *Detector {
	return &Detector{
		client: client,
	}
}

// DetectJoomla checks if the target is running Joomla
func (d *Detector) DetectJoomla(targetURL string) bool {
	// Try multiple detection methods
	methods := []func(string) bool{
		d.detectViaRobotsFile,
		d.detectViaMetaTags,
		d.detectViaJQueryReadyJS,
		d.detectViaGenerator,
		d.detectViaXJoomlaHeader,
	}

	for _, method := range methods {
		if method(targetURL) {
			return true
		}
	}
	return false
}

// DetectVersion attempts to detect Joomla version using multiple techniques
func (d *Detector) DetectVersion(targetURL string) *models.VersionInfo {
	versionInfo := &models.VersionInfo{
		Detected:   false,
		Confidence: 0.0,
		Methods:    []string{},
	}

	// Method 1: Check administrator manifest file
	if version, ok := d.detectViaManifest(targetURL); ok {
		versionInfo.Version = version
		versionInfo.Detected = true
		versionInfo.Methods = append(versionInfo.Methods, "manifest-file")
		versionInfo.Confidence = 0.95
		return versionInfo
	}

	// Method 2: Check HTML comments
	if version, ok := d.detectViaHTMLComment(targetURL); ok {
		versionInfo.Version = version
		versionInfo.Detected = true
		versionInfo.Methods = append(versionInfo.Methods, "html-comment")
		versionInfo.Confidence = 0.9
		return versionInfo
	}

	// Method 3: Check administrator login page
	if version, ok := d.detectViaAdminPage(targetURL); ok {
		versionInfo.Version = version
		versionInfo.Detected = true
		versionInfo.Methods = append(versionInfo.Methods, "admin-page")
		versionInfo.Confidence = 0.85
		return versionInfo
	}

	// Method 4: Check component versions
	if version, ok := d.detectViaComponents(targetURL); ok {
		versionInfo.Version = version
		versionInfo.Detected = true
		versionInfo.Methods = append(versionInfo.Methods, "component-version")
		versionInfo.Confidence = 0.70
		return versionInfo
	}

	return versionInfo
}

// detectViaRobotsFile checks for robots.txt specific to Joomla
func (d *Detector) detectViaRobotsFile(targetURL string) bool {
	resp, err := d.client.Get(targetURL + "/robots.txt")
	if err != nil || resp.StatusCode != 200 {
		return false
	}

	content := resp.String()
	joomlaPatterns := []string{
		"administrator/",
		"index.php?option=com_",
		"Disallow: /administrator",
	}

	for _, pattern := range joomlaPatterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}
	return false
}

// detectViaMetaTags checks for Joomla meta tags in HTML
func (d *Detector) detectViaMetaTags(targetURL string) bool {
	resp, err := d.client.Get(targetURL)
	if err != nil || resp.StatusCode != 200 {
		return false
	}

	content := resp.String()
	joomlaPatterns := []string{
		`<meta\s+name="generator"\s+content="Joomla`,
		`<meta\s+property="og:image"`,
		`name="viewport".*content="`,
	}

	re := regexp.MustCompile(strings.Join(joomlaPatterns, "|"))
	return re.MatchString(content)
}

// detectViaJQueryReadyJS checks for Joomla's specific JavaScript patterns
func (d *Detector) detectViaJQueryReadyJS(targetURL string) bool {
	resp, err := d.client.Get(targetURL)
	if err != nil || resp.StatusCode != 200 {
		return false
	}

	content := resp.String()
	return strings.Contains(content, "jQuery(document).ready(function") &&
		strings.Contains(content, "Joomla.submitbutton")
}

// detectViaGenerator checks meta generator tag
func (d *Detector) detectViaGenerator(targetURL string) bool {
	resp, err := d.client.Get(targetURL)
	if err != nil || resp.StatusCode != 200 {
		return false
	}

	content := resp.String()
	re := regexp.MustCompile(`<meta\s+name="generator"\s+content="Joomla!?\s*(.+?)"`)
	return re.MatchString(content)
}

// detectViaXJoomlaHeader checks for X-Joomla HTTP header
func (d *Detector) detectViaXJoomlaHeader(targetURL string) bool {
	resp, err := d.client.Get(targetURL)
	if err != nil {
		return false
	}

	return resp.GetHeader("X-Joomla") != ""
}

// detectViaManifest checks administrator manifest.xml
func (d *Detector) detectViaManifest(targetURL string) (string, bool) {
	manifestPaths := []string{
		"/administrator/manifests/files/joomla.xml",
		"/administrator/manifests/files/joomla-core-files.xml",
	}

	for _, path := range manifestPaths {
		resp, err := d.client.Get(targetURL + path)
		if err == nil && resp.StatusCode == 200 {
			content := resp.String()
			re := regexp.MustCompile(`<version>([0-9.]+)</version>`)
			matches := re.FindStringSubmatch(content)
			if len(matches) > 1 {
				return matches[1], true
			}
		}
	}
	return "", false
}

// detectViaHTMLComment checks for version in HTML comments
func (d *Detector) detectViaHTMLComment(targetURL string) (string, bool) {
	resp, err := d.client.Get(targetURL)
	if err != nil || resp.StatusCode != 200 {
		return "", false
	}

	content := resp.String()
	re := regexp.MustCompile(`<!--\s*Joomla!?\s*(.+?)\s*-->`)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		return matches[1], true
	}
	return "", false
}

// detectViaAdminPage checks administrator login page
func (d *Detector) detectViaAdminPage(targetURL string) (string, bool) {
	adminPaths := []string{
		"/administrator/",
		"/administrator/index.php",
	}

	for _, path := range adminPaths {
		resp, err := d.client.Get(targetURL + path)
		if err == nil && resp.StatusCode == 200 {
			content := resp.String()
			re := regexp.MustCompile(`version["\']?\s*[:=]\s*["\']([0-9.]+)["\']`)
			matches := re.FindStringSubmatch(content)
			if len(matches) > 1 {
				return matches[1], true
			}
		}
	}
	return "", false
}

// detectViaComponents detects version from installed components
func (d *Detector) detectViaComponents(targetURL string) (string, bool) {
	// Try to get version from a known component
	resp, err := d.client.Get(targetURL + "/administrator/components/com_banners/banners.php")
	if err == nil && resp.StatusCode == 200 {
		// If the component exists, we're likely on Joomla 3.x+
		return "3.x", true
	}
	return "", false
}

// EnumerateComponents finds installed components
func (d *Detector) EnumerateComponents(targetURL string) []models.Component {
	var components []models.Component

	// Common Joomla components
	commonComponents := []string{
		"banners", "categories", "com_contact", "com_content",
		"com_fields", "com_installer", "com_languages", "com_media",
		"com_menus", "com_modules", "com_plugins", "com_tags",
		"com_templates", "com_users", "com_weblinks", "com_workflow",
	}

	for _, comp := range commonComponents {
		resp, err := d.client.Get(fmt.Sprintf("%s/administrator/components/com_%s/", targetURL, comp))
		if err == nil && resp.StatusCode == 200 {
			components = append(components, models.Component{
				Name:      comp,
				Type:      "component",
				Path:      fmt.Sprintf("/components/com_%s/", comp),
				Detected:  true,
				Installed: true,
			})
		}
	}

	return components
}

// EnumerateTemplates finds installed templates
func (d *Detector) EnumerateTemplates(targetURL string) []models.Template {
	var templates []models.Template

	// Check common template locations
	resp, err := d.client.Get(targetURL + "/templates/")
	if err == nil && resp.StatusCode == 200 {
		// Parse directory listing or check for specific templates
		content := resp.String()
		if strings.Contains(content, "protostar") {
			templates = append(templates, models.Template{
				Name: "protostar",
				Path: "/templates/protostar/",
			})
		}
		if strings.Contains(content, "beez3") {
			templates = append(templates, models.Template{
				Name: "beez3",
				Path: "/templates/beez3/",
			})
		}
	}

	return templates
}
