package knowledge

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	knowledgefs "github.com/khaleddevsec/Reconpipeline/v2/knowledge"
	"github.com/khaleddevsec/Reconpipeline/v2/models"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// yamlFinding is the on-disk representation of a security finding.
type yamlFinding struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Severity    string   `yaml:"severity"`
	Confidence  float64  `yaml:"confidence"`
	Evidence    []string `yaml:"evidence"`
	References  []string `yaml:"references"`
	CWEID       string   `yaml:"cwe_id"`
	CAPECID     string   `yaml:"capec_id"`
	MITREAttack []string `yaml:"mitre_attack"`
	OWASP       []string `yaml:"owasp"`
	Remediation string   `yaml:"remediation"`

	// trigger conditions (at most one set per entry)
	HeaderName          string `yaml:"header_name"`          // trigger when this header is absent
	FingerprintName     string `yaml:"fingerprint_name"`     // trigger for this technology name
	FingerprintCategory string `yaml:"fingerprint_category"` // trigger for this category
	TLSWeakProtocol     bool   `yaml:"tls_weak_protocol"`    // trigger when WeakProtocol == true
	TLSWeakCipher       bool   `yaml:"tls_weak_cipher"`      // trigger when WeakCipher == true
	TLSExpiredCert      bool   `yaml:"tls_expired_cert"`     // trigger when cert is expired
	TLSSelfSigned       bool   `yaml:"tls_self_signed"`      // trigger when cert is self-signed
}

type dbMeta struct {
	Version string `yaml:"version"`
}

// YAMLDatabase implements DB using local or embedded YAML files.
type YAMLDatabase struct {
	mu             sync.RWMutex
	headerFindings map[string][]models.Finding // keyed by lowercase header name
	fpFindings     []struct {
		name     string
		category string
		finding  models.Finding
	}
	tlsFindings []struct {
		weakProto   bool
		weakCipher  bool
		expiredCert bool
		selfSigned  bool
		finding     models.Finding
	}
	version string
	log     *zap.Logger
}

// NewYAMLDatabase returns an uninitialised YAMLDatabase.
func NewYAMLDatabase(log *zap.Logger) *YAMLDatabase {
	return &YAMLDatabase{
		headerFindings: make(map[string][]models.Finding),
		log:            log,
	}
}

// Load walks path and ingests all *.yaml / *.yml knowledge files.
func (d *YAMLDatabase) Load(path string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("knowledge: db path not found: %w", err)
	}

	count := 0
	err := filepath.WalkDir(path, func(fp string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(fp))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		if de.Name() == "meta.yaml" || de.Name() == "meta.yml" {
			return d.loadMeta(fp)
		}
		n, loadErr := d.loadFile(fp)
		if loadErr != nil {
			d.log.Warn("knowledge: skipping file", zap.String("path", fp), zap.Error(loadErr))
			return nil
		}
		count += n
		return nil
	})
	if err != nil {
		return fmt.Errorf("knowledge: walk: %w", err)
	}

	d.log.Info("knowledge DB loaded",
		zap.Int("entries", count),
		zap.String("version", d.version))
	return nil
}

// LoadEmbedded ingests the built-in embedded YAML knowledge base.
func (d *YAMLDatabase) LoadEmbedded() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	count := 0
	err := fs.WalkDir(knowledgefs.DefaultFS, ".", func(fp string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return err
		}
		ext := strings.ToLower(filepath.Ext(fp))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, readErr := knowledgefs.DefaultFS.ReadFile(fp)
		if readErr != nil {
			return readErr
		}
		if de.Name() == "meta.yaml" || de.Name() == "meta.yml" {
			var m dbMeta
			if err := yaml.Unmarshal(data, &m); err != nil {
				return fmt.Errorf("knowledge: parse embedded meta: %w", err)
			}
			d.version = m.Version
			return nil
		}
		n, parseErr := d.parseBytes(fp, data)
		if parseErr != nil {
			d.log.Warn("knowledge: skipping embedded file", zap.String("path", fp), zap.Error(parseErr))
			return nil
		}
		count += n
		return nil
	})
	if err != nil {
		return fmt.Errorf("knowledge: load embedded: %w", err)
	}

	d.log.Info("embedded knowledge DB loaded",
		zap.Int("entries", count),
		zap.String("version", d.version))
	return nil
}

func (d *YAMLDatabase) loadMeta(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("knowledge: read meta: %w", err)
	}
	var m dbMeta
	if err := yaml.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("knowledge: parse meta: %w", err)
	}
	d.version = m.Version
	return nil
}

func (d *YAMLDatabase) loadFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("knowledge: read %q: %w", path, err)
	}
	return d.parseBytes(path, data)
}

func (d *YAMLDatabase) parseBytes(path string, data []byte) (int, error) {
	var entries []yamlFinding
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return 0, fmt.Errorf("knowledge: parse %q: %w", path, err)
	}
	for _, e := range entries {
		f := toFinding(e)
		switch {
		case e.HeaderName != "":
			key := strings.ToLower(e.HeaderName)
			d.headerFindings[key] = append(d.headerFindings[key], f)
		case e.FingerprintName != "" || e.FingerprintCategory != "":
			d.fpFindings = append(d.fpFindings, struct {
				name     string
				category string
				finding  models.Finding
			}{
				name:     strings.ToLower(e.FingerprintName),
				category: strings.ToLower(e.FingerprintCategory),
				finding:  f,
			})
		case e.TLSWeakProtocol || e.TLSWeakCipher || e.TLSExpiredCert || e.TLSSelfSigned:
			d.tlsFindings = append(d.tlsFindings, struct {
				weakProto   bool
				weakCipher  bool
				expiredCert bool
				selfSigned  bool
				finding     models.Finding
			}{e.TLSWeakProtocol, e.TLSWeakCipher, e.TLSExpiredCert, e.TLSSelfSigned, f})
		}
	}
	return len(entries), nil
}

func toFinding(e yamlFinding) models.Finding {
	return models.Finding{
		ID:          e.ID,
		Title:       e.Title,
		Description: e.Description,
		Severity:    models.Severity(strings.ToUpper(e.Severity)),
		Confidence:  e.Confidence,
		Evidence:    e.Evidence,
		References:  e.References,
		CWEID:       e.CWEID,
		CAPECID:     e.CAPECID,
		MITREAttack: e.MITREAttack,
		OWASP:       e.OWASP,
		Remediation: e.Remediation,
	}
}

// FindingsForHeader returns findings triggered by the presence (or absence) of a header.
// Pass value="" to indicate the header is absent.
func (d *YAMLDatabase) FindingsForHeader(name, _ string) ([]models.Finding, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.headerFindings[strings.ToLower(name)], nil
}

// FindingsForFingerprint returns findings matching the detected technology.
func (d *YAMLDatabase) FindingsForFingerprint(fp models.Fingerprint) ([]models.Finding, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	name := strings.ToLower(fp.Name)
	cat := strings.ToLower(fp.Category)

	var results []models.Finding
	for _, entry := range d.fpFindings {
		if (entry.name != "" && entry.name == name) ||
			(entry.category != "" && entry.category == cat) {
			results = append(results, entry.finding)
		}
	}
	return results, nil
}

// FindingsForTLS returns findings triggered by TLS weaknesses.
func (d *YAMLDatabase) FindingsForTLS(tls *models.TLSInfo) ([]models.Finding, error) {
	if tls == nil {
		return nil, nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	var results []models.Finding
	for _, entry := range d.tlsFindings {
		if (entry.weakProto && tls.WeakProtocol) ||
			(entry.weakCipher && tls.WeakCipher) ||
			(entry.expiredCert && tls.Expired) ||
			(entry.selfSigned && tls.SelfSigned) {
			results = append(results, entry.finding)
		}
	}
	return results, nil
}

// Integrity checks that at least one knowledge entry was loaded.
func (d *YAMLDatabase) Integrity() error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.headerFindings) == 0 && len(d.fpFindings) == 0 && len(d.tlsFindings) == 0 {
		return fmt.Errorf("knowledge: DB is empty")
	}
	return nil
}

// Version returns the loaded DB version string.
func (d *YAMLDatabase) Version() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.version
}
