package plugins

// Plugin is the interface all ThreatLens plugins must implement.
type Plugin interface {
	Name() string
	Version() string
	Description() string
	Validate() error
	Run() error
}

// Registry manages loaded plugins.
type Registry struct {
	plugins map[string]Plugin
}

// New returns an empty Registry.
func New() *Registry {
	return &Registry{plugins: make(map[string]Plugin)}
}

// Register adds a plugin; overwrites any existing plugin with the same name.
func (r *Registry) Register(p Plugin) {
	r.plugins[p.Name()] = p
}

// Get retrieves a plugin by name.
func (r *Registry) Get(name string) (Plugin, bool) {
	p, ok := r.plugins[name]
	return p, ok
}

// All returns all registered plugins.
func (r *Registry) All() []Plugin {
	out := make([]Plugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		out = append(out, p)
	}
	return out
}
