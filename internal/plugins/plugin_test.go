package plugins_test

import (
	"testing"

	"github.com/khaleddevsec/Reconpipeline/internal/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noopPlugin struct{ name string }

func (p *noopPlugin) Name() string        { return p.name }
func (p *noopPlugin) Version() string     { return "0.1.0" }
func (p *noopPlugin) Description() string { return "noop" }
func (p *noopPlugin) Validate() error     { return nil }
func (p *noopPlugin) Run() error          { return nil }

func TestRegistry_Register(t *testing.T) {
	r := plugins.New()
	r.Register(&noopPlugin{name: "test"})

	got, ok := r.Get("test")
	require.True(t, ok)
	assert.Equal(t, "test", got.Name())
	assert.Equal(t, "0.1.0", got.Version())
}

func TestRegistry_Register_Overwrite(t *testing.T) {
	r := plugins.New()
	r.Register(&noopPlugin{name: "p"})
	r.Register(&noopPlugin{name: "p"}) // overwrite
	assert.Len(t, r.All(), 1)
}

func TestRegistry_All(t *testing.T) {
	r := plugins.New()
	r.Register(&noopPlugin{name: "a"})
	r.Register(&noopPlugin{name: "b"})
	assert.Len(t, r.All(), 2)
}

func TestRegistry_Get_NotFound(t *testing.T) {
	r := plugins.New()
	_, ok := r.Get("missing")
	assert.False(t, ok)
}
