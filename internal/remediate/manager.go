package remediate

// Manager extracts declared dependencies from a project's build files. Gradle is
// the only manager today; the interface is the seam for adding npm/PyPI/etc.
// (roadmap M4) without touching the worker or platform.
type Manager interface {
	// Name is the manager's identifier (used for config matchManagers).
	Name() string
	// Extract enumerates editable dependency version sites under root.
	Extract(root string) ([]DeclaredDependency, error)
}

// GradleManager is the Gradle/Maven manager.
type GradleManager struct{}

// Name implements Manager.
func (GradleManager) Name() string { return "gradle" }

// Extract implements Manager.
func (GradleManager) Extract(root string) ([]DeclaredDependency, error) {
	g, err := NewGradleResolver(root)
	if err != nil {
		return nil, err
	}
	return g.ExtractDeclared(), nil
}

// Managers returns the default manager set, in stable order.
func Managers() []Manager {
	return []Manager{GradleManager{}, PyPIManager{}, NPMManager{}}
}
