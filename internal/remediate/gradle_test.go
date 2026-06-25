package remediate

import (
	"os"
	"path/filepath"
	"testing"
)

// writeRepo lays out a minimal multi-signal Gradle project in a temp dir, shared
// by the extractor and pipeline tests. It declares two literal-versioned deps
// (bcpkix, okio), one interpolated via ${...} (the BOM) and one via $var
// (com.example:lib), a version-less dep (quarkus-rest), and a decoy under
// build/ that must be skipped.
func writeRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	buildKts := `dependencies {
    implementation(enforcedPlatform("io.quarkus.platform:quarkus-bom:${quarkusPlatformVersion}"))
    implementation("io.quarkus:quarkus-rest")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.79")
    implementation("com.squareup.okio:okio:3.12.0")
    implementation("com.example:lib:$libVersion")
}
`
	if err := os.WriteFile(filepath.Join(root, "build.gradle.kts"), []byte(buildKts), 0o644); err != nil {
		t.Fatal(err)
	}
	props := "quarkusPlatformVersion=3.36.0\nlibVersion=1.0.0\n# comment=ignored\n"
	if err := os.WriteFile(filepath.Join(root, "gradle.properties"), []byte(props), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "build"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "build", "decoy.gradle.kts"), []byte(`implementation("org.bouncycastle:bcpkix-jdk18on:0.1")`), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}
