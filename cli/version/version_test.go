package version

import (
	"testing"

	"github.com/ztdbp/cfssl/cli"
)

func TestVersionMain(t *testing.T) {
	args := []string{"cfssl", "version"}
	err := versionMain(args, cli.Config{})
	if err != nil {
		t.Fatal("version main failed")
	}
}
