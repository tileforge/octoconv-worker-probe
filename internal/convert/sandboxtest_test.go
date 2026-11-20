package convert

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeSandboxHelper(t *testing.T) (helper []string, calls func() [][]string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-sandbox-helper.sh")
	callsPath := script + ".calls"
	const body = `#!/bin/bash
script="$0"
for a in "$@"; do printf '%s\n' "$a" >> "${script}.calls"; done
printf -- '--end--\n' >> "${script}.calls"

args=("$@")
sep=-1
for i in "${!args[@]}"; do
  if [ "${args[$i]}" = "--" ]; then sep=$i; break; fi
done
if [ "$sep" -lt 0 ]; then
  echo "fake-sandbox-helper: no -- separator in argv" >&2
  exit 1
fi
rest=("${args[@]:$((sep+1))}")
exec "${rest[@]}"
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("fakeSandboxHelper: %v", err)
	}
	calls = func() [][]string {
		data, err := os.ReadFile(callsPath)
		if err != nil {
			return nil
		}
		var invocations [][]string
		var cur []string
		for _, line := range strings.Split(string(data), "\n") {
			switch line {
			case "--end--":
				invocations = append(invocations, cur)
				cur = nil
			case "":
			default:
				cur = append(cur, line)
			}
		}
		return invocations
	}
	return []string{script, "__sandbox-exec"}, calls
}

func fakeEngine(t *testing.T, dir, name, script string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	body := "#!/bin/sh\n" + script
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatalf("fakeEngine: %v", err)
	}
	return p
}

func pathWith(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}

func failingSandboxHelper(t *testing.T, code int) []string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "failing-sandbox-helper.sh")
	body := fmt.Sprintf("#!/bin/bash\nexit %d\n", code)
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("failingSandboxHelper: %v", err)
	}
	return []string{script, "__sandbox-exec"}
}
