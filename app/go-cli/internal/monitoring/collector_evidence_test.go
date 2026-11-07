package monitoring

import (
	"strings"
	"testing"
)

func TestPostgresClusterEvidenceUsesPgLSClustersColumns(t *testing.T) {
	port, status, found := postgresClusterEvidence("17 main 5432 online postgres /var/lib/postgresql/17/main /var/log/postgresql/postgresql-17-main.log\n", 17, "main")
	if !found || port != 5432 || status != "online" {
		t.Fatalf("unexpected pg_lsclusters evidence: port=%d status=%q found=%v", port, status, found)
	}
	_, _, dataDir, foundRow := postgresClusterRow("17 main 5432 online postgres /var/lib/postgresql/17/main /var/log/postgresql/postgresql-17-main.log\n", 17, "main")
	if !foundRow || dataDir != "/var/lib/postgresql/17/main" {
		t.Fatalf("pg_lsclusters data directory was not parsed: dataDir=%q found=%v", dataDir, foundRow)
	}
	if port, status, found := postgresClusterEvidence("17 main 5432 online postgres", 16, "main"); found || port != 0 || status != "" {
		t.Fatalf("wrong configured version was accepted: port=%d status=%q found=%v", port, status, found)
	}
	if _, _, found := postgresClusterEvidence("17 main not-a-port online postgres", 17, "main"); found {
		t.Fatal("malformed cluster port was accepted")
	}
}

func TestRegistryBindingsAndListenersRequireExactLoopbackIdentity(t *testing.T) {
	exact := map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{"5000/tcp": {{HostIP: "127.0.0.1", HostPort: "5000"}}}
	if !registryBindingsExact(exact) {
		t.Fatal("exact registry binding was rejected")
	}
	public := map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{"5000/tcp": {{HostIP: "127.0.0.1", HostPort: "5000"}}, "5000/udp": {{HostIP: "127.0.0.1", HostPort: "5000"}}}
	if registryBindingsExact(public) {
		t.Fatal("additional registry binding was accepted")
	}
	if !registryListenerExact("LISTEN 0 128 127.0.0.1:5000 0.0.0.0:*\n") {
		t.Fatal("exact loopback listener was rejected")
	}
	for _, listener := range []string{
		"LISTEN 0 128 0.0.0.0:5000 0.0.0.0:*\n",
		"LISTEN 0 128 [::]:5000 [::]:*\n",
		"LISTEN 0 128 127.0.0.1:5000 0.0.0.0:*\nLISTEN 0 128 127.0.0.2:5000 0.0.0.0:*\n",
	} {
		if registryListenerExact(listener) {
			t.Fatalf("unexpected listener was accepted: %q", listener)
		}
	}
}

func TestMalformedSerializedTaskAndHealthEvidenceIsUnavailable(t *testing.T) {
	if _, _, err := parseTaskEvidence("Running without tab"); err == nil {
		t.Fatal("malformed task evidence was accepted")
	}
	if _, err := parseContainerHealth("not-json"); err == nil {
		t.Fatal("malformed health evidence was accepted")
	}
	if status, err := parseContainerHealth(`{"Status":"unhealthy"}`); err != nil || status != "unhealthy" {
		t.Fatalf("unexpected serialized health result: status=%q err=%v", status, err)
	}
	if strings.TrimSpace("\n") != "" {
		t.Fatal("test fixture sanity check failed")
	}
}

func TestExecutedTaskImageRequiresFullDigestIdentity(t *testing.T) {
	image, err := parseExecutedImage(`"demo-web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`)
	if err != nil || imageRepoDigest(image) == "" {
		t.Fatalf("JSON task image was rejected: image=%q err=%v", image, err)
	}
	matched, identity := executedImageMatchesExpected(
		"demo-web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"registry.example/demo-web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	if !matched || !identity {
		t.Fatal("matching repo digests were not accepted")
	}
	matched, identity = executedImageMatchesExpected(
		"demo-web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"demo-web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	)
	if matched || !identity {
		t.Fatal("old digest was treated as the retained manifest")
	}
	if _, identity = executedImageMatchesExpected("demo-web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "demo-web:latest"); identity {
		t.Fatal("missing digest identity was accepted")
	}
	tasks, err := parseDesiredRunningTasks("taskweb1\tRunning 5 seconds ago\tRunning\t\n")
	if err != nil || len(tasks) != 1 || !taskRunningHealthy(tasks[0]) {
		t.Fatalf("serialized running task was rejected: %#v %v", tasks, err)
	}
	if _, err := parseDesiredRunningTasks("Running 5 seconds ago\tRunning\t\n"); err == nil {
		t.Fatal("task evidence without an id was accepted")
	}
}

func TestParseDesiredRunningTasksPreservesEmptyFinalColumn(t *testing.T) {
	single := "taskweb1\tRunning 5 seconds ago\tRunning\t\n"
	tasks, err := parseDesiredRunningTasks(single)
	if err != nil || len(tasks) != 1 || tasks[0].ID != "taskweb1" || tasks[0].Error != "" || !taskRunningHealthy(tasks[0]) {
		t.Fatalf("single-row empty Error was rejected: %#v %v", tasks, err)
	}
	crlf := "taskweb1\tRunning 5 seconds ago\tRunning\t\r\n"
	tasks, err = parseDesiredRunningTasks(crlf)
	if err != nil || len(tasks) != 1 || tasks[0].Error != "" || !taskRunningHealthy(tasks[0]) {
		t.Fatalf("CRLF empty Error was rejected: %#v %v", tasks, err)
	}
	multiple := "taskweb1\tRunning 5 seconds ago\tRunning\t\n" + "taskweb2\tRunning 5 seconds ago\tRunning\t\n"
	tasks, err = parseDesiredRunningTasks(multiple)
	if err != nil || len(tasks) != 2 || tasks[0].ID != "taskweb1" || tasks[1].ID != "taskweb2" || !taskRunningHealthy(tasks[0]) || !taskRunningHealthy(tasks[1]) {
		t.Fatalf("multiple-row empty Error was rejected: %#v %v", tasks, err)
	}
	if _, err := parseDesiredRunningTasks("taskweb1\tRunning 5 seconds ago\tRunning\n"); err == nil {
		t.Fatal("3-field row missing Error column was accepted")
	}
	if _, err := parseDesiredRunningTasks("\tRunning 5 seconds ago\tRunning\t\n"); err == nil {
		t.Fatal("missing task id was accepted")
	}
	if _, err := parseDesiredRunningTasks("taskweb1\tRunning 5 seconds ago\tRunning\t\ntaskweb1\tRunning 5 seconds ago\tRunning\t\n"); err == nil {
		t.Fatal("duplicate task ids were accepted")
	}
}
