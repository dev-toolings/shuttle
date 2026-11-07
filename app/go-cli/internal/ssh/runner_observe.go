package ssh

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ObserveClosedRun verifies the supervisor's durable closure from another CLI
// invocation. It never takes a new lease or stops somebody else's process.
// A missing or unresolved receipt remains an explicit recovery prerequisite.
func (r *BuildRunner) ObserveClosedRun(app, token string) (FenceResult, error) {
	if !validRunnerComponent(app) || !regexp.MustCompile(`^[a-f0-9]{24,64}$`).MatchString(token) {
		return FenceResult{}, errors.New("invalid recorded runner identity")
	}
	if err := r.Prepare(); err != nil {
		return FenceResult{}, err
	}
	if r.production == nil || r.runnerID == "" {
		return FenceResult{}, errors.New("recorded runner requires its pinned production target")
	}
	command := "python3 -c " + shellQuote(observeClosedRunProgram) + " " + shellQuote(app) + " " + shellQuote(token) + " " + shellQuote(r.runnerID) + " " + shellQuote(r.BuilderName())
	result := r.runRemote(command)
	if result.Code != 0 {
		return FenceResult{}, fmt.Errorf("runner closure cannot be observed: %s", boundedDiagnostic(result.Stderr, result.Stdout))
	}
	var observed struct {
		Token      string   `json:"token"`
		Boot       string   `json:"boot"`
		Containers []string `json:"containers"`
		Receipt    string   `json:"receipt"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &observed); err != nil {
		return FenceResult{}, err
	}
	if observed.Token != token || observed.Boot == "" || observed.Receipt == "" {
		return FenceResult{}, errors.New("runner closure response identity mismatch")
	}
	digest := sha256.Sum256([]byte(result.Stdout))
	host, _, _ := r.endpoint()
	// This is the run's planned tunnel identity even when failure preceded
	// tunnel creation. The remote observation proves its PID file is absent.
	tunnel := token + ":" + r.production.User + "@" + r.production.Host + ":" + fmt.Sprint(r.production.Port)
	return FenceResult{Status: FenceStatusFenced, RunToken: token, RunnerHost: host, RunnerHostKey: r.Config.HostKey, BootID: strings.TrimSpace(observed.Boot), Namespace: r.runnerID, ActualContainerIDs: observed.Containers, TunnelIdentity: tunnel, AdmissionState: "closed", FinishedAt: time.Now().UTC(), ProofHash: "sha256:" + hex.EncodeToString(digest[:])}, nil
}

const observeClosedRunProgram = `import json,os,pathlib,re,stat,subprocess,sys
app,token,namespace,builder=sys.argv[1:]
base=pathlib.Path.home()/'.shuttle/build-runners'
root=base/app/'runs'/token
def read(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077 or info.st_size>16384:raise RuntimeError('unsafe runner receipt')
  data=os.read(fd,16385)
  if len(data)>16384:raise RuntimeError('oversized runner receipt')
  return data.decode()
 finally:os.close(fd)
receipt=read(root/'receipt')
fields=dict(line.split('=',1) for line in receipt.splitlines() if '=' in line)
if fields.get('state')!='fenced' or fields.get('run_token')!=token or fields.get('reason'):raise RuntimeError('runner has not proven closure')
if (base/'leases'/namespace).exists():raise RuntimeError('runner namespace still has a lease')
if (base/app/(token+'.pid')).exists():raise RuntimeError('runner tunnel still has a process identity')
ids=[]
for line in read(root/'containers').splitlines():
 ident,image,network,name=line.split('|')
 if not re.fullmatch('[a-f0-9]{64}',ident) or name!=builder or network!='host':raise RuntimeError('invalid runner resource inventory')
 item=json.loads(subprocess.check_output(['docker','inspect',ident],timeout=10))[0]
 if item['Id']!=ident or item['Config']['Image']!=image or item['HostConfig']['NetworkMode']!=network or item['State']['Running']:raise RuntimeError('recorded runner container is not closed')
 ids.append(ident)
print(json.dumps({'token':token,'boot':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'containers':ids,'receipt':receipt},sort_keys=True))
`
