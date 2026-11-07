package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/backup"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
	"github.com/spf13/cobra"
)

var rebootOperationID = regexp.MustCompile(`^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$`)

type rebootReport struct {
	Schema        string `json:"schema"`
	OperationID   string `json:"operation_id"`
	State         string `json:"state"`
	BootBefore    string `json:"boot_before,omitempty"`
	BootAfter     string `json:"boot_after,omitempty"`
	Error         string `json:"error,omitempty"`
	HTTPSRequired bool   `json:"https_required"`
}

func newRebootCommand() *cobra.Command {
	var flags configFlags
	var yes, dryRun, asJSON bool
	var resume string
	c := &cobra.Command{Use: "reboot", Short: "Reboot through the SSH administrator and verify services return", Args: cobra.NoArgs, SilenceUsage: true, RunE: func(cmd *cobra.Command, _ []string) error {
		if !yes && !dryRun {
			err := errors.New("reboot requires --yes after reviewing --dry-run")
			if asJSON {
				report := rebootReport{Schema: "shuttle.reboot/v1", OperationID: resume, State: "not-started", Error: err.Error()}
				if writeErr := writeRebootOutcome(cmd.OutOrStdout(), report, true); writeErr != nil {
					return errors.Join(err, writeErr)
				}
			}
			return err
		}
		cfg, err := loadWithFlags(flags)
		if err != nil {
			return err
		}
		if dryRun {
			fmt.Fprintln(cmd.OutOrStdout(), "Would reserve the VPS, reboot, then verify operator SSH, retained services, native PostgreSQL, registry and public HTTPS.")
			return nil
		}
		report, err := rebootVPS(cfg, resume)
		if err != nil && report.Error == "" {
			report.Error = err.Error()
		}
		if writeErr := writeRebootOutcome(cmd.OutOrStdout(), report, asJSON); writeErr != nil && err == nil {
			err = writeErr
		}
		return err
	}}
	addConfigFlags(c, &flags)
	c.Flags().BoolVar(&yes, "yes", false, "authorize the reboot and its expected service interruption")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "describe the reboot without changing the VPS")
	c.Flags().StringVar(&resume, "resume", "", "resume verification of this planned reboot operation")
	c.Flags().BoolVar(&asJSON, "json", false, "print a structured reboot outcome, including failures")
	return c
}

func rebootVPS(cfg *config.Config, resume string) (rebootReport, error) {
	id, err := resolveRebootOperationID(resume)
	report := rebootReport{Schema: "shuttle.reboot/v1", OperationID: id, State: "not-started"}
	if err != nil {
		report.Error = err.Error()
		return report, err
	}
	group, host, err := singleVPS(cfg)
	if err != nil {
		return report, err
	}
	if cfg.Setup.OperatorUser == "" || cfg.Setup.OperatorUser == "deploy" || cfg.Setup.OperatorUser == "root" {
		return report, errors.New("reboot requires setup.operator_user naming the separate SSH administrator")
	}
	identity, err := loadTrustedHostIdentity(host, group.Port)
	if err != nil {
		return report, err
	}
	client, err := shuttlessh.NewClientExactWithFingerprint(host, cfg.Setup.OperatorUser, group.Port, identity.HostKeyFingerprint)
	if err != nil {
		return report, err
	}
	client.SetOperationTimeout(45 * time.Second)
	request := map[string]any{"id": id, "app": cfg.App, "owner": identity.OperatorKeyFingerprint, "host": identity.HostKeyFingerprint}
	if resume == "" {
		if err := runRebootStep(client, request, "schedule", &report); err != nil {
			return report, err
		}
	}
	deadline := time.Now().Add(5 * time.Minute)
	var lastErr error
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		if err := runRebootStep(client, request, "verify", &report); err != nil {
			lastErr = err
			continue
		}
		if report.State == "completed" {
			if err := requireRebootBootChange(report); err != nil {
				return report, err
			}
			return report, nil
		}
		if report.State != "ready" {
			continue
		}
		if err := requireRebootBootChange(report); err != nil {
			lastErr = err
			continue
		}
		url := cfg.Deploy.AvailabilityURL
		if url == "" {
			url = "https://" + domainString(cfg.Domain) + cfg.Readiness.HealthcheckPath
		}
		if err := checkRebootHTTPS(cfg, url, report.HTTPSRequired); err != nil {
			lastErr = err
			continue
		}
		if report.HTTPSRequired {
			request["https_verified"] = true
		}
		if err := runRebootStep(client, request, "finish", &report); err != nil {
			return report, err
		}
		if err := requireRebootBootChange(report); err != nil {
			return report, err
		}
		return report, nil
	}
	report.State = "recovery_required"
	return report, fmt.Errorf("reboot did not complete all postconditions within five minutes; operation %s remains recoverable: %w", id, errors.Join(errors.New("post-reboot verification incomplete"), lastErr))
}

func runRebootStep(client *shuttlessh.Client, request map[string]any, action string, report *rebootReport) error {
	request["action"] = action
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	command, err := backup.PythonCommand(rebootProgram, nil)
	if err != nil {
		return err
	}
	response := client.RunWithStdin(command, body)
	if response.Stdout == "" {
		return fmt.Errorf("reboot %s returned no structured outcome (SSH exit %d)", action, response.Code)
	}
	var received rebootReport
	if err := decodeSingleJSON([]byte(response.Stdout), &received); err != nil {
		return fmt.Errorf("decode reboot outcome: %w", err)
	}
	if received.Schema != "shuttle.reboot/v1" || received.OperationID != report.OperationID {
		return errors.New("reboot response identity mismatch")
	}
	*report = received
	if response.Code != 0 {
		return fmt.Errorf("reboot %s failed: %s", action, response.Stderr)
	}
	valid := (action == "schedule" && report.State == "scheduled") || (action == "verify" && (report.State == "ready" || report.State == "waiting" || report.State == "completed")) || (action == "finish" && report.State == "completed")
	if !valid {
		return errors.New("reboot returned an unexpected state for its verified phase")
	}
	return nil
}

// This program travels only over the separately authenticated administrator
// channel, as backups do. Every journal check and mutation uses the same flock
// as signed helper operations; setup never grants deploy a general reboot sudo.
const rebootProgram = `import base64,contextlib,datetime,fcntl,json,os,pathlib,re,stat,subprocess,sys,tempfile,time
ROOT=pathlib.Path('/var/lib/shuttle/operations')
LOCK='/run/shuttle-root.lock'
MIGRATION='/var/lib/shuttle/helper-migration/intent.json'
MIGRATION_MAX=16384
MIGRATION_UID=0
UNIT_LOAD_STATES=frozenset(('loaded','not-found','error','bad-setting','masked','stub'))
SCHEDULE_WINDOW=datetime.timedelta(minutes=15)

def stamp():
 return datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def boot():
 return pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
def run(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=10)
 if p.returncode: raise RuntimeError('postcondition failed: '+args[0])
 return p.stdout.strip()
@contextlib.contextmanager
def locked():
 fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
 try:
  deadline=time.monotonic()+30
  while True:
   try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
   except BlockingIOError:
    if time.monotonic()>=deadline: raise RuntimeError('host operation lock is busy')
    time.sleep(.05)
  yield
 finally: os.close(fd)
def persist(path,value):
 fd,tmp=tempfile.mkstemp(prefix='.reboot-',dir=ROOT)
 try:
  with os.fdopen(fd,'w') as f:
   json.dump(value,f);f.flush();os.fsync(f.fileno())
  os.replace(tmp,path)
  fd=os.open(ROOT,os.O_RDONLY)
  try: os.fsync(fd)
  finally: os.close(fd)
 finally:
  if os.path.exists(tmp): os.unlink(tmp)
def inventory():
 services=[]
 for line in run(['docker','service','ls','--format','{{.Name}}|{{.Replicas}}|{{.Image}}']).splitlines():
  name,replicas,image=line.split('|',2)
  match=re.fullmatch(r'(\d+)/(\d+)',replicas)
  if not match or match[1]!=match[2]: raise RuntimeError('service is not converged: '+name)
  ids=run(['docker','ps','-q','--filter','label=com.docker.swarm.service.name='+name]).split()
  if len(ids)!=int(match[2]): raise RuntimeError('running service tasks differ: '+name)
  for cid in ids:
   health=run(['docker','inspect',cid,'--format','{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}'])
   if health not in ('healthy','none'): raise RuntimeError('service task is unhealthy: '+name)
  image=run(['docker','service','inspect',name,'--format','{{.Spec.TaskTemplate.ContainerSpec.Image}}'])
  services.append({'name':name,'replicas':int(match[2]),'image':image})
 return sorted(services,key=lambda item:item['name'])
def postgres():
 clusters=[]
 for line in run(['pg_lsclusters','--no-header']).splitlines():
  fields=line.split()
  if len(fields)<4 or fields[3]!='online': raise RuntimeError('native PostgreSQL cluster is not online')
  run(['pg_isready','-h','/var/run/postgresql','-p',fields[2]])
  clusters.append(fields[:3])
 return clusters
def postconditions(intent):
 if boot()==intent['boot_before']:return False
 run(['systemctl','is-active','ssh']);run(['systemctl','is-active','docker'])
 # A removed registry must not resolve to its same-named data volume.
 registry=json.loads(run(['docker','container','inspect','shuttle-registry','--format','{{json .}}']))
 if not registry['State']['Running'] or registry['State'].get('Health',{}).get('Status')!='healthy':raise RuntimeError('loopback registry is unhealthy')
 bindings=registry['HostConfig'].get('PortBindings',{}).get('5000/tcp',[])
 if len(bindings)!=1 or bindings[0].get('HostIp')!='127.0.0.1' or bindings[0].get('HostPort')!='5000' or registry['HostConfig'].get('RestartPolicy',{}).get('Name')!='always':raise RuntimeError('registry binding or restart policy changed')
 run(['curl','--fail','--silent','--max-time','5','http://127.0.0.1:5000/v2/'])
 if inventory()!=intent['services'] or postgres()!=intent['postgres']:raise RuntimeError('service image/replicas or native PostgreSQL inventory changed')
 return True
def probe(args):
 try: p=subprocess.run(args,capture_output=True,text=True,timeout=10)
 except (subprocess.TimeoutExpired,OSError) as error: raise RuntimeError('reboot unit status is unknown') from error
 return p.returncode,(p.stdout or ''),(p.stderr or '')
def load_state(unit):
 code,out,_err=probe(['systemctl','show',unit,'--property=LoadState','--value'])
 if code!=0: raise RuntimeError('reboot unit status is unknown: '+unit)
 state=(out or '').strip()
 if state not in UNIT_LOAD_STATES or '\n' in state: raise RuntimeError('reboot unit status is malformed: '+unit)
 return state
def reboot_units_absent(identifier):
 timer=load_state('shuttle-reboot-'+identifier+'.timer')
 service=load_state('shuttle-reboot-'+identifier+'.service')
 return timer=='not-found' and service=='not-found'
def arm_reboot(identifier):
 run(['systemd-run','--quiet','--unit=shuttle-reboot-'+identifier,'--on-active=2s','--service-type=oneshot','--property=RemainAfterExit=yes','/usr/bin/systemctl','reboot'])
def parse_started(value):
 if not value or not isinstance(value,str): raise RuntimeError('reboot reservation started_at is missing')
 try: parsed=datetime.datetime.fromisoformat(value.replace('Z','+00:00') if value.endswith('Z') else value)
 except ValueError as error: raise RuntimeError('reboot reservation started_at is invalid') from error
 if parsed.tzinfo is None: raise RuntimeError('reboot reservation started_at is missing a timezone')
 return parsed.astimezone(datetime.timezone.utc)
def scheduling_window(record):
 started=parse_started(record.get('started_at'))
 now=datetime.datetime.now(datetime.timezone.utc)
 if started>now: raise RuntimeError('reboot reservation started_at is in the future')
 if now-started>SCHEDULE_WINDOW: raise RuntimeError('reboot reservation scheduling window has expired')
def refuse_migration_scheduling():
 try: fd=os.open(MIGRATION,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 except FileNotFoundError: return
 except OSError as error: raise RuntimeError('helper migration intent is unreadable') from error
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=MIGRATION_UID or stat.S_IMODE(info.st_mode)!=0o600: raise RuntimeError('helper migration intent is not a root-owned regular file with mode 0600')
  if info.st_size>MIGRATION_MAX: raise RuntimeError('helper migration intent is too large')
  body=os.read(fd,MIGRATION_MAX+1)
 finally: os.close(fd)
 if len(body)>MIGRATION_MAX: raise RuntimeError('helper migration intent is too large')
 try: intent=json.loads(body)
 except ValueError as error: raise RuntimeError('helper migration intent is corrupt') from error
 if not isinstance(intent,dict) or intent.get('schema')!='shuttle.helper-migration/v1': raise RuntimeError('helper migration intent is unknown')
 if not isinstance(intent.get('id'),str) or not re.fullmatch(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',intent['id']): raise RuntimeError('helper migration intent id is invalid')
 if not isinstance(intent.get('candidate_sha256'),str) or not re.fullmatch(r'sha256:[a-f0-9]{64}',intent['candidate_sha256']): raise RuntimeError('helper migration intent digest is invalid')
 phase=intent.get('phase')
 if phase=='completed': return
 if phase in ('prepared','replaced'): raise RuntimeError('helper migration blocks reboot scheduling')
 raise RuntimeError('helper migration intent is unknown')
def ensure_scheduled(identifier,record,intent,path):
 if boot()!=intent.get('boot_before') or boot()!=record.get('host_boot_id'): return
 if intent.get('boot_before')!=record.get('host_boot_id'): raise RuntimeError('reboot reservation baseline is inconsistent')
 if not reboot_units_absent(identifier): return
 scheduling_window(record)
 refuse_migration_scheduling()
 if inventory()!=intent.get('services') or postgres()!=intent.get('postgres'): raise RuntimeError('saved reboot baseline no longer matches the host')
 now=stamp();record['updated_at']=now
 record.setdefault('events',[]).append({'at':now,'kind':'reboot-rescheduled','state':'recovery_required','recovery_required':True})
 persist(path,record)
 arm_reboot(identifier)
def step(request):
 identifier=request['id']
 if not re.fullmatch(r'(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',identifier):raise RuntimeError('invalid reboot operation id')
 if not re.fullmatch('[a-z][a-z0-9-]{0,62}',request['app']):raise RuntimeError('invalid reboot application')
 for key in ('owner','host'):
  if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}',request[key]):raise RuntimeError('invalid reboot identity')
 action=request['action'];ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
 path=ROOT/(identifier+'.json');intentpath=ROOT/(identifier+'.reboot')
 with locked():
  if action=='schedule':
   if request.get('require_pending') and not pathlib.Path('/var/run/reboot-required').exists():return {'schema':'shuttle.reboot/v1','operation_id':identifier,'state':'not-needed','boot_before':boot()}
   refuse_migration_scheduling()
   for existing in ROOT.glob('*.json'):
    record=json.loads(existing.read_text())
    if record.get('schema')!='shuttle.operation/v1':raise RuntimeError('invalid operation journal schema')
    if record.get('state') in ('active','recovery_required') or record.get('recovery_required'):
     # The live recette refusal named only the ID; an operator deciding whether
     # to wait needs the kind, target and age like every other refusal.
     try:age=str(max(0,int(__import__('time').time()-__import__('calendar').timegm(__import__('time').strptime(str(record.get('started_at',''))[:19],'%Y-%m-%dT%H:%M:%S')))))+'s'
     except ValueError:age='unknown'
     raise RuntimeError('operation '+record.get('id','unknown')+' is '+str(record.get('state'))+' for '+str(record.get('kind','unknown'))+' (target '+str(record.get('app') or 'VPS')+', age '+age+') and blocks reboot')
   before=boot();now=stamp()
   intent={'boot_before':before,'services':inventory(),'postgres':postgres(),'https_required':not request.get('require_pending',False)}
   persist(intentpath,intent)
   record={'schema':'shuttle.operation/v1','id':identifier,'kind':'reboot','scope':'global','app':request['app'],'principal':request['owner'],'owner_key_fingerprint':request['owner'],'host':request['host'],'host_boot_id':before,'started_at':now,'updated_at':now,'lease_until':'','state':'recovery_required','recovery_required':True,'result':'planned reboot; post-boot verification pending','phases':[{'name':'reboot-scheduled','started_at':now,'result':'pending postconditions'}],'events':[{'at':now,'kind':'reboot-scheduled','state':'recovery_required','recovery_required':True}]}
   persist(path,record)
   arm_reboot(identifier)
   return {'schema':'shuttle.reboot/v1','operation_id':identifier,'state':'scheduled','boot_before':before}
  record=json.loads(path.read_text());intent=json.loads(intentpath.read_text())
  if record.get('kind')!='reboot' or record.get('principal')!=request['owner'] or record.get('owner_key_fingerprint')!=request['owner'] or record.get('host')!=request['host'] or record.get('app')!=request['app']:raise RuntimeError('reboot reservation identity differs')
  if record.get('state')=='completed' and action in ('verify','finish'):return {'schema':'shuttle.reboot/v1','operation_id':identifier,'state':'completed','boot_before':intent['boot_before'],'boot_after':boot(),'https_required':intent.get('https_required',True)}
  if record.get('state')!='recovery_required' or not record.get('recovery_required'):raise RuntimeError('reboot reservation is no longer pending')
  ready=postconditions(intent)
  if action=='verify' and not ready: ensure_scheduled(identifier,record,intent,path)
  result={'schema':'shuttle.reboot/v1','operation_id':identifier,'state':'ready' if ready else 'waiting','https_required':intent.get('https_required',True),'boot_before':intent['boot_before'],'boot_after':boot()}
  if action=='finish':
   if not ready or (intent.get('https_required',True) and request.get('https_verified') is not True):raise RuntimeError('reboot completion requires fresh host and external HTTPS proofs')
   now=stamp();record.update(state='completed',recovery_required=False,lease_until='',updated_at=now,result='new boot, operator SSH, service identities, native PostgreSQL and registry verified'+('; external HTTPS verified' if intent.get('https_required',True) else ''))
   record['phases'].append({'name':'reboot-verified','started_at':now,'ended_at':now,'result':'verified'})
   record['events'].append({'at':now,'kind':'completed','state':'completed'})
   persist(path,record);result['state']='completed'
  elif action!='verify':raise RuntimeError('unknown reboot action')
  return result
if __name__=='__main__':
 request=json.loads(base64.b64decode(sys.argv[1])) if len(sys.argv)>1 else json.load(sys.stdin)
 try: print(json.dumps(step(request)),flush=True)
 except Exception as error:
  state='not-started'
  identifier=request.get('id','')
  if re.fullmatch(r'(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',identifier):
   try: state=json.loads((ROOT/(identifier+'.json')).read_text()).get('state','recovery_required')
   except (OSError,ValueError): pass
  print(json.dumps({'schema':'shuttle.reboot/v1','operation_id':identifier,'state':state,'error':str(error)[:512]}),flush=True)
  print(str(error)[:512],file=sys.stderr);sys.exit(1)
`

func checkRebootHTTPS(cfg *config.Config, url string, required bool) error {
	if !required {
		return nil
	}
	return newAvailabilityProbe(url, 250, availabilityURLIsGated(cfg)).CheckNow()
}

func resolveRebootOperationID(resume string) (string, error) {
	if resume != "" {
		if !rebootOperationID.MatchString(resume) {
			return resume, errors.New("invalid reboot operation id")
		}
		return resume, nil
	}
	return coord.NewID()
}

func requireRebootBootChange(report rebootReport) error {
	if report.BootBefore == "" || report.BootAfter == "" || report.BootBefore == report.BootAfter {
		return errors.New("reboot completion requires a changed host boot id")
	}
	return nil
}

func writeRebootOutcome(out io.Writer, report rebootReport, asJSON bool) error {
	if asJSON {
		body, err := json.Marshal(report)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(body))
		return err
	}
	_, err := fmt.Fprintf(out, "reboot=%s operation=%s boot_before=%s boot_after=%s\n", report.State, report.OperationID, report.BootBefore, report.BootAfter)
	return err
}

func completeCoordinatedSetupReboot(runner setupRunner, app, owner, host string) (rebootReport, error) {
	id, err := coord.NewID()
	report := rebootReport{Schema: "shuttle.reboot/v1", OperationID: id, State: "not-started"}
	if err != nil {
		return report, err
	}
	request := map[string]any{"id": id, "app": app, "owner": owner, "host": host, "require_pending": true}
	step := func(action string) error {
		request["action"] = action
		command, err := backup.PythonCommand(rebootProgram, request)
		if err != nil {
			return err
		}
		result := runner.run(command)
		if result.Stdout == "" {
			return fmt.Errorf("setup reboot returned no structured outcome: %s", result.Stderr)
		}
		if err := decodeSingleJSON([]byte(result.Stdout), &report); err != nil {
			return err
		}
		if report.Schema != "shuttle.reboot/v1" || report.OperationID != id {
			return errors.New("setup reboot identity mismatch")
		}
		if result.Code != 0 {
			return fmt.Errorf("setup reboot %s failed: %s", action, result.Stderr)
		}
		return nil
	}
	if err := step("schedule"); err != nil {
		return report, err
	}
	if report.State == "not-needed" {
		return report, nil
	}
	if report.State != "scheduled" {
		return report, errors.New("setup reboot was not scheduled")
	}
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		if err := step("verify"); err != nil {
			continue
		}
		if report.State != "ready" {
			continue
		}
		if err := requireRebootBootChange(report); err != nil {
			continue
		}
		if err := step("finish"); err != nil {
			return report, err
		}
		if report.State != "completed" {
			return report, errors.New("setup reboot did not confirm completion")
		}
		if err := requireRebootBootChange(report); err != nil {
			return report, err
		}
		return report, nil
	}
	return report, fmt.Errorf("setup reboot %s did not complete postconditions; use operations reboot --resume %s --yes", id, id)
}
