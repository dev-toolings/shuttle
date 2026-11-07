package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
)

func TestRebootJournalAndPostconditions(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	dir := t.TempDir()
	module := filepath.Join(dir, "reboot_program.py")
	if err := os.WriteFile(module, []byte(rebootProgram), 0600); err != nil {
		t.Fatal(err)
	}
	code := `import datetime,importlib.util,json,os,pathlib,sys,tempfile,unittest
OPID=sys.argv[2]
spec=importlib.util.spec_from_file_location('reboot_program',sys.argv[1]);r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class RebootTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();root=pathlib.Path(self.tmp.name);r.ROOT=root/'ops';r.LOCK=str(root/'lock')
  r.MIGRATION=str(root/'missing-migration.json');r.MIGRATION_UID=os.geteuid()
  self.current_boot='before';r.boot=lambda:self.current_boot
  self.services=[{'name':'demo_web','replicas':1,'image':'example@sha256:abc'}]
  r.inventory=lambda:self.services;r.postgres=lambda:[['17','main','5432']]
  self.request={'id':OPID,'app':'demo','owner':'SHA256:'+'a'*43,'host':'SHA256:'+'b'*43,'action':'schedule'}
  self.scheduled=0;self.unit_active=False;self.fail_schedule=False;self.probe_error=None
  self.timer='shuttle-reboot-'+OPID+'.timer';self.service='shuttle-reboot-'+OPID+'.service'
  self.units={self.timer:'not-found',self.service:'not-found'}
  def run(args):
   if args[0]=='systemd-run':
    record=json.loads((r.ROOT/(OPID+'.json')).read_text());self.assertTrue(record['recovery_required']);self.assertEqual(record.get('lease_until'),'');self.assertTrue((r.ROOT/(OPID+'.reboot')).exists())
    self.assertIn('--service-type=oneshot',args);self.assertIn('--property=RemainAfterExit=yes',args)
    if self.fail_schedule: raise RuntimeError('postcondition failed: systemd-run')
    self.scheduled+=1;self.unit_active=True;self.units[self.timer]='loaded';self.units[self.service]='loaded'
   if args[:3]==['docker','container','inspect']:
    return json.dumps({'State':{'Running':True,'Health':{'Status':'healthy'}},'HostConfig':{'PortBindings':{'5000/tcp':[{'HostIp':'127.0.0.1','HostPort':'5000'}]},'RestartPolicy':{'Name':'always'}}})
   return 'active'
  def probe(args):
   if self.probe_error: raise RuntimeError(self.probe_error)
   if args[:2]==['systemctl','show']:
    state=self.units.get(args[2],'not-found')
    if state=='error-exit': return 1,'','denied'
    if state=='malformed': return 0,'not a load state\n',''
    return 0,state+'\n',''
   return 0,'',''
  r.run=run;r.probe=probe
 def seed_pending(self, started):
  r.ROOT.mkdir(parents=True,exist_ok=True)
  r.persist(r.ROOT/(OPID+'.reboot'),{'boot_before':self.current_boot,'services':self.services,'postgres':[['17','main','5432']],'https_required':True})
  r.persist(r.ROOT/(OPID+'.json'),{'schema':'shuttle.operation/v1','id':OPID,'kind':'reboot','scope':'global','app':'demo','principal':self.request['owner'],'owner_key_fingerprint':self.request['owner'],'host':self.request['host'],'host_boot_id':self.current_boot,'started_at':started,'updated_at':started,'lease_until':'','state':'recovery_required','recovery_required':True,'result':'pending','phases':[{'name':'reboot-scheduled','started_at':started,'result':'pending'}],'events':[{'at':started,'kind':'reboot-scheduled','state':'recovery_required','recovery_required':True}]})
 def write_migration(self, body):
  path=pathlib.Path(self.tmp.name)/'intent.json';path.write_text(body);path.chmod(0o600);r.MIGRATION=str(path)
 def tearDown(self):self.tmp.cleanup()
 def test_active_other_app_blocks_before_reboot(self):
  r.ROOT.mkdir();r.persist(r.ROOT/('b'*32+'.json'),{'schema':'shuttle.operation/v1','id':'b'*32,'kind':'deploy','app':'other','state':'active'})
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.assertEqual(self.scheduled,0)
 def test_recovery_required_other_app_blocks_before_reboot(self):
  r.ROOT.mkdir();r.persist(r.ROOT/('c'*32+'.json'),{'schema':'shuttle.operation/v1','id':'c'*32,'kind':'deploy','app':'other','state':'recovery_required','recovery_required':True})
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.assertEqual(self.scheduled,0)
 def test_changed_boot_and_https_required_with_resumable_intent(self):
  self.assertEqual(r.step(self.request)['state'],'scheduled');self.assertEqual(self.scheduled,1)
  self.request['action']='verify';waiting=r.step(self.request);self.assertEqual(waiting['state'],'waiting');self.assertTrue(waiting['https_required'])
  self.current_boot='after';ready=r.step(self.request);self.assertEqual(ready['state'],'ready');self.assertTrue(ready['https_required']);self.assertNotEqual(ready['boot_before'],ready['boot_after'])
  self.request['action']='finish'
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.request['https_verified']=True;completed=r.step(self.request);self.assertEqual(completed['state'],'completed');self.assertTrue(completed['https_required'])
  resumed=r.step(self.request);self.assertEqual(resumed['state'],'completed');self.assertTrue(resumed['https_required']);self.assertEqual(self.scheduled,1)
  record=json.loads((r.ROOT/(OPID+'.json')).read_text());self.assertEqual(record['lease_until'],'');self.assertFalse(record['recovery_required'])
 def test_same_boot_cannot_finish_even_with_https_claim(self):
  r.step(self.request);self.request.update(action='finish',https_verified=True)
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.request['action']='verify';waiting=r.step(self.request);self.assertEqual(waiting['state'],'waiting');self.assertTrue(waiting['https_required'])
  record=json.loads((r.ROOT/(OPID+'.json')).read_text());self.assertEqual(record['state'],'recovery_required');self.assertEqual(record.get('lease_until'),'')
 def test_resume_schedules_after_systemd_run_failed_following_fsync(self):
  self.fail_schedule=True
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.assertEqual(self.scheduled,0);self.assertFalse(self.unit_active)
  record=json.loads((r.ROOT/(OPID+'.json')).read_text());self.assertEqual(record['state'],'recovery_required');self.assertEqual(record.get('lease_until'),'')
  self.fail_schedule=False;self.request['action']='verify'
  waiting=r.step(self.request);self.assertEqual(waiting['state'],'waiting');self.assertEqual(self.scheduled,1);self.assertTrue(self.unit_active)
  self.assertEqual(r.step(self.request)['state'],'waiting');self.assertEqual(self.scheduled,1)
  self.request.update(action='finish',https_verified=True)
  with self.assertRaises(RuntimeError):r.step(self.request)
  record=json.loads((r.ROOT/(OPID+'.json')).read_text());self.assertEqual(record['state'],'recovery_required')
 def test_active_unit_is_not_scheduled_twice(self):
  self.assertEqual(r.step(self.request)['state'],'scheduled');self.assertEqual(self.scheduled,1)
  self.request['action']='verify'
  self.assertEqual(r.step(self.request)['state'],'waiting');self.assertEqual(r.step(self.request)['state'],'waiting');self.assertEqual(self.scheduled,1)
 def test_timer_loaded_service_inactive_does_not_reschedule(self):
  started=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
  self.seed_pending(started);self.units[self.timer]='loaded';self.units[self.service]='loaded'
  self.request['action']='verify';self.assertEqual(r.step(self.request)['state'],'waiting');self.assertEqual(self.scheduled,0)
 def test_both_units_absent_allows_resume_schedule(self):
  started=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
  self.seed_pending(started);self.request['action']='verify'
  self.assertEqual(r.step(self.request)['state'],'waiting');self.assertEqual(self.scheduled,1)
 def test_loaded_inactive_unit_does_not_reschedule(self):
  started=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
  self.seed_pending(started);self.units[self.timer]='not-found';self.units[self.service]='loaded'
  self.request['action']='verify';self.assertEqual(r.step(self.request)['state'],'waiting');self.assertEqual(self.scheduled,0)
 def test_probe_errors_fail_closed_without_scheduling(self):
  started=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
  self.seed_pending(started);self.request['action']='verify'
  self.probe_error='timeout';
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.probe_error=None;self.units[self.timer]='error-exit'
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.units[self.timer]='malformed';self.units[self.service]='not-found'
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.assertEqual(self.scheduled,0)
 def test_expired_and_future_intents_never_schedule(self):
  past=(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(minutes=16)).isoformat().replace('+00:00','Z')
  self.seed_pending(past);self.request['action']='verify'
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.assertEqual(self.scheduled,0)
  future=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=1)).isoformat().replace('+00:00','Z')
  self.seed_pending(future)
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.assertEqual(self.scheduled,0)
  self.seed_pending('2026-09-13T14:00:00')
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.assertEqual(self.scheduled,0)
 def test_helper_migration_fifo_and_symlink_do_not_schedule(self):
  os.mkfifo(r.MIGRATION)
  with self.assertRaises(RuntimeError):r.step(self.request)
  pathlib.Path(r.MIGRATION).unlink()
  pathlib.Path(r.MIGRATION).symlink_to(pathlib.Path(r.MIGRATION).parent/'absent-target')
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.assertEqual(self.scheduled,0)
 def test_helper_migration_blocks_new_scheduling_except_completed_or_missing(self):
  self.write_migration(json.dumps({'schema':'shuttle.helper-migration/v1','phase':'prepared','id':'a'*8+'-'+'b'*4+'-'+'c'*4+'-'+'d'*4+'-'+'e'*12,'candidate_sha256':'sha256:'+'f'*64}))
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.write_migration(json.dumps({'schema':'shuttle.helper-migration/v1','phase':'replaced','id':'a'*8+'-'+'b'*4+'-'+'c'*4+'-'+'d'*4+'-'+'e'*12,'candidate_sha256':'sha256:'+'f'*64}))
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.write_migration('{')
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.write_migration(json.dumps({'schema':'shuttle.helper-migration/v1','phase':'unknown','id':'a'*8+'-'+'b'*4+'-'+'c'*4+'-'+'d'*4+'-'+'e'*12,'candidate_sha256':'sha256:'+'f'*64}))
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.assertEqual(self.scheduled,0)
  self.write_migration(json.dumps({'schema':'shuttle.helper-migration/v1','phase':'completed','id':'a'*8+'-'+'b'*4+'-'+'c'*4+'-'+'d'*4+'-'+'e'*12,'candidate_sha256':'sha256:'+'f'*64}))
  self.assertEqual(r.step(self.request)['state'],'scheduled');self.assertEqual(self.scheduled,1)
 def test_helper_migration_invalid_completed_identity_mode_owner_and_size_block(self):
  body={'schema':'shuttle.helper-migration/v1','phase':'completed','id':'a'*8+'-'+'b'*4+'-'+'c'*4+'-'+'d'*4+'-'+'e'*12,'candidate_sha256':'sha256:'+'f'*64}
  for key in ('id','candidate_sha256'):
   bad=dict(body);bad[key]='invalid';self.write_migration(json.dumps(bad))
   with self.assertRaises(RuntimeError):r.step(self.request)
  self.write_migration(json.dumps(body));pathlib.Path(r.MIGRATION).chmod(0o644)
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.write_migration(json.dumps(body));r.MIGRATION_UID=os.geteuid()+1
  with self.assertRaises(RuntimeError):r.step(self.request)
  r.MIGRATION_UID=os.geteuid();self.write_migration('x'*(r.MIGRATION_MAX+1))
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.assertEqual(self.scheduled,0)
 def test_wrong_owner_and_changed_service_identity_cannot_finish(self):
  r.step(self.request);self.current_boot='after';self.request.update(action='finish',https_verified=True)
  self.request['owner']='SHA256:'+'c'*43
  with self.assertRaises(RuntimeError):r.step(self.request)
  self.request['owner']='SHA256:'+'a'*43;self.services=[{'name':'demo_web','replicas':1,'image':'different'}]
  with self.assertRaises(RuntimeError):r.step(self.request)
  record=json.loads((r.ROOT/(OPID+'.json')).read_text());self.assertEqual(record['state'],'recovery_required')
unittest.main(argv=['reboot-test'])
`
	id, err := coord.NewID()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-B", "-c", code, module, id)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("reboot protocol tests failed: %v\n%s", err, output)
	}
}

func TestPlannedRebootCommandIsDiscoverable(t *testing.T) {
	root := NewRootCommand()
	cmd, _, err := root.Find([]string{"operations", "reboot"})
	if err != nil || cmd == nil || cmd.Name() != "reboot" {
		t.Fatalf("reboot unavailable: %v", err)
	}
	if cmd.Flags().Lookup("resume") == nil || cmd.Flags().Lookup("json") == nil {
		t.Fatal("reboot needs explicit resume and structured outcomes")
	}
}

func TestRebootJournalIsReadableByCoordinator(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	dir := t.TempDir()
	module := filepath.Join(dir, "reboot_program.py")
	if err := os.WriteFile(module, []byte(rebootProgram), 0600); err != nil {
		t.Fatal(err)
	}
	ops := filepath.Join(dir, "ops")
	lock := filepath.Join(dir, "lock")
	id, err := coord.NewID()
	if err != nil {
		t.Fatal(err)
	}
	code := `import importlib.util,json,pathlib,sys
spec=importlib.util.spec_from_file_location('reboot_program',sys.argv[1]);r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
r.ROOT=pathlib.Path(sys.argv[2]);r.LOCK=sys.argv[3]
r.MIGRATION=str(pathlib.Path(sys.argv[2]).parent/'missing-migration.json')
r.boot=lambda:'before'
r.inventory=lambda:[{'name':'demo_web','replicas':1,'image':'example@sha256:abc'}]
r.postgres=lambda:[['17','main','5432']]
def run(args):
 if args[:3]==['docker','container','inspect']:
  return json.dumps({'State':{'Running':True,'Health':{'Status':'healthy'}},'HostConfig':{'PortBindings':{'5000/tcp':[{'HostIp':'127.0.0.1','HostPort':'5000'}]},'RestartPolicy':{'Name':'always'}}})
 return 'active'
r.run=run
print(json.dumps(r.step({'id':sys.argv[4],'app':'demo','owner':'SHA256:'+'a'*43,'host':'SHA256:'+'b'*43,'action':'schedule'})))
`
	cmd := exec.Command(python, "-B", "-c", code, module, ops, lock, id)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("schedule pending reboot journal: %v\n%s", err, output)
	}
	c := coord.New(coord.Options{Root: ops, LockPath: lock, LockWait: time.Millisecond})
	record, err := c.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("coordinator rejected pending reboot journal: %v", err)
	}
	if record.Kind != "reboot" || record.State != coord.RecoveryRequired || !record.RecoveryRequired || record.LeaseUntil != "" {
		t.Fatalf("pending reboot journal is not coordinator-readable recovery state: %#v", record)
	}
}

func TestRebootResumeRejectsInvalidOperationID(t *testing.T) {
	report, err := rebootVPS(&config.Config{}, "not-a-valid-id")
	if err == nil {
		t.Fatal("invalid --resume id was accepted")
	}
	if !strings.Contains(err.Error(), "invalid reboot operation id") {
		t.Fatalf("expected fail-fast resume id error, got %v", err)
	}
	if report.OperationID != "not-a-valid-id" || report.State != "not-started" || report.Error == "" {
		t.Fatalf("structured resume failure: %#v", report)
	}
}

func TestRebootRefusesDeployAndRootAdministrators(t *testing.T) {
	cfg := &config.Config{App: "demo", Servers: map[string]config.ServerGroup{"vps": {Hosts: []string{"203.0.113.10"}}}, Setup: config.SetupConfig{OperatorUser: "deploy"}}
	if _, err := rebootVPS(cfg, ""); err == nil || !strings.Contains(err.Error(), "separate SSH administrator") {
		t.Fatalf("deploy user must not reboot: %v", err)
	}
	cfg.Setup.OperatorUser = "root"
	if _, err := rebootVPS(cfg, ""); err == nil || !strings.Contains(err.Error(), "separate SSH administrator") {
		t.Fatalf("root must not reboot: %v", err)
	}
}

func TestRequireRebootBootChange(t *testing.T) {
	if err := requireRebootBootChange(rebootReport{State: "completed", BootBefore: "before", BootAfter: "before"}); err == nil {
		t.Fatal("same boot must not count as completion")
	}
	if err := requireRebootBootChange(rebootReport{State: "ready", BootBefore: "before"}); err == nil {
		t.Fatal("missing boot_after must not count as completion")
	}
	if err := requireRebootBootChange(rebootReport{State: "completed", BootBefore: "before", BootAfter: "after", HTTPSRequired: true}); err != nil {
		t.Fatal(err)
	}
}

func TestRebootJSONIncludesFailuresAndHTTPSRequired(t *testing.T) {
	var stdout bytes.Buffer
	report := rebootReport{Schema: "shuttle.reboot/v1", OperationID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", State: "recovery_required", Error: "postconditions failed", HTTPSRequired: true, BootBefore: "before", BootAfter: "after"}
	if err := writeRebootOutcome(&stdout, report, true); err != nil {
		t.Fatal(err)
	}
	var decoded rebootReport
	if err := decodeSingleJSON(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("json outcome: %v %q", err, stdout.String())
	}
	if decoded.Error != "postconditions failed" || !decoded.HTTPSRequired || decoded.State != "recovery_required" {
		t.Fatalf("json outcome lost failure fields: %#v", decoded)
	}
	cmd := newRebootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--json"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected --yes requirement")
	}
	var auth rebootReport
	if err := decodeSingleJSON(out.Bytes(), &auth); err != nil {
		t.Fatalf("json authorization failure: %v %q", err, out.String())
	}
	if auth.Schema != "shuttle.reboot/v1" || auth.State != "not-started" || auth.Error == "" {
		t.Fatalf("structured authorization failure: %#v", auth)
	}
}
