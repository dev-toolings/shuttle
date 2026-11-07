package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/backup"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/operationwriters"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
	"github.com/spf13/cobra"
)

type writerRecoverySnapshot struct {
	Record  coord.Record           `json:"record"`
	Writers operationwriters.State `json:"writers"`
}

func newOperationsWritersCommand(provided ...*configFlags) *cobra.Command {
	flags, owned := operationFlags(provided...)
	var dryRun, yes, asJSON bool
	var digest string
	cmd := &cobra.Command{
		Use:          "writers <operation-id>",
		Short:        "Observe and explicitly close an interrupted operation's recorded writers",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !rebootOperationID.MatchString(args[0]) {
				return errors.New("invalid operation identifier")
			}
			if !dryRun && !yes {
				return errors.New("writer closure requires --yes after reviewing --dry-run")
			}
			cfg, err := loadWithFlags(*flags)
			if err != nil {
				return err
			}
			op, snapshot, err := readWriterRecoverySnapshot(cfg, args[0])
			if err != nil {
				return err
			}
			expected, err := writerRecoveryPlanDigest(snapshot)
			if err != nil {
				return err
			}
			result := map[string]any{"schema": "shuttle.writer-recovery/v1", "id": args[0], "plan_digest": expected, "state": "observed", "writers": snapshot.Writers}
			if dryRun {
				if asJSON {
					return writeOperationJSON(cmd.OutOrStdout(), result)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Observe closure for %d recorded writers of %s; confirmation digest %s\n", len(snapshot.Writers.Writers), args[0], expected)
				for _, writer := range snapshot.Writers.Writers {
					fmt.Fprintf(cmd.OutOrStdout(), "  %s (%s)\n", writer.ID, writer.Kind)
				}
				return nil
			}
			if _, err := snapshot.Writers.ClosedProofHash(); err == nil {
				result["state"] = "closed"
				if asJSON {
					return writeOperationJSON(cmd.OutOrStdout(), result)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Writer closure is already durable.")
				return nil
			}
			if err := confirmWriterRecoveryDigest(digest, expected); err != nil {
				return err
			}
			if snapshot.Record.State != "active" && snapshot.Record.State != coord.RecoveryRequired {
				return errors.New("operation is already terminal")
			}
			for _, writer := range snapshot.Writers.Writers {
				writer := writer
				fence, cleanup, err := recordedWriterCloser(cfg, op, snapshot, writer)
				if err != nil {
					return err
				}
				if cleanup != nil {
					defer cleanup()
				}
				op.writers = append(op.writers, registeredOperationWriter{writer: writer, fence: fence})
			}
			err, note := closeRecoveryWriters(op, snapshot.Record.State)
			if note != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Abort reported: %v\n", note)
			}
			if err != nil {
				result["state"] = "unresolved"
				result["error"] = err.Error()
			} else {
				result["state"] = "closed"
			}
			if asJSON {
				if writeErr := writeOperationJSON(cmd.OutOrStdout(), result); writeErr != nil {
					return errors.Join(err, writeErr)
				}
				if err == nil {
					fmt.Fprintln(cmd.ErrOrStderr(), "Signed recovery still has to run. Review operations recover --dry-run next.")
				}
			} else if err == nil {
				fmt.Fprintln(cmd.OutOrStdout(), "Writer closure is durable. Signed recovery still has to run; review operations recover --dry-run next.")
			}
			return err
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "inspect writer identities without fencing or journal mutation")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm closure of the reviewed writer inventory")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print a structured closure outcome")
	cmd.Flags().StringVar(&digest, "plan-digest", "", "confirmation digest from --dry-run")
	if owned {
		addConfigFlags(cmd, flags)
	}
	return cmd
}

func closeRecoveryWriters(op *remoteOperation, state string) (error, error) {
	err := remoteOperationCloseWriters(op)
	if err == nil && state == "active" {
		err = op.control("operation-abort", "operator closed recorded writers; explicit host recovery remains required")
		if err != nil {
			// A reboot can make abort durably mark recovery required before it
			// reports failure. Confirm the outcome through signed status rather
			// than treating that failure as an unresolved writer closure.
			records, statusErr := readRemoteOperationStatus(op.client, op.identity, op.key)
			if statusErr == nil {
				for _, record := range records {
					if record.ID == op.id && record.Kind == op.kind && record.App == op.app && record.RecoveryRequired {
						return nil, err
					}
				}
			}
		}
	}
	return err, nil
}

func writerRecoveryPlanDigest(snapshot writerRecoverySnapshot) (string, error) {
	body, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

func confirmWriterRecoveryDigest(provided, expected string) error {
	if provided != expected {
		return errors.New("writer inventory changed or confirmation digest is missing; review --dry-run again")
	}
	return nil
}

func validateWriterRecoveryIdentities(id, app, hostKey, ownerKey string, snapshot writerRecoverySnapshot) error {
	if snapshot.Record.ID != id || snapshot.Record.App != app || snapshot.Record.Host != hostKey || snapshot.Record.OwnerKeyFingerprint != ownerKey {
		return errors.New("writer inventory belongs to another operation, host or operator")
	}
	if err := snapshot.Writers.Validate(); err != nil {
		return err
	}
	if snapshot.Writers.Binding.OperationID != id || snapshot.Writers.Binding.HostKey != snapshot.Record.Host || snapshot.Writers.Binding.BootID != snapshot.Record.HostBootID {
		return errors.New("writer inventory does not match the operation journal")
	}
	return nil
}

func recordedWriterCloser(cfg *config.Config, op *remoteOperation, snapshot writerRecoverySnapshot, writer operationwriters.Writer) (func(operationwriters.Binding) (operationwriters.Receipt, error), func() error, error) {
	switch writer.Kind {
	case operationwriters.WriterKindRemoteRunner:
		if cfg == nil || !cfg.Build.UsesSSH() || writer.Remote == nil || cfg.Build.HostKey != writer.Remote.HostKey {
			return nil, nil, errors.New("configuration does not identify the recorded SSH runner")
		}
		group, host, err := singleVPS(cfg)
		if err != nil {
			return nil, nil, err
		}
		runner, err := newSSHBuildRunner(cfg, group, host)
		if err != nil {
			return nil, nil, err
		}
		app := snapshot.Record.App
		token := writer.Remote.RunToken
		return func(binding operationwriters.Binding) (operationwriters.Receipt, error) {
			proof, err := runner.ObserveClosedRun(app, token)
			if err != nil {
				return operationwriters.Receipt{}, err
			}
			return sshRunnerClosureReceipt(writer, binding, proof)
		}, runner.Close, nil
	case operationwriters.WriterKindClientOrigin:
		return func(binding operationwriters.Binding) (operationwriters.Receipt, error) {
			return closeRecordedClientWriter(op, writer, binding)
		}, func() error { return nil }, nil
	default:
		return nil, nil, errors.New("this writer requires its VPS recovery executor")
	}
}

func readWriterRecoverySnapshot(cfg *config.Config, id string) (*remoteOperation, writerRecoverySnapshot, error) {
	var snapshot writerRecoverySnapshot
	group, host, err := singleVPS(cfg)
	if err != nil {
		return nil, snapshot, err
	}
	identity, err := loadTrustedHostIdentity(host, group.Port)
	if err != nil {
		return nil, snapshot, err
	}
	if cfg.Setup.OperatorUser == "" || cfg.Setup.OperatorUser == "deploy" || cfg.Setup.OperatorUser == "root" {
		return nil, snapshot, errors.New("writer recovery observation requires the separate SSH administrator")
	}
	admin, err := shuttlessh.NewClientExactWithFingerprint(host, cfg.Setup.OperatorUser, group.Port, identity.HostKeyFingerprint)
	if err != nil {
		return nil, snapshot, err
	}
	admin.SetOperationTimeout(30 * time.Second)
	command, err := backup.PythonCommand(readWriterRecoveryProgram, []string{id})
	if err != nil {
		return nil, snapshot, err
	}
	r := admin.Run(command)
	if r.Code != 0 {
		return nil, snapshot, fmt.Errorf("read writer recovery inventory: %s", r.Stderr)
	}
	if err := decodeSingleJSON([]byte(r.Stdout), &snapshot); err != nil {
		return nil, snapshot, err
	}
	if err := validateWriterRecoveryIdentities(id, cfg.App, identity.HostKeyFingerprint, identity.OperatorKeyFingerprint, snapshot); err != nil {
		return nil, snapshot, err
	}
	path, _, err := ensureRootOperationKeyPair()
	if err != nil {
		return nil, snapshot, err
	}
	key, err := rootplan.ReadPrivateKey(path)
	if err != nil {
		return nil, snapshot, err
	}
	client, err := connectSSH(group, host)
	if err != nil {
		return nil, snapshot, err
	}
	return &remoteOperation{id: id, kind: snapshot.Record.Kind, app: snapshot.Record.App, client: client, identity: identity, key: key}, snapshot, nil
}

// backup.PythonCommand passes the request as base64 JSON, not as a raw argv
// string. Reading sys.argv[1] directly refused every real operation ID as
// "invalid identifier" on the recette VPS, so the payload is decoded here.
const readWriterRecoveryProgram = `import base64,json,os,pathlib,re,stat,sys
request=json.loads(base64.b64decode(sys.argv[1],validate=True))
if not isinstance(request,list) or len(request)!=1 or not isinstance(request[0],str):raise RuntimeError('invalid request')
identifier=request[0]
if not re.fullmatch(r'(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',identifier):raise RuntimeError('invalid identifier')
def read(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077 or info.st_size>262144:raise RuntimeError('unsafe operation inventory')
  data=os.read(fd,262145)
  if len(data)>262144:raise RuntimeError('oversized operation inventory')
  return json.loads(data)
 finally:os.close(fd)
root=pathlib.Path('/var/lib/shuttle/operations')
print(json.dumps({'record':read(root/(identifier+'.json')),'writers':read(root/'writers'/(identifier+'.json'))}))
`
