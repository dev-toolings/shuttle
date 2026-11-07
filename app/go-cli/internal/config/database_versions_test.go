package config

import (
	"strconv"
	"strings"
	"testing"
)

// 17 is a supported major, not a tolerated one: it has to validate in every
// shape 16 validates in, including the declared roles and databases that are
// only reachable when the database is managed.
func TestValidateDatabaseConfigAcceptsEverySupportedMajor(t *testing.T) {
	for _, version := range SupportedDatabaseVersions {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			bare := DatabaseConfig{Version: version}
			if err := validateDatabaseConfig("demo", bare); err != nil {
				t.Fatalf("database.version %d rejected on its own: %v", version, err)
			}
			if !bare.Managed() {
				t.Fatalf("database.version %d must be a managed database", version)
			}
			declared := DatabaseConfig{
				Version:   version,
				Backup:    DatabaseBackup{Mode: "local", Retention: 7},
				Roles:     []DatabaseRole{{Name: "demo"}, {Name: "reporting"}},
				Databases: []DatabaseDatabase{{Name: "demo", Owner: "demo"}, {Name: "reporting", Owner: "reporting", Schemas: []string{"marts"}}},
			}
			if err := validateDatabaseConfig("demo", declared); err != nil {
				t.Fatalf("database.version %d rejected with declared roles and databases: %v", version, err)
			}
		})
	}
}

// A major on either side of the supported window is refused, and the refusal
// has to name the window: an operator who wrote 19 needs to be told what to
// write instead, not merely that 19 is wrong.
func TestValidateDatabaseConfigRefusesUnsupportedMajorsByName(t *testing.T) {
	for _, version := range []int{15, 19} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			err := validateDatabaseConfig("demo", DatabaseConfig{Version: version})
			if err == nil {
				t.Fatalf("database.version %d must be refused", version)
			}
			for _, supported := range SupportedDatabaseVersions {
				if !strings.Contains(err.Error(), strconv.Itoa(supported)) {
					t.Fatalf("the refusal must name supported major %d, got %q", supported, err)
				}
			}
			if (DatabaseConfig{Version: version}).Managed() {
				t.Fatalf("database.version %d must not be a managed database", version)
			}
		})
	}
}

// The refusal that guards declared objects has to name the supported majors
// too, and it must fire on an unsupported major as well as on an absent one:
// both describe a host where nothing would ever create them.
func TestDeclaredObjectsRequireASupportedManagedVersion(t *testing.T) {
	for _, version := range []int{0, 15} {
		spec := DatabaseConfig{Version: version, Roles: []DatabaseRole{{Name: "app"}}}
		err := validateDatabaseConfig("demo", spec)
		if err == nil {
			t.Fatalf("declared roles on database.version %d must be refused", version)
		}
		if version == 0 && !strings.Contains(err.Error(), "require a managed database.version (16, 17, 18)") {
			t.Fatalf("the refusal must name the managed majors, got %q", err)
		}
	}
}

// An absent database block is not a managed database, and it must keep
// validating: it is what an operator leaves out when the host's PostgreSQL is
// theirs to manage, and Shuttle must not claim a role or a password there.
func TestAbsentDatabaseVersionStaysUnmanagedAndValid(t *testing.T) {
	spec := DatabaseConfig{}
	if err := validateDatabaseConfig("demo", spec); err != nil {
		t.Fatalf("an absent database block must validate: %v", err)
	}
	if spec.Managed() {
		t.Fatal("an absent database.version must not be a managed database")
	}
}

// The default is a promise to every configuration already in the field: adding
// a newer major must not move what `shuttle init` writes or what setup installs
// on a bare host.
func TestDefaultDatabaseVersionIsSupportedAndStable(t *testing.T) {
	if DefaultDatabaseVersion != 18 {
		t.Fatalf("new installations must use stable major 18, got %d", DefaultDatabaseVersion)
	}
	if !(DatabaseConfig{Version: DefaultDatabaseVersion}).Managed() {
		t.Fatal("the default major must itself be supported")
	}
}
