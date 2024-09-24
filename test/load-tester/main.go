// Package main provides the "load-tester" tool, which emulates the Web Front
// End to drive Boulder at speed, for load testing purposes.
//
// Run "load-tester -h" for a list of flags and subcommands.
//
// This tool will need privileges like the Admin tool.
//
// Note that this tool is not safe to use against a production environment,
// as it uses its admin privileges to bypass slow operations, depending on
// mode.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
)

type Config struct {
	LoadTester struct {
		// TLS controls the TLS client the admin tool uses for gRPC connections.
		TLS cmd.TLSConfig

		RAService *cmd.GRPCClientConfig
		SAService *cmd.GRPCClientConfig

		DebugAddr string

		Features features.Config
	}

	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig
}

// subcommand specifies the set of methods that a struct must implement to be
// usable as an admin subcommand.
type subcommand interface {
	// Desc should return a short (one-sentence) description of the subcommand for
	// use in help/usage strings.
	Desc() string
	// Flags should register command line flags on the provided flagset. These
	// should use the "TypeVar" methods on the provided flagset, targeting fields
	// on the subcommand struct, so that the results of command line parsing can
	// be used by other methods on the struct.
	Flags(*flag.FlagSet)
	// Run should do all of the subcommand's heavy lifting, with behavior gated on
	// the subcommand struct's member fields which have been populated from the
	// command line. The provided admin object can be used for access to external
	// services like the RA, SA, and configured logger.
	Run(context.Context, *loadtester) error
}

// main is the entry-point for the admin tool. We do not include admin in the
// suite of tools which are subcommands of the "boulder" binary, since it
// should be small and portable and standalone.
func main() {
	// Do setup as similarly as possible to all other boulder services, including
	// config parsing and stats and logging setup. However, the one downside of
	// not being bundled with the boulder binary is that we don't get config
	// validation for free.
	defer cmd.AuditPanic()

	// This is the registry of all subcommands that the admin tool can run.
	subcommands := map[string]subcommand{
		"issue": &subcommandIssueCert{},
	}

	defaultUsage := flag.Usage
	flag.Usage = func() {
		defaultUsage()
		fmt.Printf("\nSubcommands:\n")
		for name, command := range subcommands {
			fmt.Printf("  %s\n", name)
			fmt.Printf("\t%s\n", command.Desc())
		}
		fmt.Print("\nYou can run \"load-tester <subcommand> -help\" to get usage for that subcommand.\n")
	}

	// Start by parsing just the global flags before we get to the subcommand, if
	// they're present.
	configFile := flag.String("config", "", "Path to the configuration file for this service (required)")
	flag.Parse()

	// Figure out which subcommand they want us to run.
	unparsedArgs := flag.Args()
	if len(unparsedArgs) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	subcommand, ok := subcommands[unparsedArgs[0]]
	if !ok {
		flag.Usage()
		os.Exit(1)
	}

	// Then parse the rest of the args according to the selected subcommand's
	// flags, and allow the global flags to be placed after the subcommand name.
	subflags := flag.NewFlagSet(unparsedArgs[0], flag.ExitOnError)
	subcommand.Flags(subflags)
	flag.VisitAll(func(f *flag.Flag) {
		// For each flag registered at the global/package level, also register it on
		// the subflags FlagSet. The `f.Value` here is a pointer to the same var
		// that the original global flag would populate, so the same variable can
		// be set either way.
		subflags.Var(f.Value, f.Name, f.Usage)
	})
	_ = subflags.Parse(unparsedArgs[1:])

	// With the flags all parsed, now we can parse our config and set up our admin
	// object.
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	a, err := newLoadTester(*configFile)
	cmd.FailOnError(err, "creating admin object")

	// Finally, run the selected subcommand.
	a.log.AuditInfof("Boulder Load Tester executing with the following arguments: %q", strings.Join(os.Args, " "))

	err = subcommand.Run(context.Background(), a)
	cmd.FailOnError(err, "executing subcommand")

	a.log.AuditInfof("Boulder Load Tester successfully completed executing with the following arguments: %q", strings.Join(os.Args, " "))
}