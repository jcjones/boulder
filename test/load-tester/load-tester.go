package main

import (
	"context"
	"fmt"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

// admin holds all of the external connections necessary to perform admin
// actions on a boulder deployment.
type loadtester struct {
	rac   rapb.RegistrationAuthorityClient
	sac   sapb.StorageAuthorityClient
	saroc sapb.StorageAuthorityReadOnlyClient

	clk clock.Clock
	log blog.Logger
}

// newLoadTester constructs a new Boulder Load Tester object on the heap and returns a pointer to
// it.
func newLoadTester(configFile string) (*loadtester, error) {
	// Unlike most boulder service constructors, this does all of its own config
	// parsing and dependency setup. If this is broken out into its own package
	// (outside the //cmd/ directory) those pieces of setup should stay behind
	// in //cmd/admin/main.go, to match other boulder services.
	var c Config
	err := cmd.ReadConfigFile(configFile, &c)
	if err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.LoadTester.DebugAddr)
	defer oTelShutdown(context.Background())
	logger.Info(cmd.VersionString())

	clk := cmd.Clock()
	features.Set(c.LoadTester.Features)

	tlsConfig, err := c.LoadTester.TLS.Load(scope)
	if err != nil {
		return nil, fmt.Errorf("loading TLS config: %w", err)
	}

	raConn, err := bgrpc.ClientSetup(c.LoadTester.RAService, tlsConfig, scope, clk)
	if err != nil {
		return nil, fmt.Errorf("creating SA gRPC client: %w", err)
	}
	rac := rapb.NewRegistrationAuthorityClient(raConn)

	saConn, err := bgrpc.ClientSetup(c.LoadTester.SAService, tlsConfig, scope, clk)
	if err != nil {
		return nil, fmt.Errorf("creating SA gRPC client: %w", err)
	}
	saroc := sapb.NewStorageAuthorityReadOnlyClient(saConn)

	sac := sapb.NewStorageAuthorityClient(saConn)

	return &loadtester{
		rac:   rac,
		sac:   sac,
		saroc: saroc,
		clk:   clk,
		log:   logger,
	}, nil
}
