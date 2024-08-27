package main

import (
	"context"
	"flag"
	"fmt"

	// sapb "github.com/letsencrypt/boulder/sa/proto"
	rapb "github.com/letsencrypt/boulder/ra/proto"
)

// subcommandIssueCert issues certs.
type subcommandIssueCert struct {
	count uint
	regId int64
}

var _ subcommand = (*subcommandIssueCert)(nil)

func (s *subcommandIssueCert) Desc() string {
	return "Issue certs for the provided regID"
}

func (s *subcommandIssueCert) Flags(flag *flag.FlagSet) {
	// General flags relevant to all key input methods.
	flag.UintVar(&s.count, "count", 10, "Number of concurrent workers to use while blocking keys")
	flag.Int64Var(&s.regId, "regID", 11, "RegID to own the certificates")
}

func (s *subcommandIssueCert) Run(ctx context.Context, lt *loadtester) error {
	err := lt.newOrder(ctx, s.regId, []string{"common.lencr.org"})
	if err != nil {
		return err
	}
	return nil
}

func (lt *loadtester) newOrder(ctx context.Context, regID int64, dnsNames []string) error {
	req := &rapb.NewOrderRequest{
		RegistrationID: regID,
		DnsNames:       dnsNames,
	}
	order, err := lt.rac.NewOrder(ctx, req)
	if err != nil {
		return fmt.Errorf("unable to make order: %w", err)
	}

	lt.log.Infof("oh %v\n", order)

	return nil
}
