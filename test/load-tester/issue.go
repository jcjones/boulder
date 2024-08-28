package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/privatekey"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// subcommandIssueCert issues certs.
type subcommandIssueCert struct {
	count   uint
	acctKey string
}

var _ subcommand = (*subcommandIssueCert)(nil)

func (s *subcommandIssueCert) Desc() string {
	return "Issue certs for the provided regID"
}

func (s *subcommandIssueCert) Flags(flag *flag.FlagSet) {
	// General flags relevant to all key input methods.
	flag.UintVar(&s.count, "count", 10, "Number of concurrent workers to use while blocking keys")
	flag.StringVar(&s.acctKey, "acct", "", "Account privkey")
}

func (s *subcommandIssueCert) Run(ctx context.Context, lt *loadtester) error {
	_, key, err := privatekey.Load(s.acctKey)
	if err != nil {
		return err
	}

	jwk := &jose.JSONWebKey{
		Key: key,
	}
	regId, err := lt.getOrMakeReg(ctx, jwk.Public())
	if err != nil {
		return err
	}

	err = lt.newOrder(ctx, regId, []string{"common.lencr.org"})
	if err != nil {
		return err
	}
	return nil
}

func (lt *loadtester) makeReg(ctx context.Context, keyBytes []byte) (int64, error) {
	reg := &corepb.Registration{
		Key:             keyBytes,
		InitialIP:       net.IP("10.0.0.1"),
		Contact:         []string{},
		ContactsPresent: false,
		Agreement:       "no terms",
		Status:          string(core.StatusValid),
	}
	finalReg, err := lt.sac.NewRegistration(ctx, reg)
	if err != nil {
		return 0, err
	}
	return finalReg.Id, nil
}

func (lt *loadtester) getOrMakeReg(ctx context.Context, jwk jose.JSONWebKey) (int64, error) {
	keyBytes, err := jwk.MarshalJSON()
	if err != nil {
		return 0, err
	}
	inKey := &sapb.JSONWebKey{Jwk: keyBytes}

	reg, err := lt.saroc.GetRegistrationByKey(ctx, inKey)
	if err != nil {
		return lt.makeReg(ctx, keyBytes)
	}
	return reg.Id, nil
}

func (lt *loadtester) newOrder(ctx context.Context, regID int64, dnsNames []string) error {
	var order *corepb.Order

	csr, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{DNSNames: dnsNames},
		lt.certKey,
	)
	if err != nil {
		return fmt.Errorf("unable to make CSR: %w", err)
	}

	req := &rapb.NewOrderRequest{
		RegistrationID: regID,
		DnsNames:       dnsNames,
	}
	order, err = lt.rac.NewOrder(ctx, req)
	if err != nil {
		return fmt.Errorf("unable to make order: %w", err)
	}

	lt.log.Infof("New Order by regID=%d, names=%v: %v", regID, dnsNames, order)

	attemptedTime := time.Now()
	expirationTime := attemptedTime.Add(time.Hour * 24)

	for _, authzID := range order.V2Authorizations {
		lt.log.Infof("Satisfying challenge %d", authzID)

		finalAuthzReq := &sapb.FinalizeAuthorizationRequest{
			Id:          authzID,
			Status:      "valid",
			Expires:     timestamppb.New(expirationTime),
			AttemptedAt: timestamppb.New(attemptedTime),
			Attempted:   string(core.ChallengeTypeTLSALPN01),
		}
		_, err := lt.sac.FinalizeAuthorization2(ctx, finalAuthzReq)
		if err != nil {
			return err
		}
	}

	// We're done, really
	order.Status = string(core.StatusReady)

	lt.log.Infof("Finalizing order %d", order.Id)
	finalOrderReq := &rapb.FinalizeOrderRequest{
		Order: order,
		Csr:   csr,
	}

	order, err = lt.rac.FinalizeOrder(ctx, finalOrderReq)
	if err != nil {
		return fmt.Errorf("unable to finalize order: %w", err)
	}

	getOrderReq := &sapb.OrderRequest{
		Id: order.Id,
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if order.Status != string(core.StatusProcessing) {
			lt.log.Infof("Final Order: %v", order)
			return nil
		}

		order, err = lt.saroc.GetOrder(ctx, getOrderReq)
		if err != nil {
			return fmt.Errorf("unable to poll order update: %w", err)
		}

		time.Sleep(time.Second)
	}

}
