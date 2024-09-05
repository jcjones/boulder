package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"sync"
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
	workers           uint
	orders            uint
	hostnameWidth     uint
	acctKey           string
	inhibitAuthzReuse bool
}

var _ subcommand = (*subcommandIssueCert)(nil)

func (s *subcommandIssueCert) Desc() string {
	return "Rapidly make and fulfill Orders for the provided Account, registering it if needed."
}

func (s *subcommandIssueCert) Flags(flag *flag.FlagSet) {
	// General flags relevant to all key input methods.
	flag.UintVar(&s.workers, "workers", 10, "Number of concurrent workers to use")
	flag.UintVar(&s.hostnameWidth, "hostnameWidth", 1, "Bytes of random data in hostnames")
	flag.UintVar(&s.orders, "orders", 8124, "Total number of orders to make")
	flag.StringVar(&s.acctKey, "acct", "", "Account privkey")
	flag.BoolVar(&s.inhibitAuthzReuse, "limit-reuse", false, "Trick the RA to inhibit AuthZ reuse")
}

func (s *subcommandIssueCert) issueWorker(ctx context.Context, lt *loadtester, wg *sync.WaitGroup, workChan <-chan int64) {
	defer wg.Done()
	for regId := range workChan {
		err := s.newOrder(ctx, lt, regId)
		if err != nil {
			lt.log.Errf("NewOrder failed: %w", err)
		}
	}
}

func (s *subcommandIssueCert) Run(ctx context.Context, lt *loadtester) error {
	if s.acctKey == "" {
		return fmt.Errorf("The account key must be provided.")
	}

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

	workStart := time.Now()

	wg := sync.WaitGroup{}
	workChan := make(chan int64, 100)
	for range s.workers {
		wg.Add(1)
		go s.issueWorker(ctx, lt, &wg, workChan)
	}

	for range s.orders {
		workChan <- regId
	}
	close(workChan)
	wg.Wait()

	workDuration := time.Since(workStart)
	lt.log.Infof("Runner completed %d NewOrders in %s (%f/sec)", s.orders, workDuration, float64(s.orders)/workDuration.Seconds())

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

func (s *subcommandIssueCert) randomHostname() string {
	b := make([]byte, s.hostnameWidth)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	host := fmt.Sprintf("%s.lencr.org", hex.EncodeToString(b))
	return host
}

func (s *subcommandIssueCert) newOrder(ctx context.Context, lt *loadtester, regID int64) error {
	var order *corepb.Order

	startTime := time.Now()

	dnsNames := []string{"common.lencr.org", s.randomHostname()}
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

	orderId := order.Id

	lt.log.Debugf("[%d] New Order by regID=%d, names=%v: %v", order.Id, regID, dnsNames, order)

	attemptedTime := time.Now()
	expirationTime := attemptedTime.Add(time.Hour * 24 * 7)
	if s.inhibitAuthzReuse {
		// Setting these to 1 day expiration ensures RA won't perform a unlimited authz reuse, as
		// 1 day is its cutoff.
		expirationTime = attemptedTime.Add(time.Hour * 24)
	}

	for _, authzID := range order.V2Authorizations {
		lt.log.Debugf("[%d] Attempting to satisfy challenge for authzID=%d", orderId, authzID)

		authz, err := lt.saroc.GetAuthorization2(ctx, &sapb.AuthorizationID2{Id: authzID})
		if err != nil {
			return fmt.Errorf("[%d] unable to find authz: %w", orderId, err)
		}
		if authz.Status == string(core.StatusValid) {
			lt.log.Debugf("[%d] AuthzID was reused, already Valid authzID=%d", orderId, authzID)
			continue
		}

		finalAuthzReq := &sapb.FinalizeAuthorizationRequest{
			Id:          authzID,
			Status:      "valid",
			Expires:     timestamppb.New(expirationTime),
			AttemptedAt: timestamppb.New(attemptedTime),
			Attempted:   string(core.ChallengeTypeTLSALPN01),
		}
		_, err = lt.sac.FinalizeAuthorization2(ctx, finalAuthzReq)
		if err != nil {
			return fmt.Errorf("[%d] unable to finalize authz: %w", orderId, err)
		}
	}

	// We're done, really
	order.Status = string(core.StatusReady)

	lt.log.Debugf("[%d] Finalizing order", order.Id)
	finalOrderReq := &rapb.FinalizeOrderRequest{
		Order: order,
		Csr:   csr,
	}

	getOrderReq := &sapb.OrderRequest{
		Id: orderId,
	}

	for try := range 10 {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		order, err = lt.rac.FinalizeOrder(ctx, finalOrderReq)
		if err != nil {
			lt.log.Debugf("[%d] unable to finalize order: %w", orderId, err)
			continue
		}

		if order.Status != string(core.StatusProcessing) {
			lt.log.Debugf("[%d] Final Order; orderTime=%s, order=%v", orderId, time.Since(startTime), order)
			return nil
		}

		backoff := core.RetryBackoff(try, time.Millisecond*250, time.Second*5, 2)
		lt.log.Debugf("[%d] Retrying, try=%d, backoff=%s", orderId, try, backoff)
		time.Sleep(backoff)

		order, err = lt.saroc.GetOrder(ctx, getOrderReq)
		if err != nil {
			return fmt.Errorf("[%d] unable to poll order update: %w", orderId, err)
		}
	}

	return fmt.Errorf("[%d] Timed out trying to finalize order, orderTime=%s, order=%v", orderId, time.Since(startTime), order)
}
