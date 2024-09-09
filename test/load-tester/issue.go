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

type IssueResult string

const (
	ResultSuccess = IssueResult("success") // The certificate was issued
	ResultReused  = IssueResult("reused")  // The order was reused
	ResultInvalid = IssueResult("invalid") // The order was invalid
	ResultTimeout = IssueResult("timeout") // The order ended in a timeout
	ResultError   = IssueResult("error")   // The order ended in an error
)

// subcommandIssueCert issues certs.
type subcommandIssueCert struct {
	workers           uint
	orders            uint
	hostnameWidth     uint
	acctKey           string
	domain            string
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
	flag.StringVar(&s.domain, "domain", "lencr.org", "Domain name to use")
	flag.BoolVar(&s.inhibitAuthzReuse, "limit-reuse", false, "Trick the RA to inhibit AuthZ reuse")
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
	resultChan := make(chan IssueResult, s.orders)
	for range s.workers {
		wg.Add(1)
		go s.issueWorker(ctx, lt, &wg, workChan, resultChan)
	}

	for range s.orders {
		workChan <- regId
	}
	close(workChan)
	wg.Wait()
	workDuration := time.Since(workStart)

	close(resultChan)
	var resultSuccess int
	var resultReused int
	var resultInvalid int
	var resultTimeout int
	var resultError int

	for result := range resultChan {
		if result == ResultSuccess {
			resultSuccess += 1
		}
		if result == ResultReused {
			resultReused += 1
		}
		if result == ResultInvalid {
			resultInvalid += 1
		}
		if result == ResultTimeout {
			resultTimeout += 1
		}
		if result == ResultError {
			resultError += 1
		}
	}

	lt.log.Infof("Runner completed %d NewOrders in %s (%f/sec), success=%d, reused=%d, invalid=%d, timeout=%d, error=%d", s.orders, workDuration, float64(s.orders)/workDuration.Seconds(), resultSuccess, resultReused, resultInvalid, resultTimeout, resultError)

	problems := resultError + resultTimeout + resultInvalid
	lt.log.Info("threads,count,reuse,duration,problems")
	lt.log.Infof("%d,%d,%t,%f,%d", s.workers, s.orders, s.inhibitAuthzReuse, workDuration.Seconds(), problems)

	return nil
}

func (s *subcommandIssueCert) issueWorker(ctx context.Context, lt *loadtester, wg *sync.WaitGroup, workChan <-chan int64, resultChan chan<- IssueResult) {
	defer wg.Done()
	for regId := range workChan {
		result, err := s.newOrder(ctx, lt, regId)
		if err != nil {
			lt.log.Errf("NewOrder failed: %w", err)
		}
		resultChan <- result
	}
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

	host := fmt.Sprintf("%s.%s", hex.EncodeToString(b), s.domain)
	return host
}

func (s *subcommandIssueCert) validateAuthz(ctx context.Context, lt *loadtester, orderId int64, authzId int64, attemptedTime time.Time, expirationTime time.Time) error {
	lt.log.Debugf("[%d] Attempting to satisfy challenge for authzId=%d", orderId, authzId)

	try := 0

	for {
		authz, err := lt.saroc.GetAuthorization2(ctx, &sapb.AuthorizationID2{Id: authzId})
		if err != nil {
			return fmt.Errorf("[%d] unable to find authz: %w", orderId, err)
		}

		if authz.Status == string(core.StatusValid) {
			if try == 0 {
				lt.log.Debugf("[%d] AuthzID was reused, already Valid authzId=%d", orderId, authzId)
			}
			return nil
		}

		finalAuthzReq := &sapb.FinalizeAuthorizationRequest{
			Id:          authzId,
			Status:      "valid",
			Expires:     timestamppb.New(expirationTime),
			AttemptedAt: timestamppb.New(attemptedTime),
			Attempted:   string(core.ChallengeTypeTLSALPN01),
		}
		_, err = lt.sac.FinalizeAuthorization2(ctx, finalAuthzReq)
		if err != nil {
			return fmt.Errorf("[%d] unable to finalize authz: %w", orderId, err)
		}

		// Go immediately on the first attempt
		if try > 0 {
			backoff := core.RetryBackoff(try, time.Millisecond*250, time.Second*5, 2)
			lt.log.Debugf("[%d] Retrying, try=%d, backoff=%s", orderId, try, backoff)
			time.Sleep(backoff)
		}
		try += 1
	}
}

func (s *subcommandIssueCert) newOrder(ctx context.Context, lt *loadtester, regID int64) (IssueResult, error) {
	var order *corepb.Order

	startTime := time.Now()

	dnsNames := []string{s.randomHostname(), s.randomHostname()}
	csr, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{DNSNames: dnsNames},
		lt.certKey,
	)
	if err != nil {
		return ResultError, fmt.Errorf("unable to make CSR: %w", err)
	}

	req := &rapb.NewOrderRequest{
		RegistrationID: regID,
		DnsNames:       dnsNames,
	}
	order, err = lt.rac.NewOrder(ctx, req)
	if err != nil {
		return ResultError, fmt.Errorf("unable to make order: %w", err)
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
		err := s.validateAuthz(ctx, lt, orderId, authzID, attemptedTime, expirationTime)
		if err != nil {
			return ResultError, err
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

	order, finalizeErr := lt.rac.FinalizeOrder(ctx, finalOrderReq)
	if finalizeErr != nil {
		// Possibly we had order reuse.
		order, err = lt.saroc.GetOrder(ctx, getOrderReq)
		if err != nil {
			return ResultError, fmt.Errorf("[%d] unable to poll order update: %w", orderId, err)
		}
	}

	for try := range 10 {
		if ctx.Err() != nil {
			return ResultTimeout, ctx.Err()
		}

		if order.Status == string(core.StatusValid) {
			lt.log.Debugf("[%d] Final Order; orderTime=%s, order=%v", orderId, time.Since(startTime), order)
			return ResultSuccess, nil
		}

		if order.Status == string(core.StatusReady) {
			lt.log.Errf("[%d] Unprocessed order, did the finalize not work? finalizeErr=%v, orderTime=%s, order=%v", orderId, finalizeErr, time.Since(startTime), order)
			return ResultReused, nil
		}

		// We failed for some reason, bail out
		if order.Status == string(core.StatusInvalid) {
			lt.log.Errf("[%d] Invalid Order; orderTime=%s, order=%v", orderId, time.Since(startTime), order)
			return ResultInvalid, nil
		}

		// We're not done yet
		if order.Status != string(core.StatusProcessing) {
			lt.log.Errf("[%d] Unexpected status; orderTime=%s, order=%v", orderId, time.Since(startTime), order)
		}

		backoff := core.RetryBackoff(try, time.Millisecond*250, time.Second*5, 2)
		lt.log.Debugf("[%d] Retrying, try=%d, backoff=%s", orderId, try, backoff)
		time.Sleep(backoff)

		order, err = lt.saroc.GetOrder(ctx, getOrderReq)
		if err != nil {
			return ResultError, fmt.Errorf("[%d] unable to poll order update: %w", orderId, err)
		}
	}

	return ResultTimeout, fmt.Errorf("[%d] Timed out trying to finalize order, orderTime=%s, order=%v", orderId, time.Since(startTime), order)
}
