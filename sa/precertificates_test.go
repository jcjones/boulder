package sa

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/db"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
)

// findIssuedName is a small helper test function to directly query the
// issuedNames table for a given name to find a serial (or return an err).
func findIssuedName(dbMap db.OneSelector, name string) (string, error) {
	var issuedNamesSerial string
	err := dbMap.SelectOne(
		&issuedNamesSerial,
		`SELECT serial FROM issuedNames
		WHERE reversedName = ?
		ORDER BY notBefore DESC
		LIMIT 1`,
		ReverseName(name))
	return issuedNamesSerial, err
}

func TestAddPrecertificate(t *testing.T) {
	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		return
	}

	sa, clk, cleanUp := initSA(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)

	addPrecert := func(expectIssuedNamesUpdate bool) {
		// Create a throw-away self signed certificate with a random name and
		// serial number
		serial, testCert := test.ThrowAwayCert(t, 1)

		// Add the cert as a precertificate
		ocspResp := []byte{0, 0, 1}
		regID := reg.ID
		issuedTime := time.Date(2018, 4, 1, 7, 0, 0, 0, time.UTC)
		issuedTimeNano := issuedTime.UnixNano()
		_, err := sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
			Der:    testCert.Raw,
			RegID:  &regID,
			Ocsp:   ocspResp,
			Issued: &issuedTimeNano,
		})
		test.AssertNotError(t, err, "Couldn't add test cert")

		// It should have the expected certificate status
		certStatus, err := sa.GetCertificateStatus(ctx, serial)
		test.AssertNotError(t, err, "Couldn't get status for test cert")
		test.Assert(
			t,
			bytes.Compare(certStatus.OCSPResponse, ocspResp) == 0,
			fmt.Sprintf("OCSP responses don't match, expected: %x, got %x", certStatus.OCSPResponse, ocspResp),
		)
		test.Assert(
			t,
			clk.Now().Equal(certStatus.OCSPLastUpdated),
			fmt.Sprintf("OCSPLastUpdated doesn't match, expected %s, got %s", clk.Now(), certStatus.OCSPLastUpdated),
		)

		issuedNamesSerial, err := findIssuedName(sa.dbMap, testCert.DNSNames[0])
		if expectIssuedNamesUpdate {
			// If we expectIssuedNamesUpdate then there should be no err and the
			// expected serial
			test.AssertNotError(t, err, "expected no err querying issuedNames for precert")
			test.AssertEquals(t, issuedNamesSerial, serial)

			// We should also be able to call AddCertificate with the same cert
			// without it being an error. The duplicate err on inserting to
			// issuedNames should be ignored.
			_, err := sa.AddCertificate(ctx, testCert.Raw, regID, nil, &issuedTime)
			test.AssertNotError(t, err, "unexpected err adding final cert after precert")
		} else {
			// Otherwise we expect an ErrDatabaseOp that indicates NoRows because
			// AddCertificate not AddPrecertificate will be updating this table.
			test.AssertEquals(t, db.IsNoRows(err), true)
		}

		// Adding the same certificate with the same serial should result in an
		// error
		_, err = sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
			Der:    testCert.Raw,
			RegID:  &regID,
			Ocsp:   ocspResp,
			Issued: &issuedTimeNano,
		})
		if err == nil {
			t.Fatalf("Expected error inserting duplicate precertificate, got none")
		}
		if !berrors.Is(err, berrors.Duplicate) {
			t.Fatalf("Expected berrors.Duplicate inserting duplicate precertificate, got %#v", err)
		}
	}

	addPrecert(true)
}

func TestAddPrecertificateKeyHash(t *testing.T) {
	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		return
	}

	sa, _, cleanUp := initSA(t)
	defer cleanUp()
	reg := satest.CreateWorkingRegistration(t, sa)
	err := features.Set(map[string]bool{"StoreKeyHashes": true})
	test.AssertNotError(t, err, "failed to set features")
	defer features.Reset()

	serial, testCert := test.ThrowAwayCert(t, 1)
	issued := testCert.NotBefore.UnixNano()
	_, err = sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:    testCert.Raw,
		RegID:  &reg.ID,
		Ocsp:   []byte{1, 2, 3},
		Issued: &issued,
	})
	test.AssertNotError(t, err, "failed to add precert")

	var keyHashes []keyHashModel
	_, err = sa.dbMap.Select(&keyHashes, "SELECT * FROM keyHashToSerial")
	test.AssertNotError(t, err, "failed to retrieve rows from keyHashToSerial")
	test.AssertEquals(t, len(keyHashes), 1)
	test.AssertEquals(t, keyHashes[0].CertSerial, serial)
	test.AssertEquals(t, keyHashes[0].CertNotAfter, testCert.NotAfter)
	spkiHash := sha256.Sum256(testCert.RawSubjectPublicKeyInfo)
	test.Assert(t, bytes.Compare(keyHashes[0].KeyHash, spkiHash[:]) == 0, "spki hash mismatch")
}
