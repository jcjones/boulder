package main

import (
	"context"
	"errors"
	"os"
	"path"
	"strings"
	"testing"

	blog "github.com/letsencrypt/boulder/log"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
	"google.golang.org/grpc"
)

func TestReadingUnpauseAccountsFile(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		data           []string
		expectedRegIDs int
	}{
		{
			name: "No data in file",
			data: nil,
		},
		{
			name:           "valid",
			data:           []string{"1"},
			expectedRegIDs: 1,
		},
		{
			name:           "valid with duplicates",
			data:           []string{"1", "2", "1", "3", "3"},
			expectedRegIDs: 5,
		},
		{
			name:           "valid with empty lines and duplicates",
			data:           []string{"1", "\n", "6", "6", "6"},
			expectedRegIDs: 4,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			log := blog.NewMock()
			a := admin{log: log}

			file := path.Join(t.TempDir(), path.Base(t.Name()+".txt"))
			err := os.WriteFile(file, []byte(strings.Join(testCase.data, "\n")), os.ModePerm)
			test.AssertNotError(t, err, "could not write temporary file")

			regIDs, err := a.readUnpauseAccountFile(file)
			test.AssertNotError(t, err, "no error expected, but received one")
			test.AssertEquals(t, len(regIDs), testCase.expectedRegIDs)
		})
	}
}

// mockSAPaused is a mock that always succeeds. It records each PauseRequest it
// receives, and returns the number of identifiers as a
// PauseIdentifiersResponse. It does not maintain state of repaused identifiers.
type mockSAUnpause struct {
	sapb.StorageAuthorityClient
	regIDCounter map[int64]int64
}

func (msa *mockSAUnpause) UnpauseAccount(ctx context.Context, in *sapb.RegistrationID, _ ...grpc.CallOption) (*sapb.Count, error) {
	if _, ok := msa.regIDCounter[in.Id]; ok {
		msa.regIDCounter[in.Id] += 1
	}

	return &sapb.Count{Count: msa.regIDCounter[in.Id]}, nil
}

// mockSAUnpauseBroken is a mock that always returns an error.
type mockSAUnpauseBroken struct {
	sapb.StorageAuthorityClient
}

func (msa *mockSAUnpauseBroken) UnpauseAccount(ctx context.Context, in *sapb.RegistrationID, _ ...grpc.CallOption) (*sapb.Count, error) {
	return nil, errors.New("oh dear")
}

func TestUnpauseAccounts(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		regIDs    []int64
		saImpl    sapb.StorageAuthorityClient
		expectErr bool
	}{
		{
			name:      "no data",
			regIDs:    nil,
			expectErr: true,
		},
		{
			name:   "valid single entry",
			regIDs: []int64{1},
		},
		{
			name:      "valid single entry but broken SA",
			expectErr: true,
			saImpl:    &mockSAUnpauseBroken{},
			regIDs:    []int64{1},
		},
		{
			name:   "valid multiple entries with duplicates",
			regIDs: []int64{1, 1, 2, 3, 4},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			log := blog.NewMock()

			// Default to a working mock SA implementation
			if testCase.saImpl == nil {
				testCase.saImpl = &mockSAUnpause{}
			}
			a := admin{sac: testCase.saImpl, log: log}

			count, err := a.unpauseAccounts(context.Background(), testCase.regIDs)
			if testCase.expectErr {
				test.AssertError(t, err, "should have errored, but did not")
			} else {
				test.AssertNotError(t, err, "should not have errored")
				test.AssertEquals(t, len(count), len(testCase.regIDs))
			}
		})
	}
}