package certauth_test

import (
	"testing"

	"github.com/pantheon-systems/go-certauth"
)

func TestAuthValidateOU(t *testing.T) {
	// Tests that OU validation works as expected
	testCases := []struct {
		Name        string
		AllowedOUs  []string
		ActualOUs   []string
		ExpectedErr error
	}{
		{"NilServerOU", nil, []string{"endpoint"}, nil},
		{"EmptyServerOU", []string{}, []string{"endpoint"}, nil},
		{"MatchingOU", []string{"endpoint"}, []string{"endpoint"}, nil},
		{"MismatchOU", []string{"endpoint"}, []string{"site"}, mkOUErr("site", "endpoint")},
		{"NilClientOU", []string{"endpoint"}, nil, mkOUErr("", "endpoint")},
		{"EmptyClientOU", []string{"endpoint"}, []string{}, mkOUErr("", "endpoint")},
		{"EmptyStringClientOU", []string{"endpoint"}, []string{""}, mkOUErr("", "endpoint")},
		{"ListOU1", []string{"endpoint", "titan"}, []string{"endpoint"}, nil},
		{"ListOU2", []string{"endpoint", "titan"}, []string{"titan"}, nil},
		{"ListOU3", []string{"endpoint", "titan"}, []string{"site"}, mkOUErr("site", "endpoint titan")},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t2 *testing.T) {
			check := certauth.AllowSpecificOUandCNs{OUs: tc.AllowedOUs, CNs: nil}
			_, err := check.CheckAuthorization(tc.ActualOUs, "")

			expectErr(t2, err, tc.ExpectedErr)
		})
	}
}

func TestAuthValidateCN(t *testing.T) {
	// Tests that CN validation works as expected
	tests := []struct {
		Name        string
		AllowedCNs  []string
		ActualCN    string
		ExpectedErr error
	}{
		{"NilServerCN", nil, "site1", nil},
		{"EmptyServerCN", []string{}, "site1", nil},
		{"MatchingCN", []string{"site1"}, "site1", nil},
		{"MismatchCN", []string{"site1"}, "site", mkCNErr("site", "site1")},
		{"EmptyClientCN", []string{"site1"}, "", mkCNErr("", "site1")},
		{"ListCN1", []string{"site1", "site2"}, "site1", nil},
		{"ListCN2", []string{"site1", "site2"}, "site2", nil},
		{"ListCN3", []string{"site1", "site2"}, "site3", mkCNErr("site3", "site1 site2")},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t2 *testing.T) {
			check := certauth.AllowSpecificOUandCNs{OUs: nil, CNs: tc.AllowedCNs}
			_, err := check.CheckAuthorization(nil, tc.ActualCN)

			expectErr(t2, err, tc.ExpectedErr)
		})
	}
}

func TestAuthCNWithParams(t *testing.T) {
	// Tests that HasAuthorizedOU and HasAuthorizedCN are in the response
	actualCN := "i_am_a_cn"
	actualOU := "i_am_an_ou"

	check := certauth.AllowSpecificOUandCNs{OUs: nil, CNs: []string{actualCN}}
	params, err := check.CheckAuthorization([]string{actualOU}, actualCN)

	if err != nil {
		t.Fatalf(
			"Expected AllowedCNs (%v) and ActualCN (%v) to pass validation, but it failed: %s",
			check.CNs, actualCN, err,
		)
	}
	v, ok := params[certauth.HasAuthorizedCN]
	if !ok {
		t.Fatalf("Expected context key %s was not present %v", certauth.HasAuthorizedCN, params)
	}
	if v != actualCN {
		t.Errorf("Expected context value %q but received %q", actualCN, v)
	}
}

func TestAuthOUWithParams(t *testing.T) {
	// Tests that HasAuthorizedOU and HasAuthorizedCN are in the response
	actualCN := "i_am_a_cn"
	actualOU := "i_am_an_ou"

	check := certauth.AllowSpecificOUandCNs{OUs: []string{actualOU}, CNs: nil}
	params, err := check.CheckAuthorization([]string{actualOU}, actualCN)

	if err != nil {
		t.Fatalf(
			"Expected AllowedOUs (%v) and ActualOU (%v) to pass validation, but it failed: %s",
			check.OUs, actualOU, err,
		)
	}
	v, ok := params[certauth.HasAuthorizedOU]
	vl := v.([]string)
	if !ok {
		t.Fatalf("Expected context key %s was not present %v", certauth.HasAuthorizedOU, params)
	}
	if len(vl) != 1 || vl[0] != actualOU {
		t.Errorf("Expected context value %q but received %q", actualOU, v)
	}
}
