package certauth_test

import (
	"testing"

	. "github.com/pantheon-systems/go-certauth"
)

func TestAuthValidateOU(t *testing.T) {
	// Tests that OU validation works as expected
	tests := []struct {
		AllowedOUs []string
		ActualOUs  []string
		IsAllowed  bool
	}{
		{[]string{}, []string{"endpoint"}, true},
		{[]string{"endpoint"}, []string{"endpoint"}, true},
		{[]string{"endpoint"}, []string{"site"}, false},
		{[]string{"endpoint"}, []string{""}, false},
		{[]string{"endpoint", "titan"}, []string{"site"}, false},
		{[]string{"endpoint", "titan"}, []string{"titan"}, true},
	}

	for _, tc := range tests {
		check := AllowSpecificOUandCNs{OUs: tc.AllowedOUs, CNs: nil}
		_, err := check.CheckAuthorization(tc.ActualOUs, "")

		if err != nil && tc.IsAllowed {
			t.Errorf(
				"Expected AllowedOUs (%v) and ActualOUs (%v) "+
					"to pass validation, but it failed: err: %s",
				tc.AllowedOUs, tc.ActualOUs, err,
			)
		}

		if err == nil && !tc.IsAllowed {
			t.Errorf(
				"Expected AllowedOUs (%v) and ActualOUs (%v) "+
					"to fail validation, but it passed.",
				tc.AllowedOUs, tc.ActualOUs,
			)
		}
	}
}

func TestAuthValidateCN(t *testing.T) {
	// Tests that CN validation works as expected
	tests := []struct {
		AllowedCNs []string
		ActualCN   string
		IsAllowed  bool
	}{
		{[]string{}, "site1", true},
		{[]string{"site1"}, "site1", true},
		{[]string{"site1"}, "site", false},
		{[]string{"site1"}, "", false},
		{[]string{"site1", "site2"}, "site1", true},
		{[]string{"site1", "site2"}, "site2", true},
		{[]string{"site1", "site2"}, "site3", false},
	}

	for _, tc := range tests {
		check := AllowSpecificOUandCNs{OUs: nil, CNs: tc.AllowedCNs}
		_, err := check.CheckAuthorization([]string{""}, tc.ActualCN)

		if err != nil && tc.IsAllowed {
			t.Errorf(
				"Expected AllowedCNs (%v) and ActualCN (%v) "+
					"to pass validation, but it failed: err: %s",
				tc.AllowedCNs, tc.ActualCN, err,
			)
		}

		if err == nil && !tc.IsAllowed {
			t.Errorf(
				"Expected AllowedCNs (%v) and ActualCN (%v) "+
					"to fail validation, but it passed.",
				tc.AllowedCNs, tc.ActualCN,
			)
		}
	}
}

func TestAuthWithParams(t *testing.T) {
	// Tests that HasAuthorizedOU and HasAuthorizedCN are in the response
	actualCN := "i_am_a_cn"
	actualOU := "i_am_an_ou"

	check := AllowSpecificOUandCNs{OUs: nil, CNs: []string{actualCN}}
	params, err := check.CheckAuthorization([]string{actualOU}, actualCN)

	if err != nil {
		t.Errorf(
			"Expected AllowedCNs (%v) and ActualCN (%v) to pass validation, but it failed: err: %s",
			check.CNs, actualCN, err,
		)
	}
	v, ok := params[HasAuthorizedCN]
	if !ok {
		t.Errorf("Expected context key %q was not present %v", HasAuthorizedCN.String(), params)
	} else if v != actualCN {
		t.Errorf("Expected context value %q but received %q", actualCN, v)
	}

	check = AllowSpecificOUandCNs{OUs: []string{actualOU}, CNs: nil}
	params, err = check.CheckAuthorization([]string{actualOU}, actualCN)

	if err != nil {
		t.Errorf(
			"Expected AllowedOUs (%v) and ActualOU (%v) to pass validation, but it failed: err: %s",
			check.OUs, actualOU, err,
		)
	}
	v, ok = params[HasAuthorizedOU]
	vl := v.([]string)
	if !ok {
		t.Errorf("Expected context key %q was not present %v", HasAuthorizedOU.String(), params)
	} else if len(vl) != 1 || vl[0] != actualOU {
		t.Errorf("Expected context value %q but received %q", actualOU, v)
	}
}
