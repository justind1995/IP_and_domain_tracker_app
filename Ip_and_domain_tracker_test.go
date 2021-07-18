package main

import (
	"fmt"
	"testing"
)

func TestCheckFileHashFailure(t *testing.T) {
	var response DataResponse
	checkFileHash(&response, "8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85")

	if response.ErrorResponseData != nil {
		t.Errorf("API call should fail as token is an environment variable")
	}
}

func TestGeoIPData(t *testing.T) {
	var response DataResponse
	getIpGeoData(&response, "8.8.8.8")
	if response.GeoData.TimeZone != "America/Chicago" {
		t.Errorf("Timezone is different than expected")
	}
}

func TestWhoIsIP(t *testing.T) {
	var response DataResponse
	getWhoisDataIP(&response, "8.8.8.8")
	if response.WhoisDataIP.DomainNames[0] != "dns.google." {
		t.Errorf("domain is different than expected for IP provided")
	}
}

func TestWhoIsDomain(t *testing.T) {
	var response DataResponse
	getWhoisDataDomain(&response, "google.com")
	fmt.Println(response.WhoIsDataDomain.IpAddresses[0].String())
	if response.WhoIsDataDomain.DomainCreationDate != "1997-09-15T04:00:00Z" {
		t.Errorf("domain is different than expected for IP provided")
	}
}
