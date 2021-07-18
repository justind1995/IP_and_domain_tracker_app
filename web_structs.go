package main

import (
	"net"

	"github.com/tidwall/gjson"
)

type DataResponse struct {
	GeoData           *IpGeo         `json:"geoData,omitempty"`
	WhoIsDataDomain   *WhoisDomain   `json:"whoIsDataDomain,omitempty"`
	WhoisDataIP       *WhoisIP       `json:"whoIsDataIP,omitempty"`
	VirusData         *HashVirusData `json:"virusData,omitempty"`
	ErrorResponseData *ErrorResponse `json:"errorResponse,omitempty"`
}

type WhoisDomain struct {
	DomainStatus         []string `json:"domain_status"`
	DomainCreationDate   string   `json:"domain_creation_date"`
	DomainExpirationDate string   `json:"domain_expiration_date"`
	RegistrarName        string   `json:"registrar_name"`
	RegistrantName       string   `json:"registrant_name"`
	RegistrantEmail      string   `json:"registrant_email"`
	IpAddresses          []net.IP `json:"ip_addresses"`
}

type WhoisIP struct {
	DomainNames []string `json:"domain_names"`
	NetRanges   []string `json:"net_ranges"`
	CIDRs       []string `json:"cidrs"`
}

type HashVirusData struct {
	MD5Hash        string         `json:"md5"`
	SHA1Hash       string         `json:"sha-1"`
	SHA256Hash     string         `json:"sha-256"`
	TLSH           string         `json:"tlsh"`
	FileType       string         `json:"file_type"`
	FileSize       string         `json:"file_size"`
	KnownSource    string         `json:"known_sources"`
	TrustedVerdict string         `json:"trusted_verdict"`
	Names          []gjson.Result `json:"names"`
}

type IpGeo struct {
	City     string `json:"city"`
	Country  string `json:"country"`
	IsoCode  string `json:"iso_code"`
	TimeZone string `json:"timezone"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}
