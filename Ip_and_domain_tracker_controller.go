package main

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/oschwald/geoip2-golang"
	"github.com/tidwall/gjson"
)

func main() {
	lambda.Start(handleRequests)
}

func checkFileHash(response *DataResponse, data string) {
	var virusData HashVirusData
	var errorResponse ErrorResponse

	client := &http.Client{
		Timeout: time.Second * 10,
	}

	url := "https://www.virustotal.com/api/v3/files/" + data

	log.Println(url)

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		log.Println("Error building request for api call")
		errorResponse.Message = "could not make call to retrieve file hash information"
		response.ErrorResponseData = &errorResponse
		return
	}

	api_key := os.Getenv("api_key")
	req.Header.Add("x-apikey", api_key)
	apiResponse, err := client.Do(req)

	if err != nil {
		log.Println("Error making API Call to retrieve file hash info")
		errorResponse.Message = "could not make call to retrieve file hash information"
		response.ErrorResponseData = &errorResponse
		return
	}

	body, err := ioutil.ReadAll(apiResponse.Body)

	if err != nil {
		log.Println("Error making API Call to retrieve file hash info")
		errorResponse.Message = "could not decode api response"
		response.ErrorResponseData = &errorResponse
		return
	}

	//all is well, retrieve fields and build response
	bodyStr := string(body)

	virusData.FileSize = gjson.Get(bodyStr, "data.attributes.tlsh").String()
	virusData.FileType = gjson.Get(bodyStr, "data.attributes.type_description").String()
	virusData.MD5Hash = gjson.Get(bodyStr, "data.attributes.md5").String()
	virusData.SHA1Hash = gjson.Get(bodyStr, "data.attributes.sha1").String()
	virusData.SHA256Hash = gjson.Get(bodyStr, "data.attributes.sha256").String()
	virusData.FileSize = gjson.Get(bodyStr, "data.attributes.size").String()
	virusData.Names = gjson.Get(bodyStr, "data.attributes.names").Array()
	virusData.KnownSource = gjson.Get(bodyStr, "data.attributes.trusted_verdict.organization").String()
	virusData.TrustedVerdict = gjson.Get(bodyStr, "data.attributes.trusted_verdict.verdict").String()

	response.VirusData = &virusData

}

//don't build error response for geo data, if db is outdated somehow, its possible that IP doesn't exist there. Best to continue on.
func getIpGeoData(response *DataResponse, data string) {
	log.Println("getIpGeoData")
	var geoData IpGeo

	ip := net.ParseIP(data)

	log.Println("before db")
	db, err := geoip2.Open("GeoLite2-City.mmdb")

	if err != nil {
		log.Println("error opening city geo database, returning error")
	}

	record, err := db.City(ip)
	log.Println("after db")

	if err == nil {
		geoData.City = record.City.Names["en"]
		geoData.Country = record.Country.Names["en"]
		geoData.IsoCode = record.Country.IsoCode
		geoData.TimeZone = record.Location.TimeZone
		response.GeoData = &geoData
	} else {
		log.Println("error getting geo info for requested IP address, continuing but logged")
	}

}

func getWhoisDataDomain(response *DataResponse, data string) {
	var whoisData WhoisDomain
	var errorResponse ErrorResponse

	ips, err := net.LookupIP(data)

	log.Println(ips)

	//make IP optional, just to see if we can get any information
	if err == nil {
		whoisData.IpAddresses = ips
	} else {
		log.Println("error looking up ip for domain, continuing to see if who is data can be retrieved")
	}

	result, err := whois.Whois(data)
	if err != nil {
		log.Println("error looking up whois data for IP returning error")
		errorResponse.Message = "error trying to look up who is data for domain provided"

		//build error response
		response.ErrorResponseData = &errorResponse
		return
	}

	result2, err := whoisparser.Parse(result)

	//if error is nil, then build correct response
	if err == nil {
		whoisData.DomainStatus = result2.Domain.Status
		whoisData.DomainCreationDate = result2.Domain.CreatedDate
		whoisData.DomainExpirationDate = result2.Domain.ExpirationDate
		whoisData.RegistrarName = result2.Registrar.Name
		whoisData.RegistrantName = result2.Registrant.Name
		whoisData.RegistrantEmail = result2.Registrant.Email

		response.WhoIsDataDomain = &whoisData
	} else {
		log.Println("error parsing who is data, returning error")
		errorResponse.Message = "error parsing who is data with domain provided"
		response.ErrorResponseData = &errorResponse
		return
	}
}

func getWhoisDataIP(response *DataResponse, data string) {
	log.Println("getWhoisDataIP")
	var whoisData WhoisIP
	var errorResponse ErrorResponse

	names, err := net.LookupAddr(data)

	if err == nil {
		for i := 0; i < len(names); i++ {
			whoisData.DomainNames = append(whoisData.DomainNames, names[i])
		}
	} else {
		log.Println("error looking up domains for IP provided, continuing on to see if who is data can be retrieved")
	}

	result, err := whois.Whois(data)

	//if who is data can be retrieved... go ahead and do string parsing to get CIDRs and Netrange of IPs in response
	if err == nil {
		lines := strings.Split(result, "\n")

		for i := 0; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])

			//if not key value pair, skip
			if !strings.Contains(line, ":") {
				continue
			}

			line = strings.Trim(line, ";;")
			seperatedValue := strings.Split(line, ":")
			seperatedValue[0] = strings.TrimSpace(seperatedValue[0])
			seperatedValue[1] = strings.TrimSpace(seperatedValue[1])

			if seperatedValue[0] == "CIDR" {
				whoisData.CIDRs = append(whoisData.CIDRs, seperatedValue[1])
			} else if seperatedValue[0] == "NetRange" {
				whoisData.NetRanges = append(whoisData.NetRanges, seperatedValue[1])
			}
		}

		//if these arrays are empty, parsing was futile, document was empty, return error
		if len(whoisData.CIDRs) < 1 || len(whoisData.NetRanges) < 1 {
			log.Println("error parsing who is data, returning error")
			errorResponse.Message = "error parsing who is data with IP provided, required fields missing from whois report"
			response.ErrorResponseData = &errorResponse
			return
		} else {
			response.WhoisDataIP = &whoisData
		}

		response.WhoisDataIP = &whoisData
	} else {
		log.Println("Error retrieving who is data for IP provided")
		errorResponse.Message = "Error retrieving who is data for IP"
		response.ErrorResponseData = &errorResponse
	}
}

func handleRequests(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var response DataResponse
	var errorResponse ErrorResponse

	data := request.QueryStringParameters["data"]
	dataType := request.QueryStringParameters["dataType"]

	//based on data type, pass response object in by reference and build it up dynamically
	if dataType == "IP" {
		log.Println("ip")
		getIpGeoData(&response, data)
		getWhoisDataIP(&response, data)
	} else if dataType == "domain" {
		getWhoisDataDomain(&response, data)
		log.Println("domain")
	} else if dataType == "fileHash" {
		log.Println("file")
		checkFileHash(&response, data)
	} else {
		log.Println("invalid input")
		errorResponse.Message = "invalid dataType, please check for typos"
		response.ErrorResponseData = &errorResponse
	}

	log.Println("returning")
	responseStr, err := json.Marshal(response)
	log.Println(responseStr)

	if err == nil && response.ErrorResponseData == nil {
		return events.APIGatewayProxyResponse{Body: string(responseStr), StatusCode: 200}, nil
	} else {
		return events.APIGatewayProxyResponse{Body: string(responseStr), StatusCode: 500}, nil
	}
}
