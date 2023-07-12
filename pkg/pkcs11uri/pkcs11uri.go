/*
Copyright 2023 Deutsche Telekom MMS GmbH
SPDX-License-Identifier: MIT
*/

// Package pkcs11uri implements a subset of the PKCS#11 URI specification. See
// https://www.rfc-editor.org/rfc/rfc7512.html for the format specification of these URIs.
package pkcs11uri

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/miekg/pkcs11"
)

// PKCS11URI encapsulates path and query attributes of a PKCS#11 URI.
type PKCS11URI struct {
	// path attributes

	Token               string
	Manufacturer        string
	Serial              string
	Model               string
	LibraryManufacturer string
	LibraryVersion      pkcs11.Version
	LibraryVersionSet   bool
	LibraryDescription  string
	Object              string
	Type                string
	ID                  string
	SlotDescription     string
	SlotManufacturer    string
	SlotID              int
	SlotIDSet           bool

	// query attributes

	PinSource        string
	PinValue         string
	ModuleName       string
	ModulePath       string
	VendorAttributes map[string]string
}

// Parse a PKCS#11 URI and assign path and query attributes to the corresponding fields in the returned PKCS11URI
// instance.
func Parse(p11Url string) (*PKCS11URI, error) {
	uriData, err := url.Parse(p11Url)
	if err != nil {
		return nil, fmt.Errorf("could not parse PKCS#11 URL: %w", err)
	}

	if uriData.Scheme != "pkcs11" {
		return nil, errors.New("a PKCS#11 URI must start with pkcs11")
	}

	if uriData.Opaque == "" {
		return nil, errors.New("a PKCS#11 URI must have a path")
	}

	pk11Path := strings.Split(uriData.Opaque, ";")
	if len(pk11Path) == 0 {
		return nil, errors.New("a PKCS#11 URI must contain at least one path attribute")
	}

	p11Uri := &PKCS11URI{}

	for _, pk11PathAttribute := range pk11Path {
		pathAttribute, err := url.ParseQuery(pk11PathAttribute)
		if err != nil {
			return nil, fmt.Errorf("could not parse PKCS#11 URL: %w", err)
		}

		err = matchAttribute(pathAttribute, p11Uri)
		if err != nil {
			return nil, err
		}
	}

	for k, v := range uriData.Query() {
		switch k {
		case "pin-source":
			p11Uri.PinSource = v[0]
		case "pin-value":
			p11Uri.PinValue = v[0]
		case "module-name":
			p11Uri.ModuleName = v[0]
		case "module-path":
			p11Uri.ModulePath = v[0]
		default:
			log.Printf("unhandled PKCS#11 URI query attribute %s: %s", k, v[0])
		}
	}

	return p11Uri, nil
}

func matchAttribute(attr url.Values, p11Uri *PKCS11URI) error {
	var err error

	for k, v := range attr {
		switch k {
		case "token":
			p11Uri.Token = v[0]
		case "manufacturer":
			p11Uri.Manufacturer = v[0]
		case "serial":
			p11Uri.Serial = v[0]
		case "model":
			p11Uri.Model = v[0]
		case "object":
			p11Uri.Object = v[0]
		case "library-manufacturer":
			p11Uri.LibraryManufacturer = v[0]
		case "library-version":
			p11Uri.LibraryVersionSet = true
			p11Uri.LibraryVersion, err = parseVersion(v[0])

			if err != nil {
				return fmt.Errorf("could not parse library version: %w", err)
			}
		case "pin-value":
			// this is a violation of RFC-7512, but is common in real applications like NetworkManager
			p11Uri.PinValue = v[0]
		case "library-description":
			p11Uri.LibraryDescription = v[0]
		default:
			log.Printf("unhandled PKCS#11 URI path attribute %s: %s", k, v[0])
		}
	}

	return nil
}

func parseVersion(s string) (pkcs11.Version, error) {
	version := pkcs11.Version{}

	_, err := fmt.Scanf("%d.%d", s, &version.Major, &version.Minor)
	if err != nil {
		return version, fmt.Errorf("version must be in format DIGIT.DIGIT: %w", err)
	}

	return version, nil
}
