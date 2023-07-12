/*
Copyright 2023 Deutsche Telekom MMS GmbH
SPDX-License-Identifier: MIT
*/

// Package p11support provides the interface to PKCS#11 tokens.
package p11support

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/ThalesIgnite/crypto11"
	"github.com/miekg/pkcs11"

	"github.com/telekom-mms/p11support/pkg/pkcs11uri"
)

// ErrNoTokenFound is used to signal that there is no usable token available.
var ErrNoTokenFound = errors.New("no matching token found")

const minimumRSAKeyLength = 2048

// P11Support encapsulates PKCS#11 token functionality.
type P11Support struct {
	label        []byte
	token        *crypto11.Context
	keyAlgorithm x509.PublicKeyAlgorithm
	keyParameter interface{}
}

// New creates a new P11Support instance for the given PKCS#11 library module and the given PKCS#11 URI.
func New(p11Module, p11Uri, keyAlgorithm, keyParameter string) (*P11Support, error) {
	pkcs11URI, err := pkcs11uri.Parse(p11Uri)
	if err != nil {
		return nil, fmt.Errorf("PKCS#11 URI problem: %w", err)
	}

	keyAlgorithmID, keyParameterValue, err := parseKeyParameters(keyAlgorithm, keyParameter)
	if err != nil {
		return nil, err
	}

	context, err := findToken(p11Module, pkcs11URI)
	if err != nil {
		return nil, fmt.Errorf("could not find token: %w", err)
	}

	if pkcs11URI.Object == "" {
		return nil, fmt.Errorf(
			"object attribute used as key and certificate label is missing in PKCS#11 URI %s",
			p11Uri,
		)
	}

	return &P11Support{
		token:        context,
		label:        []byte(pkcs11URI.Object),
		keyAlgorithm: keyAlgorithmID,
		keyParameter: keyParameterValue,
	}, nil
}

func parseKeyParameters(algorithm string, parameter string) (x509.PublicKeyAlgorithm, interface{}, error) {
	var (
		algorithmIdentifier x509.PublicKeyAlgorithm
		keyParameters       interface{}
	)

	switch strings.ToLower(algorithm) {
	case "rsa":
		algorithmIdentifier = x509.RSA

		keyLength, err := strconv.Atoi(parameter)
		if err != nil {
			return x509.UnknownPublicKeyAlgorithm, nil, fmt.Errorf("could not parse RSA key length: %w", err)
		}

		if keyLength < minimumRSAKeyLength {
			return x509.UnknownPublicKeyAlgorithm, nil, fmt.Errorf(
				"RSA keys must be at least %d bits long",
				minimumRSAKeyLength,
			)
		}

		keyParameters = keyLength
	case "ec", "ecdsa":
		algorithmIdentifier = x509.ECDSA

		switch strings.ToLower(parameter) {
		case "p224":
			keyParameters = elliptic.P224()
		case "p256":
			keyParameters = elliptic.P256()
		case "p384":
			keyParameters = elliptic.P384()
		case "p521":
			keyParameters = elliptic.P521()
		default:
			return x509.UnknownPublicKeyAlgorithm, nil, fmt.Errorf(
				"%s is not a valid ECDSA curve, supported values are 'p224', 'p256', 'p384' and 'p521'",
				parameter,
			)
		}
	case "":
		algorithmIdentifier = x509.ECDSA
		keyParameters = elliptic.P384()
	default:
		return x509.UnknownPublicKeyAlgorithm, nil, fmt.Errorf(
			"unsupported public key algorithm %s. supported values are 'rsa', 'ecdsa' (or 'ec')",
			algorithm,
		)
	}

	return algorithmIdentifier, keyParameters, nil
}

func findToken(library string, uri *pkcs11uri.PKCS11URI) (*crypto11.Context, error) {
	if uri.ModulePath != "" && uri.ModulePath != library {
		return nil, ErrNoTokenFound
	}

	if uri.ModuleName != "" && uri.ModuleName != strings.Split(path.Base(library), ".")[0] {
		return nil, ErrNoTokenFound
	}

	c11Config := &crypto11.Config{Path: library}

	if uri.Serial != "" {
		c11Config.TokenSerial = uri.Serial
	} else if uri.Token != "" {
		c11Config.TokenLabel = uri.Token
	}

	if uri.SlotIDSet {
		c11Config.SlotNumber = &uri.SlotID
	}

	if uri.PinValue != "" {
		c11Config.Pin = uri.PinValue
	} else {
		c11Config.LoginNotSupported = true
	}

	c11Context, err := crypto11.Configure(c11Config)
	if err != nil {
		return nil, fmt.Errorf("could not initialize crypto11 context: %w", err)
	}

	return c11Context, nil
}

// NewP11TokenCert returns the client certificate including its associated private key handle for TLS client
// authentication, the actual certificate instance and a new signing request for renewal of the certificate.
//
// An error is returned if retrieving the key pair or the certificate from the token fails, or if the CSR
// cannot be generated.
func (s *P11Support) NewP11TokenCert() ([]tls.Certificate, *x509.Certificate, []byte, error) {
	privateKey, err := s.token.FindKeyPair(nil, s.label)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not find key pair: %w", err)
	}

	cert, err := s.token.FindCertificate(nil, s.label, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not find certificate: %w", err)
	}

	if cert == nil {
		return nil, nil, nil, fmt.Errorf("no certificate found for label %s", s.label)
	}

	certificates := []tls.Certificate{{
		PrivateKey:  privateKey,
		Leaf:        cert,
		Certificate: [][]byte{cert.Raw},
	}}

	csrTemplate := &x509.CertificateRequest{
		Subject:   cert.Subject,
		DNSNames:  cert.DNSNames,
		PublicKey: cert.PublicKey,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not create signing request: %w", err)
	}

	return certificates, cert, csr, nil
}

// GetExistingCertificate retrieves an existing certificate identified by the label from the PKCS#11 URI.
func (s *P11Support) GetExistingCertificate() (*x509.Certificate, error) {
	cert, err := s.token.FindCertificate(nil, s.label, nil)
	if err != nil {
		return nil, fmt.Errorf("could not find certificate pairs: %w", err)
	}

	return cert, nil
}

// BuildNewCSR creates a new certificate signing request (CSR) for the given fully qualified domain name (fqdn).
// A new keypair for the label in the PKCS#11 URI is generated if there is none yet.
func (s *P11Support) BuildNewCSR(fqdn string, deleteExisting bool) ([]byte, error) {
	if deleteExisting {
		err := s.token.DeleteCertificate(nil, s.label, nil)
		if err != nil {
			return nil, fmt.Errorf("could not delete existing certificate: %w", err)
		}
	}

	privateKey, err := s.token.FindKeyPair(nil, s.label)
	if err != nil {
		return nil, fmt.Errorf("could not find private key: %w", err)
	}

	if privateKey == nil {
		privateKey, err = s.generatePrivateKey()
		if err != nil {
			return nil, err
		}
	}

	csrTemplate := &x509.CertificateRequest{
		Subject:   pkix.Name{CommonName: fqdn},
		DNSNames:  []string{fqdn},
		PublicKey: privateKey.Public(),
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return nil, fmt.Errorf("could not create signing request: %w", err)
	}

	return csr, nil
}

func (s *P11Support) generatePrivateKey() (crypto11.Signer, error) {
	keyID, err := generateRandomID()
	if err != nil {
		return nil, fmt.Errorf("could not generate id for private key: %w", err)
	}

	var privateKey crypto11.Signer

	switch s.keyAlgorithm {
	case x509.RSA:
		privateKey, err = s.token.GenerateRSAKeyPairWithLabel(keyID, s.label, s.keyParameter.(int))
	case x509.ECDSA:
		privateKey, err = s.token.GenerateECDSAKeyPairWithLabel(keyID, s.label, s.keyParameter.(elliptic.Curve))
	default:
		return nil, fmt.Errorf("unsupported public key algorithm %s", s.keyAlgorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("could not create private key: %w", err)
	}

	return privateKey, nil
}

func generateRandomID() ([]byte, error) {
	const pkcs11IdLength = 16
	generatedID := make([]byte, pkcs11IdLength)

	l, err := rand.Reader.Read(generatedID)
	if err != nil {
		return nil, fmt.Errorf("could not read random bytes: %w", err)
	}

	if l != pkcs11IdLength {
		return nil, errors.New("could not read enough random bytes")
	}

	return generatedID, nil
}

// StoreCertificate stores the given certificate in a certificate entry of the PKCS#11 token with the same id and label
// as the corresponding private key. The label is taken from the PKCS#11 URI.
func (s *P11Support) StoreCertificate(certificate *x509.Certificate) error {
	key, err := s.token.FindKeyPair(nil, s.label)
	if err != nil {
		return fmt.Errorf("could not find key for label %s: %w", s.label, err)
	}

	if key == nil {
		return fmt.Errorf("could not find key for label %s", s.label)
	}

	id, err := s.token.GetAttribute(key, pkcs11.CKA_ID)
	if err != nil {
		return fmt.Errorf("could not get ID for key: %w", err)
	}

	cert, err := s.token.FindCertificate(id.Value, s.label, nil)
	if err != nil {
		return fmt.Errorf("could not find certificate for id %s: %w", id.Value, err)
	}

	if cert != nil {
		err = s.token.DeleteCertificate(id.Value, s.label, cert.SerialNumber)
		if err != nil {
			return fmt.Errorf("could not delete existing certificate for id %s: %w", id.Value, err)
		}
	}

	err = s.token.ImportCertificateWithLabel(id.Value, s.label, certificate)
	if err != nil {
		return fmt.Errorf("could not import certificate: %w", err)
	}

	return nil
}
