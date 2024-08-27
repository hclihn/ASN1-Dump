package main

import (
	"bytes"
	"fmt"
  "crypto/x509"
  "encoding/asn1"
	"encoding/hex"
  "encoding/pem"
  "time"
  "strings"
  "unicode"
	"unicode/utf16"
	"unicode/utf8"

	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func main() {
  certs, err := GetCertsFromPEM([]byte(cert))
  if err != nil {
    fmt.Printf("ERROR: failed to get cert from PEM: %+v\n", err)
    return
  }
  _, info := GetCertInfo(certs[0])
  fmt.Printf("Cert Info: %s\n", info)
  s, err := DERDump(certs[0].Raw, 2)
  if err != nil {
    fmt.Printf("ERROR: failed to dump cert bytes: %+v\n", err)
    return
  }
	fmt.Printf("Cert dump:\n%s\n", s)
}

const cert = `-----BEGIN CERTIFICATE-----
	MIIIlzCCCD2gAwIBAgIRAMvURZGMQkPqoFqmAilLxJcwCgYIKoZIzj0EAwIwgYQx
	KzApBgoJkiaJk/IsZAEBDBtpZGVudGl0eTppZG1zLmdyb3VwLjU1MDQ0ODcxLTAr
	BgNVBAMMJGFwcGF1dGhvcml0eTAwNC5jbmd5YTA1LnBpZS5zaWx1Lm5ldDEmMCQG
	A1UECwwdbWFuYWdlbWVudDppZG1zLmdyb3VwLjE0MDUyMDYwHhcNMjQwNzAxMTkw
	MzA0WhcNMjQwNzExMTkwODA0WjCB9DELMAkGA1UEBhMCVVMxJzAlBgNVBAsMHm1h
	bmFnZW1lbnQ6aWRtcy5ncm91cC4xMDg2MjcwNDETMBEGA1UECwwKY24tZWFzdC0x
	ZTEtMCsGA1UEAwwkNzY5MTU3YmEtNWQ4Mi00MDk2LThlNGQtOGYxY2E2M2U0NThl
	MSwwKgYKCZImiZPyLGQBAQwcaWRlbnRpdHk6aWRtcy5ncm91cC4xMTEzMzE4NDEh
	MB8GA1UECwwYb3duZXI6aWRtcy5ncm91cC41NTQ4MzE2MScwJQYDVQQKDB5tYW5h
	Z2VtZW50OmlkbXMuZ3JvdXAuMTA4NjI3MDQwWTATBgcqhkjOPQIBBggqhkjOPQMB
	BwNCAARjFEFwiL3H0IVk/Jv5pAQZXnf5qyx3nrkRzbrWrlaI6EmfkmMU+ADdLwtF
	726ZLxoxVFKQmNpaMcwwd1rrWB8to4IGHDCCBhgwggN1BgNVHREEggNsMIIDaII2
	Y2Fib29kbGUtZ2F0ZWtlZXBlci1nY2JkLmNhYm9vZGxlLWdhdGVrZWVwZXItZ2Ni
	ZC5rdWJlgkcqLmNhYm9vZGxlLWdhdGVrZWVwZXItZ2NiZC5jYWJvb2RsZS1nYXRl
	a2VlcGVyLWdjYmQua3ViZS5jbG91ZC5zaWx1Lm5ldIZ7Zmx1ZmZ5Oi8vY2Fib29k
	bGUtZ2F0ZWtlZXBlci1nY2JkLmNhYm9vZGxlLWdhdGVrZWVwZXItZ2NiZC5rdWJl
	LjE0MDUyMDYvb3duZXI9NTU0ODMxNi9tYW5hZ2VtZW50PTEwODYyNzA0L2lkZW50
	aXR5PTExMTMzMTg0hwSsFQ4GhxAkAvFAEBABpgAAAAAAAAAGhwSsFQ4GhwSsESXo
	hxAkAvFAEComBgAAAAAAACG0hwSsFrP5glRjYWJvb2RsZS1nYXRla2VlcGVyLWdj
	YmQuY2Fib29kbGUtZ2F0ZWtlZXBlci1nY2JkLmt1YmUuY24tZWFzdC0xZS5rOHMu
	Y2xvdWQuc2lsdS5uZXSCPWNhYm9vZGxlLWdhdGVrZWVwZXItc2VydmljZS1nY2Jk
	LmNhYm9vZGxlLWdhdGVrZWVwZXItZ2NiZC5zdmOCYGNhYm9vZGxlLWdhdGVrZWVw
	ZXItc2VydmljZS1nY2JkLmNhYm9vZGxlLWdhdGVrZWVwZXItZ2NiZC5zdmMua3Vi
	ZS5jbi1lYXN0LTFlLms4cy5jbG91ZC5zaWx1Lm5ldIJiKi5jYWJvb2RsZS1nYXRl
	a2VlcGVyLXNlcnZpY2UtZ2NiZC5jYWJvb2RsZS1nYXRla2VlcGVyLWdjYmQuc3Zj
	Lmt1YmUuY24tZWFzdC0xZS5rOHMuY2xvdWQuc2lsdS5uZXSCeWNhYm9vZGxlLWdh
	dGVrZWVwZXItZ2NiZC5jYWJvb2RsZS1nYXRla2VlcGVyLXNlcnZpY2UtZ2NiZC5j
	YWJvb2RsZS1nYXRla2VlcGVyLWdjYmQuc3ZjLmt1YmUuY24tZWFzdC0xZS5rOHMu
	Y2xvdWQuc2lsdS5uZXSCVmNhYm9vZGxlLWdhdGVrZWVwZXItZ2NiZC5jYWJvb2Rs
	ZS1nYXRla2VlcGVyLXNlcnZpY2UtZ2NiZC5jYWJvb2RsZS1nYXRla2VlcGVyLWdj
	YmQuc3ZjMIIBjwYJKwYBBAE/hWcBBIIBgASCAXwKNmNhYm9vZGxlLWdhdGVrZWVw
	ZXItZ2NiZC5jYWJvb2RsZS1nYXRla2VlcGVyLWdjYmQua3ViZRIKY24tZWFzdC0x
	ZRqzAQgAEAAYACAAKAAwADgAQABKJAoKY24tZWFzdC0xZRIUcGxiLnBpZS1wbGIu
	cGllLXByb2QYAEokCgpjbi1lYXN0LTFlEhRrbm9kZTA1NzYuY25neWEwNS5raxgB
	YhgSFC5jYWJvb2RsZS1wcm94eS5rdWJlGABqFlBJRSBWSVAgJiBCR1AgTmV0d29y
	a3N4AIABAIoBHQoDU0RSEhZQSUUgVklQICYgQkdQIE5ldHdvcmtzIggIABAAGAAw
	ADI2Y2Fib29kbGUtZ2F0ZWtlZXBlci1nY2JkLmNhYm9vZGxlLWdhdGVrZWVwZXIt
	Z2NiZC5rdWJlMj5jYWJvb2RsZS1nYXRla2VlcGVyLXNlcnZpY2UtZ2NiZC5jYWJv
	b2RsZS1nYXRla2VlcGVyLWdjYmQua3ViZTAvBgkrBgEEAT+FZwMEIgQgZW50aXRs
	ZW1lbnRzLnByb2R1Y3Rpb24ucGxhdGZvcm0wJgYJKwYBBAE/hWcCBBkEF3NjaGVk
	dWxlc2lnbmVyLmt1YmUucGllMBkGCSsGAQQBP4VnCAQMBApjbi1lYXN0LTFlMBkG
	CSsGAQQBP4VnCQQMDApjbi1lYXN0LTFlMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/
	BAQDAgOoMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAdBgNVHQ4EFgQU
	y4KX227jqWQ/Njq9Uvlef70C/QIwHwYDVR0jBBgwFoAUdLWEy0Pd//HPJoMVgiTt
	bhd3c4QwCgYIKoZIzj0EAwIDSAAwRQIgLhHz+8j/1h69mmiTjI0G9fi1T0a/A1Y7
	PnLFXIRT198CIQDilFkRZ+Whk1drHncXldLDdk0+ioK7InRqNiyv6Gydrg==
-----END CERTIFICATE-----
`

func GetCertInfo(c *x509.Certificate) (bool, string) {
	now := time.Now()
	valid := now.After(c.NotBefore) && now.Before(c.NotAfter)
	info := fmt.Sprintf("%sCertificate %q issued by %q (SN=%v) valid from %s to %s - %sVALID",
		IfElse(c.IsCA, "CA ", ""), c.Subject, c.Issuer, c.SerialNumber, c.NotBefore, c.NotAfter,
		IfElse(valid, "", "NOT "))
	return valid, info
}

func GetCertsFromPEM(pemCerts []byte) ([]*x509.Certificate, error) {
	if len(pemCerts) == 0 {
		return nil, nil
	}
	certs := make([]*x509.Certificate, 0)
	errs := make([]string, 0)
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		certs = append(certs, cert)
	}
	if len(errs) > 0 {
		return nil, WrapTraceableErrorf(nil, "error parsing PEM certificates: %s", strings.Join(errs, ";"))
	}
	return certs, nil
}


var (
  	// Signed Data OIDs
	// PKCS#7 {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7)}
	OIDData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	// PKCS#9 {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)}
	OIDAttributeContentType       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDAttributeMessageDigest     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDAttributeSigningTime       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	OIDAttributeSmimeCapabilities = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 15}

	// Digest Algorithms
	// {iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2)}
	OIDDigestAlgorithmSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	// {joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithms(4) hashalgs(2)}
	OIDDigestAlgorithmSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDDigestAlgorithmSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDDigestAlgorithmSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDDigestAlgorithmSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}

	// {iso(1) member-body(2) us(840) x9-57(10040) x9algorithm(4)}
	OIDEncryptionAlgorithmDSA     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	OIDEncryptionAlgorithmDSASHA1 = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}

	// {iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4) ecdsa-with-SHA1(1)}
	OIDEncryptionAlgorithmECDSASHA1 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	// {iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4) ecdsa-with-SHA2(3)}
	OIDEncryptionAlgorithmECDSASHA224 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 1}
	OIDEncryptionAlgorithmECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDEncryptionAlgorithmECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDEncryptionAlgorithmECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// Signature Algorithms
	// PKCS#1 {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1)}
	OIDEncryptionAlgorithmRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDEncryptionAlgorithmRSASHA1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	//OIDEncryptionAlgorithmRSASSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	OIDEncryptionAlgorithmRSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDEncryptionAlgorithmRSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDEncryptionAlgorithmRSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDEncryptionAlgorithmRSASHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 14}

	// {iso(1) member-body(2) us(840) ansi-x962(10045) curves(3) prime(1)}
	//OIDEncryptionAlgorithmECDSAP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7} // secp256r1 or prime256v1
	// {iso(1) identified-organization(3) certicom(132) curve(0)}
	//OIDEncryptionAlgorithmECDSAP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34} // secp384r1
	//OIDEncryptionAlgorithmECDSAP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35} // secp521r1

	// PE signing from Microsoft
	// {iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) Microsoft(311) 2 1}
	OIDSpcIndirectDataContent = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	//OIDStatementType          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 11}
	//OIDSpcSpOpusInfo          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
	OIDSpcPeImageData = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
	//OIDIndividualSPKeyPurpose = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 21}

	// X.509 Certificate stuff
	// {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) pe(1)}
	OIDAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	// {iso(1) member-body(2) us(840) apple(113635) appleDataSecurity(100)}
	OIDAppleCertificateExtensions = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 24, 4}
	// {joint-iso-itu-t(2) ds(5) attributeType(4)}
	OIDCommonName             = asn1.ObjectIdentifier{2, 5, 4, 3}
	OIDCountryName            = asn1.ObjectIdentifier{2, 5, 4, 6}
	OIDLocalityName           = asn1.ObjectIdentifier{2, 5, 4, 7}
	OIDStateOrProvinceName    = asn1.ObjectIdentifier{2, 5, 4, 8}
	OIDOrganizationName       = asn1.ObjectIdentifier{2, 5, 4, 10}
	OIDOrganizationalUnitName = asn1.ObjectIdentifier{2, 5, 4, 11}
	// {joint-iso-itu-t(2) ds(5) certificateExtension(29)}
	OIDSubjectKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 14}
	OIDKeyUsage               = asn1.ObjectIdentifier{2, 5, 29, 15}
	OIDSubjectAltName         = asn1.ObjectIdentifier{2, 5, 29, 17}
	OIDBasicConstraints       = asn1.ObjectIdentifier{2, 5, 29, 19}
	OIDCRLDistributionPoints  = asn1.ObjectIdentifier{2, 5, 29, 31}
	OIDCertificatePolicies    = asn1.ObjectIdentifier{2, 5, 29, 32}
	OIDAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
	OIDExtKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 37}

  	// OIDNameMap is the OID string map used by OIDName
	OIDNameMap = map[string]string{
		OIDData.String():                       "PKCS#7 Data",
		OIDSignedData.String():                 "PKCS#7 Signed Data",
		OIDAttributeContentType.String():       "Content-Type Attribute",
		OIDAttributeMessageDigest.String():     "Message-Digest Attribute",
		OIDAttributeSigningTime.String():       "Signing-Time Attribute",
		OIDAttributeSmimeCapabilities.String(): "S/MIME-Capabilities Attribute",
		// digest algorithms
		OIDDigestAlgorithmSHA1.String():   "SHA1 Digest Algorithm",
		OIDDigestAlgorithmSHA224.String(): "SHA224 Digest Algorithm",
		OIDDigestAlgorithmSHA256.String(): "SHA256 Digest Algorithm",
		OIDDigestAlgorithmSHA384.String(): "SHA384 Digest Algorithm",
		OIDDigestAlgorithmSHA512.String(): "SHA512 Digest Algorithm",
		// DSA encryption
		OIDEncryptionAlgorithmDSA.String():     "DSA Encryption Algorithm",
		OIDEncryptionAlgorithmDSASHA1.String(): "DSA Encryption Algorithm with SHA1 Digest",
		// ECDSA encryption
		OIDEncryptionAlgorithmECDSASHA1.String():   "ECDSA Encryption Algorithm SHA1 Digest",
		OIDEncryptionAlgorithmECDSASHA224.String(): "ECDSA Encryption Algorithm SHA224 Digest",
		OIDEncryptionAlgorithmECDSASHA256.String(): "ECDSA Encryption Algorithm SHA256 Digest",
		OIDEncryptionAlgorithmECDSASHA384.String(): "ECDSA Encryption Algorithm SHA384 Digest",
		OIDEncryptionAlgorithmECDSASHA512.String(): "ECDSA Encryption Algorithm SHA512 Digest",
		// RSA encryption
		OIDEncryptionAlgorithmRSA.String():       "RSA Encryption Algorithm",
		OIDEncryptionAlgorithmRSASHA1.String():   "RSA Encryption Algorithm with SHA1 Digest",
		OIDEncryptionAlgorithmRSASHA224.String(): "RSA Encryption Algorithm with SHA224 Digest",
		OIDEncryptionAlgorithmRSASHA256.String(): "RSA Encryption Algorithm with SHA256 Digest",
		OIDEncryptionAlgorithmRSASHA384.String(): "RSA Encryption Algorithm with SHA384 Digest",
		OIDEncryptionAlgorithmRSASHA512.String(): "RSA Encryption Algorithm with SHA512 Digest",
		// PE stuff
		OIDSpcIndirectDataContent.String(): "Microsoft SPC Indirect Data Content",
		OIDSpcPeImageData.String():         "Microsoft SPC PE Image Data",
		// Apple stuff
		OIDAppleCertificateExtensions.String(): "Apple Certificate Extensions",
		// X.509 cert stuff
		OIDAuthorityInfoAccess.String():    "Authority Info Access",
		OIDCommonName.String():             "Common Name",
		OIDCountryName.String():            "Country Name",
		OIDLocalityName.String():           "Locality Name",
		OIDStateOrProvinceName.String():    "State/Province Name",
		OIDOrganizationName.String():       "Organization Name",
		OIDOrganizationalUnitName.String(): "Organizational Unit Name",
		OIDSubjectKeyIdentifier.String():   "Subject Key Identifier",
		OIDKeyUsage.String():               "Key Usage",
		OIDSubjectAltName.String():         "Subject Alternative Name",
		OIDBasicConstraints.String():       "Basic Constraints",
		OIDCRLDistributionPoints.String():  "CRL Distribution Points",
		OIDCertificatePolicies.String():    "Certificate Policies",
		OIDAuthorityKeyIdentifier.String(): "Authority Key Identifier",
		OIDExtKeyUsage.String():            "Extended Key Usage",
	}
)

func OIDName(oid asn1.ObjectIdentifier) string {
	oidStr := oid.String()
	name, ok := OIDNameMap[oidStr]
	if !ok {
		return oidStr
	}
	return fmt.Sprintf("%s:%q", oidStr, name)
}

func WrapTraceableErrorf(err error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", msg, err)
	}
	return fmt.Errorf("%s", msg)
}

func IfElse(cond bool, a, b any) any {
  if cond {
    return a
  }
  return b
}

// Asn1TagNames maps the ASN.1 tag value to its name. Trying to get as many as possible.
// Unlike cryptobyte (limited to simple tag), asn1.Unmarshal of asn1.RawValue will parse tag values of all kinds.
var Asn1TagNames = map[int]string{
	0:                       "EndOfContent",
	asn1.TagBoolean:         "Boolean",
	asn1.TagInteger:         "Integer",
	asn1.TagBitString:       "BitString",
	asn1.TagOctetString:     "OctetString",
	asn1.TagNull:            "Null",
	asn1.TagOID:             "ObjectIdentifier",
	7:                       "ObjectDescriptor",
	8:                       "External", // EmbeddedPDV was introduced in 1994 to replace the EXTERNAL type.
	9:                       "Real",
	asn1.TagEnum:            "Enumerated",
	11:                      "EmbeddedPDV",
	asn1.TagUTF8String:      "UTF8String",
	13:                      "RelativeOID",
	14:                      "Time", // ISO 8601: very general time formats!
	15:                      "Reserved",
	asn1.TagSequence:        "Sequence",
	asn1.TagSet:             "Set",
	asn1.TagNumericString:   "NumericString",
	asn1.TagPrintableString: "PrintableString",
	asn1.TagT61String:       "T61String",
	21:                      "VideotexString",  // This type is no longer used.
	asn1.TagIA5String:       "IA5String",       // International Alphabet 5
	asn1.TagUTCTime:         "UTCTime",         // in the form of "YYMMDDhhmm[ss]{Z|(+|-)hhmm}"
	asn1.TagGeneralizedTime: "GeneralizedTime", // in the form of "YYYYMMDDHH[MM[SS[.fff]]]{Z|(+|-)HHMM}"
	25:                      "GraphicString",   // Like GeneralString, using GraphicString is no longer recommended.
	26:                      "VisibleString",
	asn1.TagGeneralString:   "GeneralString", // It is too general to be implemented, therefore it is not recommended.
	// UniversalString: These are four-byte characters (Unicode-32), and are not recommended for use.
	// This type did not gain popularity, and it is often replaced with UTF8String.
	28:                "UniversalString",
	29:                "CharacterString", // allows the definition of character sets to be deferred until runtime
	asn1.TagBMPString: "BMPString",       // Basic Multilingual Plane string (Unicode-16)
	31:                "Date",            // in the form "YYYY-MM-DD"
	32:                "TimeOfDay",       // in the form "HH:MM:SS"
	33:                "DateTime",        // in the form "YYYY-MM-DDTHH:MM:SS"
	34:                "Duration",        // in the form of "P2Y10M15DT10H20M30S"
	35:                "OID-IRI",         // OID in Internationalized Resource Identifier (IRI) form
	36:                "RelativeOID-IRI", // Relative OID in IRI form
}

func GetBitString(data []byte) ([]byte, error) {
	if data[0] == 0 {
		return data[1:], nil
	}

	shift := data[0]
	if shift > 7 {
		return nil, WrapTraceableErrorf(nil, "Incorrect shift in BitString: %d", shift)
	}

	var buf bytes.Buffer
	var upperBits byte
	mask := (byte(1) << shift) - 1

	// shift string right and convert to hex
	for i := 1; i < len(data); i++ {
		 val := (data[i] >> shift) | upperBits
		 upperBits = (data[i] & mask) << (8 - shift)
		 buf.WriteByte(val)
	}
	return buf.Bytes(), nil
}

// GetASN1TagName returns the ASN.1 tag name from RawValue raw.
// For ContextSpecific, Application, and Private classes, it will return <class_name>[<tag_value>].
func GetAsn1TagName(raw asn1.RawValue) string {
	prefix := "UnknownClass" // the "default" one
	switch raw.Class {
	case asn1.ClassUniversal:
		// we don't use prefix in this class!
		name, ok := Asn1TagNames[raw.Tag]
		if !ok { // not in our lookup table
			return fmt.Sprintf("Tag#%d", raw.Tag)
		}
		return name
	case asn1.ClassContextSpecific:
		prefix = "Context"
	case asn1.ClassApplication:
		prefix = "Application"
	case asn1.ClassPrivate:
		prefix = "Private"
	}
	return fmt.Sprintf("%s[%d]", prefix, raw.Tag)
}

// GetAsn1PrimitiveInfo returns ASN.1 primitive tag info from RawValue raw.
// It parses OID, Boolean, time, and string to its best ability. Otherwise, it return <tag_name>(<length>).
func GetAsn1PrimitiveInfo(raw asn1.RawValue) (string, error) {
	l := len(raw.Bytes)
	// We don't have to parse every primitive type. Just enough for the debug purpose.
	if raw.Class != asn1.ClassUniversal {
		return fmt.Sprintf("%s(%d)", GetAsn1TagName(raw), l), nil
	}
	switch raw.Tag {
	case asn1.TagBoolean:
		return fmt.Sprintf("%s{%s}(%d)", GetAsn1TagName(raw), IfElse(raw.Bytes[0] == 0xff, "true", "false"), l), nil
	case asn1.TagOID:
		var oid asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(raw.FullBytes, &oid); err != nil {
			return "", WrapTraceableErrorf(err,
				"failed to get ASN.1 primitive info when parsing DER data (%#x) to OID", raw.FullBytes)
		} else if len(rest) != 0 {
			return "", WrapTraceableErrorf(err,
				"failed to get ASN.1 primitive info when parsing DER data to OID: extra DER followed %#x", rest)
		}
		return fmt.Sprintf("%s{%s}(%d)", GetAsn1TagName(raw), OIDName(oid), l), nil
	case asn1.TagUTF8String, asn1.TagNumericString, asn1.TagPrintableString, asn1.TagT61String, asn1.TagIA5String,
		asn1.TagBMPString, 26 /*VisibleString*/ :
		s, err := ParseASN1String(cryptobyte_asn1.Tag(raw.Tag), raw.Bytes)
		if err != nil {
			return "", WrapTraceableErrorf(err, "failed to get ASN.1 primitive info when parsing string")
		}
		return fmt.Sprintf("%s{%q}(%d)", GetAsn1TagName(raw), s, l), nil
	case asn1.TagUTCTime, asn1.TagGeneralizedTime:
		var t time.Time
		if rest, err := asn1.Unmarshal(raw.FullBytes, &t); err != nil {
			return "", WrapTraceableErrorf(err,
				"failed to get ASN.1 primitive info when parsing DER data (%#x) to time", raw.FullBytes)
		} else if len(rest) != 0 {
			return "", WrapTraceableErrorf(err,
				"failed to get ASN.1 primitive info when parsing DER data to time: extra DER followed %#x", rest)
		}
		return fmt.Sprintf("%s{%s, %q}(%d)", GetAsn1TagName(raw), t, string(raw.Bytes), l), nil
	case 14 /*Time*/, 31 /*Date*/, 32 /*TimeOfDay*/, 33 /*DateTime*/, 34, /*Duration*/
		// These time types are ISO8601 time format strings.
		35 /*OID-IRI*/, 36 /*RelativeOID-IRI*/, 7 /*ObjectDescriptor*/ :
		// IRI types and ObjectDescriptor are strings.
		return fmt.Sprintf("%s{%q}(%d)", GetAsn1TagName(raw), string(raw.Bytes), l), nil
	}
	return fmt.Sprintf("%s(%d)", GetAsn1TagName(raw), l), nil
}

func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}

// derDumperInfo is the infomation passed through DERDumper calls
type derDumperInfo struct {
	level  uint   // current recursion (indent) level
	idx    int    // start index to the original DER data
	hdrFmt string // header format (<offset>:<level>)
}

// DERDumper dumps the DER data structure info recursively.
// nIndent is the number fo spaces for each indent level
// info defines the info for the call. Use nil for level 0 (start-of-the-tree).
// Returns a list of strings parsed (even when an error happens).
// This is the workhorse of DERDump().
func DERDumper(data []byte, nIndent uint, info *derDumperInfo) ([]string, error) {
	if len(data) == 0 { // terminating condition
		return nil, nil
	}
	if info == nil { // starting level
		info = &derDumperInfo{level: 0, idx: 0}
		width := 0
		for l := len(data); l > 0; l >>= 8 {
			width++
		}
		// we will assume that number levels will be less than 256 in most cases
		info.hdrFmt = fmt.Sprintf("%%0%dx:%%02x", width*2)
	}
	msgs, line := make([]string, 0), make([]string, 0)
	indent := strings.Repeat(" ", int(info.level*nIndent))
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(data, &raw)
	if err != nil {
		return msgs, WrapTraceableErrorf(err,
			"failed to dump DER data when parsing data (%#x) at level %d offset %d", data, info.level, info.idx)
	}
	// the header part
	header := raw.FullBytes[:(len(raw.FullBytes) - len(raw.Bytes))]
	line = append(line, fmt.Sprintf(info.hdrFmt+" %s%02x %02x", info.idx, info.level, indent, header[0], header[1:]))
	if raw.IsCompound { // compond structure
		line = append(line, fmt.Sprintf(": %s(%d)", GetAsn1TagName(raw), len(raw.Bytes)))
		msgs = append(msgs, strings.Join(line, ""))
		nMsgs, err := DERDumper(raw.Bytes, 2, &derDumperInfo{
			level: info.level + 1, idx: info.idx + len(header), hdrFmt: info.hdrFmt})
		msgs = append(msgs, nMsgs...)
		if err != nil {
			return msgs, err
		}
	} else { // ASN.1 primitive
		isPrimitive := true
		if raw.Tag == asn1.TagOctetString { // try parsing substructure
			nMsgs, err := DERDumper(raw.Bytes, 2, &derDumperInfo{
				level: info.level + 1, idx: info.idx + len(header), hdrFmt: info.hdrFmt})
			if err == nil {
				line = append(line, fmt.Sprintf(": %s(%d)", GetAsn1TagName(raw), len(raw.Bytes)))
				msgs = append(msgs, strings.Join(line, ""))
				msgs = append(msgs, nMsgs...)
				isPrimitive = false
			}
		} else if raw.Tag == asn1.TagBitString { 
			buf, err := GetBitString(raw.Bytes)
			if err != nil {
				return msgs, WrapTraceableErrorf(err, 
					"failed to get ASN.1 primitive info when parsing DER data (%#x) to BitString at level %d offset %d", raw.FullBytes, info.level, info.idx)
			}
			// try parsing substructure in BitString value
			nMsgs, err := DERDumper(buf, 2, &derDumperInfo{
				level: info.level + 1, idx: info.idx + len(header) + 1, hdrFmt: info.hdrFmt})
			if err == nil {
				line = append(line, fmt.Sprintf(": %s(%d, pad:%db)", GetAsn1TagName(raw), len(raw.Bytes), raw.Bytes[0]))
				msgs = append(msgs, strings.Join(line, ""))
				msgs = append(msgs, nMsgs...)
				isPrimitive = false
			} else {
				line = append(line, fmt.Sprintf(": %s{%s}(%d, pad:%db)", GetAsn1TagName(raw), hex.EncodeToString(buf), len(raw.Bytes), raw.Bytes[0]))
				if raw.Bytes[0] > 0 {
					line = append(line, fmt.Sprintf(" %02x", raw.Bytes))
				}
				msgs = append(msgs, strings.Join(line, ""))
				isPrimitive = false
			}
		}
		if isPrimitive {
			pInfo, err := GetAsn1PrimitiveInfo(raw)
			if err != nil {
				return msgs, WrapTraceableErrorf(err, "failed to dump DER data at level %d offset %d", info.level, info.idx)
			}
			line = append(line, fmt.Sprintf(" %s", pInfo))
			if len(raw.Bytes) > 0 {
				if (raw.Class != asn1.ClassUniversal || raw.Tag == asn1.TagOctetString) && isPrintable(raw.Bytes) {
					line = append(line, fmt.Sprintf(" (%q)", string(raw.Bytes)))
				}
				line = append(line, fmt.Sprintf(" %02x", raw.Bytes))
			}
			msgs = append(msgs, strings.Join(line, ""))
		}
	}
	if len(rest) != 0 { // the sibling DER
		nMsgs, err := DERDumper(rest, 2, &derDumperInfo{
			level: info.level, idx: info.idx + len(raw.FullBytes), hdrFmt: info.hdrFmt})
		msgs = append(msgs, nMsgs...)
		if err != nil {
			return msgs, err
		}
	} else if info.level == 0 {
		// We need this in the `else if` part to only print once at the last sibling of the top-level DER!
		// Print the last line to indicate the ending offset
		msgs = append(msgs, fmt.Sprintf(info.hdrFmt, info.idx+len(raw.FullBytes)+len(rest), info.level))
	}
	return msgs, nil
}

// DERDump dumps the ASN.1 DER data structure with nIdent spaces for each level.
// Returns a string of dumped content (even when an error happens).
// This is the one most users should use.
func DERDump(data []byte, nIndent uint) (string, error) {
	msgs, err := DERDumper(data, nIndent, nil)
	s := strings.Join(msgs, "\n")
	if err != nil {
		return s, WrapTraceableErrorf(err, "failed to dump DER data")
	}
	return s, nil
}

func ParseASN1String(tag cryptobyte_asn1.Tag, value []byte) (string, error) {
	switch tag {
	case cryptobyte_asn1.T61String:
		return string(value), nil
	case cryptobyte_asn1.PrintableString: // for PrintableString it is 32 to 122.
		for _, b := range value {
			// merge isPrintable from std lib's crypto/x509/parser.go into here
			if 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9' ||
				'\'' <= b && b <= ')' || '+' <= b && b <= '/' ||
				b == ' ' || b == ':' || b == '=' || b == '?' ||
				// This is technically not allowed in a PrintableString. However, x509 certificates with wildcard
				// strings don't always use the correct string type so we permit it.
				b == '*' ||
				// This is not technically allowed either. However, not only is it relatively common, but there
				// are also a handful of CA certificates that contain it. At least one of which will not expire
				// until 2027.
				b == '&' {
				continue // isPrintable!
			}
			return "", WrapTraceableErrorf(nil, "failed to parse ASN.1 string: invalid PrintableString char %q in %q",
				b, value)
		}
		return string(value), nil
	case cryptobyte_asn1.UTF8String:
		if !utf8.Valid(value) {
			return "", WrapTraceableErrorf(nil, "failed to parse ASN.1 string: invalid UTF-8 string %q", value)
		}
		return string(value), nil
	case cryptobyte_asn1.Tag(asn1.TagBMPString): // the value is in the range 0 to 2^16 – 1
		if len(value)%2 != 0 {
			return "", WrapTraceableErrorf(nil,
				"failed to parse ASN.1 string: BMPString %q length (%d) is not an event number", value, len(value))
		}
		// Strip terminator if present.
		if l := len(value); l >= 2 && value[l-1] == 0 && value[l-2] == 0 {
			value = value[:l-2]
		}
		s := make([]uint16, 0, len(value)/2)
		for len(value) > 0 {
			s = append(s, uint16(value[0])<<8+uint16(value[1]))
			value = value[2:]
		}
		return string(utf16.Decode(s)), nil
	case cryptobyte_asn1.IA5String: // For IA5String the range is 0 to 127
		s := string(value)
		// merge isIA5String from std lib's crypto/x509/x509.go into here
		for _, r := range s {
			// Per RFC5280 "IA5String is limited to the set of ASCII characters"
			if r <= unicode.MaxASCII {
				continue // isIA5String!
			}
			return "", WrapTraceableErrorf(nil, "failed to parse ASN.1 string: invalid IA5String rune %q in %q", r, s)
		}
		return s, nil
	case 26: // VisibleString: We added it here!
		s := string(value)
		for _, r := range s {
			// Per X.691-0207: For VisibleString, it is 32 to 126
			// https://www.itu.int/ITU-T/studygroups/com17/languages/X.691-0207.pdf
			if r >= ' ' && r < unicode.MaxASCII {
				continue // Visible String!
			}
			return "", WrapTraceableErrorf(nil, "failed to parse ASN.1 string: invalid Visible String rune %q in %q",
				r, s)
		}
		return s, nil
	case cryptobyte_asn1.Tag(asn1.TagNumericString): // for NumericString it is 32 to 57
		for _, b := range value {
			if ('0' > b || b > '9') && b != ' ' {
				return "", WrapTraceableErrorf(nil,
					"failed to parse ASN.1 string: invalid NumericString char %q in %q", b, value)
			}
		}
		return string(value), nil
	}
	return "", WrapTraceableErrorf(nil, "unsupported ASN.1 string type (%v) with value %q", tag, value)
}

