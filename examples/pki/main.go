package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"net"

	"github.com/jmcleod/ironhand/pki"
	"github.com/jmcleod/ironhand/storage/memory"
	"github.com/jmcleod/ironhand/vault"
)

func main() {
	ctx := context.Background()
	fmt.Println("--- Ironhand PKI / Certificate Authority Demonstration ---")

	// 1. Create credentials and vault
	fmt.Println("\n[1] Creating credentials and vault...")
	creds, err := vault.NewCredentials("correct horse battery staple")
	if err != nil {
		log.Fatal(err)
	}
	defer creds.Destroy()

	repo := memory.NewRepository()
	v := vault.New("pki-vault", repo)
	session, err := v.Create(ctx, creds)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()
	fmt.Printf("    Vault created. Epoch: %d\n", session.Epoch())

	// 2. Initialize the vault as a Root CA
	fmt.Println("\n[2] Initializing vault as a Root CA...")
	caSubject := pkix.Name{
		CommonName:   "IronHand Demo Root CA",
		Organization: []string{"IronHand"},
		Country:      []string{"US"},
	}
	if err := pki.InitCA(ctx, session, caSubject, 10, false); err != nil {
		log.Fatal(err)
	}
	fmt.Println("    Root CA initialized.")

	// 3. Retrieve CA info
	fmt.Println("\n[3] Retrieving CA info...")
	info, err := pki.GetCAInfo(ctx, session)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    Subject:     %s\n", info.Subject)
	fmt.Printf("    Valid until: %s\n", info.NotAfter)
	fmt.Printf("    Next serial: %d\n", info.NextSerial)

	// 4. Download the CA certificate
	fmt.Println("\n[4] Downloading CA certificate...")
	caCertPEM, err := pki.GetCACertificate(ctx, session)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    CA certificate: %d bytes PEM\n", len(caCertPEM))

	// 5. Issue a server certificate
	fmt.Println("\n[5] Issuing a server certificate for api.example.com...")
	serverItemID, err := pki.IssueCertificate(ctx, session, pki.IssueCertRequest{
		Subject: pkix.Name{
			CommonName:   "api.example.com",
			Organization: []string{"Example Corp"},
		},
		ValidityDays: 365,
		KeyUsages:    x509.KeyUsageDigitalSignature,
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"api.example.com", "*.api.example.com"},
		IPAddresses:  []net.IP{net.ParseIP("10.0.0.1")},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    Server cert issued. Item ID: %s\n", serverItemID)

	// Retrieve and display the certificate details
	serverFields, err := session.Get(ctx, serverItemID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    Subject:      %s\n", string(serverFields[pki.FieldSubject]))
	fmt.Printf("    Serial:       %s\n", string(serverFields[pki.FieldSerialNumber]))
	fmt.Printf("    Valid from:   %s\n", string(serverFields[pki.FieldNotBefore]))
	fmt.Printf("    Valid until:  %s\n", string(serverFields[pki.FieldNotAfter]))
	fmt.Printf("    Algorithm:    %s\n", string(serverFields[pki.FieldKeyAlgorithm]))
	fmt.Printf("    Fingerprint:  %s\n", string(serverFields[pki.FieldFingerprintSHA256]))
	fmt.Printf("    Status:       %s\n", string(serverFields[pki.FieldStatus]))

	// 6. Issue a client certificate
	fmt.Println("\n[6] Issuing a client certificate for alice@example.com...")
	clientItemID, err := pki.IssueCertificate(ctx, session, pki.IssueCertRequest{
		Subject: pkix.Name{
			CommonName:   "alice@example.com",
			Organization: []string{"Example Corp"},
		},
		ValidityDays:   90,
		KeyUsages:      x509.KeyUsageDigitalSignature,
		ExtKeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
		EmailAddresses: []string{"alice@example.com"},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    Client cert issued. Item ID: %s\n", clientItemID)

	// 7. Check updated CA info
	fmt.Println("\n[7] Checking CA info after issuing certificates...")
	info, err = pki.GetCAInfo(ctx, session)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    Certs issued: %d\n", info.CertCount)
	fmt.Printf("    Next serial:  %d\n", info.NextSerial)

	// 8. Revoke the client certificate
	fmt.Println("\n[8] Revoking client certificate...")
	if err := pki.RevokeCertificate(ctx, session, clientItemID, 0); err != nil {
		log.Fatal(err)
	}
	revokedFields, err := session.Get(ctx, clientItemID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    Status after revocation: %s\n", string(revokedFields[pki.FieldStatus]))

	// 9. Renew the server certificate
	fmt.Println("\n[9] Renewing server certificate...")
	newServerItemID, err := pki.RenewCertificate(ctx, session, serverItemID, 365)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    New cert item ID: %s\n", newServerItemID)

	newFields, err := session.Get(ctx, newServerItemID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    New serial:       %s\n", string(newFields[pki.FieldSerialNumber]))
	fmt.Printf("    Previous item:    %s\n", string(newFields[pki.FieldPreviousItemID]))

	// Confirm old cert was revoked
	oldFields, err := session.Get(ctx, serverItemID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    Old cert status:  %s\n", string(oldFields[pki.FieldStatus]))

	// 10. Generate a CRL
	fmt.Println("\n[10] Generating Certificate Revocation List...")
	crlPEM, err := pki.GenerateCRL(ctx, session)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    CRL generated: %d bytes PEM\n", len(crlPEM))

	// 11. List all items in the vault to show certificates
	fmt.Println("\n[11] Listing vault items...")
	ids, err := session.List(ctx)
	if err != nil {
		log.Fatal(err)
	}
	certCount := 0
	for _, id := range ids {
		fields, err := session.Get(ctx, id)
		if err != nil {
			continue
		}
		if string(fields["_type"]) == "certificate" {
			certCount++
			fmt.Printf("    [cert] %s — %s (status: %s)\n",
				string(fields["_name"]),
				string(fields[pki.FieldSubject]),
				string(fields[pki.FieldStatus]),
			)
		}
	}
	fmt.Printf("    Total certificates: %d\n", certCount)

	fmt.Println("\n--- PKI Demonstration Completed Successfully ---")
}
