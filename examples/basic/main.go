package main

import (
	"context"
	"fmt"
	"log"

	"github.com/jmcleod/ironhand/storage/memory"
	"github.com/jmcleod/ironhand/vault"
)

func main() {
	ctx := context.Background()
	fmt.Println("--- Ironhand End-to-End Flow Demonstration ---")

	// 1. Create credentials (generates secret key + keypair + MUK)
	fmt.Println("[1] Creating credentials...")
	creds, err := vault.NewCredentials("correct horse battery staple")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    Credentials created. Member ID: %s\n", creds.MemberID())
	fmt.Printf("    Secret Key: %s\n", creds.SecretKey().String())

	// 2. Create vault with defaults
	fmt.Println("[2] Creating new vault...")
	repo := memory.NewRepository()
	v := vault.New("default", repo)

	// 3. Create vault (owner derived from credentials)
	session, err := v.Create(ctx, creds)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()
	fmt.Printf("    Vault created. Epoch: %d\n", session.Epoch())

	// 4. Store a secret
	fmt.Println("[3] Adding a secret item to the vault...")
	err = session.Put(ctx, "item-1", []byte("This is a highly confidential message."), vault.WithContentType("text/plain"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("    Item 'item-1' added and encrypted.")

	// 5. Retrieve secret
	fmt.Println("[4] Retrieving and decrypting the item...")
	decrypted, err := session.Get(ctx, "item-1")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    Decrypted content: %q\n", string(decrypted))

	// 6. Re-open vault
	fmt.Println("[5] Re-opening vault...")
	openCreds, err := vault.OpenCredentials(
		creds.SecretKey(),
		"correct horse battery staple",
		creds.MemberID(),
		creds.PrivateKey(),
		vault.WithCredentialProfile(creds.Profile()),
	)
	if err != nil {
		log.Fatal(err)
	}
	session2, err := v.Open(ctx, openCreds)
	if err != nil {
		log.Fatal(err)
	}
	defer session2.Close()

	decrypted2, err := session2.Get(ctx, "item-1")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    Re-opened and decrypted: %q\n", string(decrypted2))

	fmt.Println("\n--- Demonstration Completed Successfully ---")
}
