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

	// 6. List items
	fmt.Println("[5] Listing items...")
	ids, err := session.List(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    Items in vault: %v\n", ids)

	// 7. Export credentials
	fmt.Println("[6] Exporting credentials...")
	exported, err := vault.ExportCredentials(creds, "export-passphrase")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    Exported credentials: %d bytes\n", len(exported))

	// 8. Import credentials and re-open vault
	fmt.Println("[7] Importing credentials and re-opening vault...")
	imported, err := vault.ImportCredentials(exported, "export-passphrase")
	if err != nil {
		log.Fatal(err)
	}
	session2, err := v.Open(ctx, imported)
	if err != nil {
		log.Fatal(err)
	}
	defer session2.Close()

	decrypted2, err := session2.Get(ctx, "item-1")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    Re-opened and decrypted: %q\n", string(decrypted2))

	// 9. Delete an item
	fmt.Println("[8] Deleting item...")
	err = session2.Delete(ctx, "item-1")
	if err != nil {
		log.Fatal(err)
	}
	ids, err = session2.List(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    Items after delete: %v\n", ids)

	fmt.Println("\n--- Demonstration Completed Successfully ---")
}
