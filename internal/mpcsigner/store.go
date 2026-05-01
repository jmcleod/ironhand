package mpcsigner

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/jmcleod/ironhand/internal/mpc"
	"github.com/jmcleod/ironhand/internal/mpc/frostsecp256k1"
	"github.com/jmcleod/ironhand/internal/util"
)

const signerStoreVersion = 1
const frostStateSnapshotVersion = 1

type FileStore struct {
	path       string
	passphrase string
}

type sealedSignerFile struct {
	Version    int                 `json:"version"`
	KDF        util.Argon2idParams `json:"kdf"`
	Salt       string              `json:"salt"`
	Ciphertext string              `json:"ciphertext"`
}

type signerSnapshot struct {
	Version           int                     `json:"version"`
	MemberID          string                  `json:"member_id"`
	PartyID           uint32                  `json:"party_id"`
	Name              string                  `json:"name,omitempty"`
	URL               string                  `json:"url,omitempty"`
	ECDHPrivateKey    string                  `json:"ecdh_private_key"`
	Ed25519PrivateKey string                  `json:"ed25519_private_key"`
	Identity          mpc.SignerIdentity      `json:"identity"`
	Keys              map[string]keySnapshot  `json:"keys,omitempty"`
	ApprovalRequests  []ApprovalRequestRecord `json:"approval_requests,omitempty"`
	FROSTState        *frostStateSnapshot     `json:"frost_state,omitempty"`
}

type frostStateSnapshot struct {
	Version  int                                 `json:"version"`
	DKG      []frostsecp256k1.DKGStateRecord     `json:"dkg,omitempty"`
	Signing  []frostsecp256k1.SigningStateRecord `json:"signing,omitempty"`
	Consumed map[string]string                   `json:"consumed_commitments,omitempty"`
}

type keySnapshot struct {
	VaultID        string                   `json:"vault_id,omitempty"`
	DKGSessionID   string                   `json:"dkg_session_id,omitempty"`
	DKGStatus      string                   `json:"dkg_status,omitempty"`
	Threshold      int                      `json:"threshold"`
	Members        []Member                 `json:"members"`
	Commitments    []mpc.PublicCommitment   `json:"commitments,omitempty"`
	Inbox          map[string]string        `json:"inbox,omitempty"`
	OutgoingShares map[string]string        `json:"outgoing_shares,omitempty"`
	Fragment       mpc.EncryptedFragment    `json:"fragment,omitempty"`
	PublicKey      mpc.Point                `json:"public_key,omitempty"`
	Nonces         map[string]nonceSnapshot `json:"nonces,omitempty"`
}

type nonceSnapshot struct {
	KeyID       string `json:"key_id"`
	SessionID   string `json:"session_id"`
	MessageHash string `json:"message_hash"`
	Nonce       string `json:"nonce"`
}

func NewFileStore(path, passphrase string) (*FileStore, error) {
	if path == "" {
		return nil, errors.New("signer state path must not be empty")
	}
	if passphrase == "" {
		return nil, errors.New("signer state passphrase must not be empty")
	}
	return &FileStore{path: path, passphrase: passphrase}, nil
}

func (s *FileStore) Load() (*signerSnapshot, bool, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var sealed sealedSignerFile
	if err := json.Unmarshal(data, &sealed); err != nil {
		return nil, false, err
	}
	if sealed.Version != signerStoreVersion {
		return nil, false, fmt.Errorf("unsupported signer state version %d", sealed.Version)
	}
	salt, err := base64.StdEncoding.DecodeString(sealed.Salt)
	if err != nil {
		return nil, false, fmt.Errorf("decode signer state salt: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		return nil, false, fmt.Errorf("decode signer state ciphertext: %w", err)
	}
	key, err := util.DeriveArgon2idKey(util.Normalize(s.passphrase), salt, sealed.KDF)
	if err != nil {
		return nil, false, err
	}
	defer util.WipeBytes(key)
	plaintext, err := util.DecryptAES(ciphertext, key)
	if err != nil {
		return nil, false, err
	}
	defer util.WipeBytes(plaintext)
	var snapshot signerSnapshot
	if err := json.Unmarshal(plaintext, &snapshot); err != nil {
		return nil, false, err
	}
	return &snapshot, true, nil
}

func (s *FileStore) Save(snapshot signerSnapshot) error {
	plaintext, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	defer util.WipeBytes(plaintext)
	salt, err := util.RandomBytes(16)
	if err != nil {
		return err
	}
	params, err := util.Argon2idProfile(util.KDFProfileInteractive)
	if err != nil {
		return err
	}
	key, err := util.DeriveArgon2idKey(util.Normalize(s.passphrase), salt, params)
	if err != nil {
		return err
	}
	defer util.WipeBytes(key)
	ciphertext, err := util.EncryptAES(plaintext, key)
	if err != nil {
		return err
	}
	sealed := sealedSignerFile{
		Version:    signerStoreVersion,
		KDF:        params,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	data, err := json.MarshalIndent(sealed, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(s.path))
	if err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func snapshotFromService(s *Service) signerSnapshot {
	keys := make(map[string]keySnapshot, len(s.keys))
	for keyID, state := range s.keys {
		commitments := make([]mpc.PublicCommitment, 0, len(state.commitments))
		for _, commitment := range state.commitments {
			commitments = append(commitments, commitment)
		}
		inbox := make(map[string]string, len(state.inbox))
		for partyID, share := range state.inbox {
			inbox[strconv.Itoa(partyID)] = share
		}
		outgoing := make(map[string]string, len(state.outgoingShares))
		for partyID, share := range state.outgoingShares {
			outgoing[strconv.Itoa(partyID)] = share
		}
		nonces := make(map[string]nonceSnapshot, len(state.nonces))
		for sessionID, nonce := range state.nonces {
			if nonce == nil || nonce.Nonce == nil {
				continue
			}
			nonces[sessionID] = nonceSnapshot{
				KeyID:       nonce.KeyID,
				SessionID:   nonce.SessionID,
				MessageHash: nonce.MessageHash,
				Nonce:       mpc.EncodeScalar(nonce.Nonce),
			}
		}
		keys[keyID] = keySnapshot{
			VaultID:        state.vaultID,
			DKGSessionID:   state.dkgSessionID,
			DKGStatus:      state.dkgStatus,
			Threshold:      state.threshold,
			Members:        append([]Member(nil), state.members...),
			Commitments:    commitments,
			Inbox:          inbox,
			OutgoingShares: outgoing,
			Fragment:       state.fragment,
			PublicKey:      state.publicKey,
			Nonces:         nonces,
		}
	}
	return signerSnapshot{
		Version:           signerStoreVersion,
		MemberID:          s.memberID,
		PartyID:           s.partyID,
		ECDHPrivateKey:    base64.StdEncoding.EncodeToString(s.ecdhPriv.Bytes()),
		Ed25519PrivateKey: base64.StdEncoding.EncodeToString([]byte(s.edPriv)),
		Identity:          s.identity,
		Keys:              keys,
		ApprovalRequests:  approvalRequestsFromService(s),
		FROSTState:        frostStateSnapshotFromDurable(s.frost),
	}
}

func approvalRequestsFromService(s *Service) []ApprovalRequestRecord {
	requests := make([]ApprovalRequestRecord, 0, len(s.approvals))
	for _, request := range s.approvals {
		requests = append(requests, *request)
	}
	return requests
}

func serviceStateFromSnapshot(snapshot *signerSnapshot) (*ecdh.PrivateKey, ed25519.PrivateKey, mpc.SignerIdentity, map[string]*keyState, map[string]*ApprovalRequestRecord, frostsecp256k1.DurableState, error) {
	if snapshot.Version != signerStoreVersion {
		return nil, nil, mpc.SignerIdentity{}, nil, nil, frostsecp256k1.DurableState{}, fmt.Errorf("unsupported signer snapshot version %d", snapshot.Version)
	}
	ecdhBytes, err := base64.StdEncoding.DecodeString(snapshot.ECDHPrivateKey)
	if err != nil {
		return nil, nil, mpc.SignerIdentity{}, nil, nil, frostsecp256k1.DurableState{}, fmt.Errorf("decode signer ECDH private key: %w", err)
	}
	ecdhPriv, err := ecdh.P256().NewPrivateKey(ecdhBytes)
	if err != nil {
		return nil, nil, mpc.SignerIdentity{}, nil, nil, frostsecp256k1.DurableState{}, fmt.Errorf("parse signer ECDH private key: %w", err)
	}
	edBytes, err := base64.StdEncoding.DecodeString(snapshot.Ed25519PrivateKey)
	if err != nil {
		return nil, nil, mpc.SignerIdentity{}, nil, nil, frostsecp256k1.DurableState{}, fmt.Errorf("decode signer approval private key: %w", err)
	}
	if len(edBytes) != ed25519.PrivateKeySize {
		return nil, nil, mpc.SignerIdentity{}, nil, nil, frostsecp256k1.DurableState{}, fmt.Errorf("invalid signer approval private key size")
	}
	keys := make(map[string]*keyState, len(snapshot.Keys))
	for keyID, state := range snapshot.Keys {
		inbox := make(map[int]string, len(state.Inbox))
		for rawPartyID, share := range state.Inbox {
			partyID, err := strconv.Atoi(rawPartyID)
			if err != nil {
				return nil, nil, mpc.SignerIdentity{}, nil, nil, frostsecp256k1.DurableState{}, fmt.Errorf("invalid saved DKG party ID %q: %w", rawPartyID, err)
			}
			inbox[partyID] = share
		}
		outgoing := make(map[int]string, len(state.OutgoingShares))
		for rawPartyID, share := range state.OutgoingShares {
			partyID, err := strconv.Atoi(rawPartyID)
			if err != nil {
				return nil, nil, mpc.SignerIdentity{}, nil, nil, frostsecp256k1.DurableState{}, fmt.Errorf("invalid saved outgoing DKG party ID %q: %w", rawPartyID, err)
			}
			outgoing[partyID] = share
		}
		commitments := make(map[int]mpc.PublicCommitment, len(state.Commitments))
		for _, commitment := range state.Commitments {
			commitments[commitment.PartyID] = commitment
		}
		nonces := make(map[string]*nonceState, len(state.Nonces))
		for sessionID, saved := range state.Nonces {
			nonce, ok := mpc.DecodeScalar(saved.Nonce)
			if !ok {
				return nil, nil, mpc.SignerIdentity{}, nil, nil, frostsecp256k1.DurableState{}, fmt.Errorf("invalid saved nonce for session %q", sessionID)
			}
			if saved.SessionID == "" {
				saved.SessionID = sessionID
			}
			nonces[sessionID] = &nonceState{
				KeyID:       saved.KeyID,
				SessionID:   saved.SessionID,
				MessageHash: saved.MessageHash,
				Nonce:       nonce,
			}
		}
		keys[keyID] = &keyState{
			vaultID:        state.VaultID,
			dkgSessionID:   state.DKGSessionID,
			dkgStatus:      state.DKGStatus,
			threshold:      state.Threshold,
			members:        append([]Member(nil), state.Members...),
			commitments:    commitments,
			inbox:          inbox,
			outgoingShares: outgoing,
			fragment:       state.Fragment,
			publicKey:      state.PublicKey,
			nonces:         nonces,
		}
	}
	approvals := make(map[string]*ApprovalRequestRecord, len(snapshot.ApprovalRequests))
	for _, request := range snapshot.ApprovalRequests {
		copy := request
		approvals[request.RequestID] = &copy
	}
	frost, err := durableFROSTStateFromSnapshot(snapshot.FROSTState)
	if err != nil {
		return nil, nil, mpc.SignerIdentity{}, nil, nil, frostsecp256k1.DurableState{}, err
	}
	return ecdhPriv, ed25519.PrivateKey(edBytes), snapshot.Identity, keys, approvals, frost, nil
}

func frostStateSnapshotFromDurable(state frostsecp256k1.DurableState) *frostStateSnapshot {
	if len(state.DKG) == 0 && len(state.Signing) == 0 && len(state.Consumed) == 0 {
		return nil
	}
	snapshot := &frostStateSnapshot{
		Version:  frostStateSnapshotVersion,
		DKG:      make([]frostsecp256k1.DKGStateRecord, 0, len(state.DKG)),
		Signing:  make([]frostsecp256k1.SigningStateRecord, 0, len(state.Signing)),
		Consumed: copyStringMap(state.Consumed),
	}
	for _, record := range state.DKG {
		snapshot.DKG = append(snapshot.DKG, record)
	}
	for _, record := range state.Signing {
		snapshot.Signing = append(snapshot.Signing, record)
	}
	slices.SortFunc(snapshot.DKG, func(a, b frostsecp256k1.DKGStateRecord) int {
		return stringsCompare(a.KeyID+":"+a.DKGID, b.KeyID+":"+b.DKGID)
	})
	slices.SortFunc(snapshot.Signing, func(a, b frostsecp256k1.SigningStateRecord) int {
		return stringsCompare(a.KeyID+":"+a.SessionID, b.KeyID+":"+b.SessionID)
	})
	return snapshot
}

func durableFROSTStateFromSnapshot(snapshot *frostStateSnapshot) (frostsecp256k1.DurableState, error) {
	if snapshot == nil {
		return frostsecp256k1.NewDurableState(), nil
	}
	if snapshot.Version != frostStateSnapshotVersion {
		return frostsecp256k1.DurableState{}, fmt.Errorf("unsupported FROST signer state version %d", snapshot.Version)
	}
	state, err := frostsecp256k1.ReconstructDurableState(snapshot.DKG, snapshot.Signing)
	if err != nil {
		return frostsecp256k1.DurableState{}, fmt.Errorf("reconstruct FROST signer state: %w", err)
	}
	if len(snapshot.Consumed) != 0 && !stringMapsEqual(snapshot.Consumed, state.Consumed) {
		return frostsecp256k1.DurableState{}, fmt.Errorf("FROST consumed commitment ownership does not match reconstructed signing records")
	}
	return state, nil
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func stringMapsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, leftValue := range left {
		if rightValue, ok := right[key]; !ok || rightValue != leftValue {
			return false
		}
	}
	return true
}

func stringsCompare(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
