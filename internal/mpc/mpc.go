package mpc

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"
)

const (
	CurveName = "P-256"
	domain    = "mpc-poc-threshold-schnorr-v2"
)

var (
	ErrInvalidKey          = errors.New("invalid key")
	ErrInvalidParticipants = errors.New("invalid participants")
)

type Point struct {
	X string `json:"x"`
	Y string `json:"y"`
}

type Commitment struct {
	PartyID int   `json:"partyId"`
	R       Point `json:"r"`
}

type ShareProof struct {
	PartyID int    `json:"partyId"`
	Z       string `json:"z"`
}

type Signature struct {
	Curve       string       `json:"curve"`
	R           Point        `json:"r"`
	Z           string       `json:"z"`
	Challenge   string       `json:"challenge"`
	Commitments []Commitment `json:"commitments"`
	Shares      []ShareProof `json:"shares"`
}

type PartyInfo struct {
	ID  int    `json:"id"`
	URL string `json:"url"`
}

type PublicCommitment struct {
	PartyID      int     `json:"partyId"`
	Coefficients []Point `json:"coefficients"`
}

type PublicKey struct {
	Curve       string `json:"curve"`
	Encoded     string `json:"encoded"`
	X           string `json:"x"`
	Y           string `json:"y"`
	Threshold   int    `json:"threshold"`
	Parties     int    `json:"parties"`
	PartyIDBase int    `json:"partyIdBase"`
}

type KeyMeta struct {
	ID          string
	CreatedAt   time.Time
	Threshold   int
	Parties     []PartyInfo
	PublicKey   Point
	Commitments []PublicCommitment
}

func NewKeyMeta(id string, threshold int, parties []PartyInfo, commitments []PublicCommitment) (*KeyMeta, error) {
	if threshold < 2 {
		return nil, fmt.Errorf("%w: threshold must be at least 2", ErrInvalidKey)
	}
	if len(parties) < threshold {
		return nil, fmt.Errorf("%w: parties must be greater than or equal to threshold", ErrInvalidKey)
	}
	if len(parties) > 20 {
		return nil, fmt.Errorf("%w: parties is capped at 20 for the demo service", ErrInvalidKey)
	}

	publicKey, err := CombinePublicKey(commitments)
	if err != nil {
		return nil, err
	}
	return &KeyMeta{
		ID:          id,
		CreatedAt:   time.Now().UTC(),
		Threshold:   threshold,
		Parties:     append([]PartyInfo(nil), parties...),
		PublicKey:   publicKey,
		Commitments: commitments,
	}, nil
}

func (k *KeyMeta) Public() PublicKey {
	return publicKey(k.PublicKey, k.Threshold, len(k.Parties))
}

func (k *KeyMeta) PartyIDs() []int {
	ids := make([]int, 0, len(k.Parties))
	for _, party := range k.Parties {
		ids = append(ids, party.ID)
	}
	sort.Ints(ids)
	return ids
}

func (k *KeyMeta) NormalizeParticipants(participants []int) ([]int, error) {
	return NormalizeParticipants(participants, k.Threshold, k.PartyIDs())
}

func (k *KeyMeta) Verify(message []byte, sig *Signature) bool {
	return Verify(message, k.PublicKey, sig)
}

func NormalizeParticipants(participants []int, threshold int, partyIDs []int) ([]int, error) {
	sort.Ints(partyIDs)
	if len(participants) == 0 {
		if len(partyIDs) < threshold {
			return nil, fmt.Errorf("%w: need at least %d configured parties", ErrInvalidParticipants, threshold)
		}
		participants = append([]int(nil), partyIDs[:threshold]...)
	}
	if len(participants) < threshold {
		return nil, fmt.Errorf("%w: need at least %d participants", ErrInvalidParticipants, threshold)
	}

	allowed := make(map[int]struct{}, len(partyIDs))
	for _, partyID := range partyIDs {
		allowed[partyID] = struct{}{}
	}

	seen := make(map[int]struct{}, len(participants))
	normalized := make([]int, 0, len(participants))
	for _, partyID := range participants {
		if _, ok := allowed[partyID]; !ok {
			return nil, fmt.Errorf("%w: party %d is not part of this key", ErrInvalidParticipants, partyID)
		}
		if _, ok := seen[partyID]; ok {
			return nil, fmt.Errorf("%w: party %d was provided more than once", ErrInvalidParticipants, partyID)
		}
		seen[partyID] = struct{}{}
		normalized = append(normalized, partyID)
	}
	sort.Ints(normalized)
	return normalized, nil
}

func GeneratePolynomial(threshold int) ([]*big.Int, error) {
	if threshold < 2 {
		return nil, fmt.Errorf("%w: threshold must be at least 2", ErrInvalidKey)
	}
	n := curve().Params().N
	coefficients := make([]*big.Int, threshold)
	for i := range coefficients {
		scalar, err := RandomScalar()
		if err != nil {
			return nil, err
		}
		coefficients[i] = scalar.Mod(scalar, n)
	}
	return coefficients, nil
}

func CommitmentsForPolynomial(partyID int, coefficients []*big.Int) PublicCommitment {
	points := make([]Point, 0, len(coefficients))
	for _, coefficient := range coefficients {
		points = append(points, ScalarBasePoint(coefficient))
	}
	return PublicCommitment{PartyID: partyID, Coefficients: points}
}

func EvalPolynomial(coefficients []*big.Int, x *big.Int) *big.Int {
	n := curve().Params().N
	result := big.NewInt(0)
	power := big.NewInt(1)
	for _, coefficient := range coefficients {
		term := new(big.Int).Mul(coefficient, power)
		result.Add(result, term)
		result.Mod(result, n)
		power.Mul(power, x)
		power.Mod(power, n)
	}
	return result
}

func VerifyPolynomialShare(shareHex string, recipientID int, commitment PublicCommitment) bool {
	share, ok := DecodeScalar(shareHex)
	if !ok {
		return false
	}
	lx, ly := curve().ScalarBaseMult(PadScalar(share))
	rx, ry, ok := EvaluateCommitment(commitment.Coefficients, recipientID)
	if !ok {
		return false
	}
	return lx.Cmp(rx) == 0 && ly.Cmp(ry) == 0
}

func CombinePublicKey(commitments []PublicCommitment) (Point, error) {
	if len(commitments) == 0 {
		return Point{}, fmt.Errorf("%w: no public commitments", ErrInvalidKey)
	}
	points := make([]Point, 0, len(commitments))
	for _, commitment := range commitments {
		if len(commitment.Coefficients) == 0 {
			return Point{}, fmt.Errorf("%w: party %d has no commitments", ErrInvalidKey, commitment.PartyID)
		}
		points = append(points, commitment.Coefficients[0])
	}
	return AddEncodedPoints(points)
}

func PublicShareCommitment(commitments []PublicCommitment, partyID int) (Point, error) {
	points := make([]Point, 0, len(commitments))
	for _, commitment := range commitments {
		x, y, ok := EvaluateCommitment(commitment.Coefficients, partyID)
		if !ok {
			return Point{}, fmt.Errorf("%w: invalid commitment for party %d", ErrInvalidKey, commitment.PartyID)
		}
		points = append(points, pointFromBig(x, y))
	}
	return AddEncodedPoints(points)
}

func EvaluateCommitment(coefficients []Point, partyID int) (*big.Int, *big.Int, bool) {
	c := curve()
	var accX, accY *big.Int
	power := big.NewInt(1)
	x := big.NewInt(int64(partyID))
	n := c.Params().N
	for _, coefficient := range coefficients {
		px, py, ok := DecodePoint(coefficient)
		if !ok || !c.IsOnCurve(px, py) {
			return nil, nil, false
		}
		tx, ty := c.ScalarMult(px, py, PadScalar(power))
		if accX == nil {
			accX, accY = tx, ty
		} else {
			accX, accY = c.Add(accX, accY, tx, ty)
		}
		power.Mul(power, x)
		power.Mod(power, n)
	}
	return accX, accY, accX != nil
}

func AddEncodedPoints(points []Point) (Point, error) {
	c := curve()
	var accX, accY *big.Int
	for _, point := range points {
		x, y, ok := DecodePoint(point)
		if !ok || !c.IsOnCurve(x, y) {
			return Point{}, fmt.Errorf("%w: invalid point", ErrInvalidKey)
		}
		if accX == nil {
			accX, accY = x, y
		} else {
			accX, accY = c.Add(accX, accY, x, y)
		}
	}
	if accX == nil {
		return Point{}, fmt.Errorf("%w: no points to add", ErrInvalidKey)
	}
	return pointFromBig(accX, accY), nil
}

func SignShare(localShare, nonce, challenge *big.Int, partyID int, participants []int) (*big.Int, error) {
	lambda, err := LagrangeCoefficientAtZero(partyID, participants)
	if err != nil {
		return nil, err
	}
	n := curve().Params().N
	z := new(big.Int).Mul(challenge, lambda)
	z.Mod(z, n)
	z.Mul(z, localShare)
	z.Add(z, nonce)
	z.Mod(z, n)
	return z, nil
}

func CombineSignatureShares(shares []ShareProof) (string, error) {
	if len(shares) == 0 {
		return "", fmt.Errorf("%w: no signature shares", ErrInvalidParticipants)
	}
	n := curve().Params().N
	z := big.NewInt(0)
	for _, share := range shares {
		value, ok := DecodeScalar(share.Z)
		if !ok {
			return "", fmt.Errorf("%w: invalid signature share from party %d", ErrInvalidParticipants, share.PartyID)
		}
		z.Add(z, value)
		z.Mod(z, n)
	}
	return EncodeScalar(z), nil
}

func Challenge(publicKey, r Point, message []byte) (*big.Int, error) {
	pubX, pubY, ok := DecodePoint(publicKey)
	if !ok || !curve().IsOnCurve(pubX, pubY) {
		return nil, fmt.Errorf("%w: invalid public key", ErrInvalidKey)
	}
	rx, ry, ok := DecodePoint(r)
	if !ok || !curve().IsOnCurve(rx, ry) {
		return nil, fmt.Errorf("%w: invalid nonce commitment", ErrInvalidKey)
	}
	return challengeScalar(pubX, pubY, rx, ry, message), nil
}

func Verify(message []byte, publicKey Point, sig *Signature) bool {
	if sig == nil || sig.Curve != CurveName {
		return false
	}
	pubX, pubY, ok := DecodePoint(publicKey)
	if !ok || !curve().IsOnCurve(pubX, pubY) {
		return false
	}
	rx, ry, ok := DecodePoint(sig.R)
	if !ok || !curve().IsOnCurve(rx, ry) {
		return false
	}
	z, ok := DecodeScalar(sig.Z)
	if !ok {
		return false
	}

	challenge := challengeScalar(pubX, pubY, rx, ry, message)
	leftX, leftY := curve().ScalarBaseMult(PadScalar(z))
	cpx, cpy := curve().ScalarMult(pubX, pubY, PadScalar(challenge))
	rightX, rightY := curve().Add(rx, ry, cpx, cpy)
	return leftX.Cmp(rightX) == 0 && leftY.Cmp(rightY) == 0
}

func ChallengeHex(publicKey, r Point, message []byte) (string, error) {
	challenge, err := Challenge(publicKey, r, message)
	if err != nil {
		return "", err
	}
	return EncodeScalar(challenge), nil
}

func AggregateCommitments(commitments []Commitment) (Point, error) {
	points := make([]Point, 0, len(commitments))
	for _, commitment := range commitments {
		points = append(points, commitment.R)
	}
	return AddEncodedPoints(points)
}

func LagrangeCoefficientAtZero(partyID int, participants []int) (*big.Int, error) {
	n := curve().Params().N
	numerator := big.NewInt(1)
	denominator := big.NewInt(1)
	xi := big.NewInt(int64(partyID))
	for _, otherID := range participants {
		if otherID == partyID {
			continue
		}
		xj := big.NewInt(int64(otherID))
		numerator.Mul(numerator, xj)
		numerator.Mod(numerator, n)

		diff := new(big.Int).Sub(xj, xi)
		diff.Mod(diff, n)
		denominator.Mul(denominator, diff)
		denominator.Mod(denominator, n)
	}

	inverse := new(big.Int).ModInverse(denominator, n)
	if inverse == nil {
		return nil, fmt.Errorf("%w: could not invert lagrange denominator", ErrInvalidParticipants)
	}
	out := numerator.Mul(numerator, inverse)
	out.Mod(out, n)
	return out, nil
}

func RandomScalar() (*big.Int, error) {
	n := CurveOrder()
	max := new(big.Int).Sub(n, big.NewInt(1))
	scalar, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return scalar.Add(scalar, big.NewInt(1)), nil
}

func ScalarBasePoint(value *big.Int) Point {
	x, y := curve().ScalarBaseMult(PadScalar(value))
	return pointFromBig(x, y)
}

func DecodeScalar(value string) (*big.Int, bool) {
	out, ok := decodeHexBig(value)
	if !ok || out.Sign() <= 0 || out.Cmp(CurveOrder()) >= 0 {
		return nil, false
	}
	return out, true
}

func EncodeScalar(value *big.Int) string {
	return hex.EncodeToString(value.FillBytes(make([]byte, scalarSize())))
}

func DecodePoint(point Point) (*big.Int, *big.Int, bool) {
	x, ok := decodeHexBig(point.X)
	if !ok {
		return nil, nil, false
	}
	y, ok := decodeHexBig(point.Y)
	if !ok {
		return nil, nil, false
	}
	return x, y, true
}

func PadScalar(value *big.Int) []byte {
	return value.FillBytes(make([]byte, scalarSize()))
}

func CurveOrder() *big.Int {
	return new(big.Int).Set(curve().Params().N)
}

func ZeroScalars(values []*big.Int) {
	for _, value := range values {
		if value != nil {
			value.SetInt64(0)
		}
	}
}

func publicKey(point Point, threshold, parties int) PublicKey {
	x, y, _ := DecodePoint(point)
	return PublicKey{
		Curve:       CurveName,
		Encoded:     hex.EncodeToString(elliptic.Marshal(curve(), x, y)),
		X:           point.X,
		Y:           point.Y,
		Threshold:   threshold,
		Parties:     parties,
		PartyIDBase: 1,
	}
}

func challengeScalar(pubX, pubY, rX, rY *big.Int, message []byte) *big.Int {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(elliptic.Marshal(curve(), pubX, pubY))
	h.Write(elliptic.Marshal(curve(), rX, rY))
	h.Write(message)
	out := new(big.Int).SetBytes(h.Sum(nil))
	out.Mod(out, curve().Params().N)
	return out
}

func pointFromBig(x, y *big.Int) Point {
	return Point{X: encodeBig(x), Y: encodeBig(y)}
}

func decodeHexBig(value string) (*big.Int, bool) {
	bytes, err := hex.DecodeString(value)
	if err != nil {
		return nil, false
	}
	return new(big.Int).SetBytes(bytes), true
}

func encodeBig(value *big.Int) string {
	return hex.EncodeToString(value.FillBytes(make([]byte, 32)))
}

func scalarSize() int {
	return (curve().Params().N.BitLen() + 7) / 8
}

func curve() elliptic.Curve {
	return elliptic.P256()
}
