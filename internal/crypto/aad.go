package icrypto

import (
	"encoding/binary"
)

const (
	aadRecord  = "RECORD"
	aadField   = "FIELD"
	aadDEKWrap = "DEKWRAP"
	aadKEKWrap = "KEKWRAP"
)

func AADRecord(vaultID, recordType, recordID string, epoch uint64, ver int) []byte {
	return buildAAD(aadRecord, vaultID, recordType, recordID, epoch, ver)
}

func AADFieldContent(vaultID, itemID, fieldName string, itemVersion uint64, epoch uint64, ver int) []byte {
	return buildAAD(aadField, vaultID, itemID, fieldName, itemVersion, epoch, ver)
}

func AADDEKWrap(vaultID, itemID string, epoch uint64, ver int) []byte {
	return buildAAD(aadDEKWrap, vaultID, itemID, epoch, ver)
}

func AADKEKWrap(vaultID, memberID string, epoch uint64, ver int) []byte {
	return buildAAD(aadKEKWrap, vaultID, memberID, epoch, ver)
}

func buildAAD(parts ...any) []byte {
	var res []byte
	for _, p := range parts {
		switch v := p.(type) {
		case string:
			res = appendLenPrefix(res, []byte(v))
		case []byte:
			res = appendLenPrefix(res, v)
		case uint64:
			b := make([]byte, 8)
			binary.BigEndian.PutUint64(b, v)
			res = append(res, b...)
		case int:
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, uint32(v))
			res = append(res, b...)
		}
	}
	return res
}

func appendLenPrefix(b, data []byte) []byte {
	l := make([]byte, 4)
	binary.BigEndian.PutUint32(l, uint32(len(data)))
	b = append(b, l...)
	b = append(b, data...)
	return b
}
