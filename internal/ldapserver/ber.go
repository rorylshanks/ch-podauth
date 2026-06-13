package ldapserver

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	tagSequence      byte = 0x30
	tagInteger       byte = 0x02
	tagEnumerated    byte = 0x0a
	tagOctetString   byte = 0x04
	tagBindRequest   byte = 0x60
	tagBindResponse  byte = 0x61
	tagUnbindRequest byte = 0x42
	tagSimpleAuth    byte = 0x80
)

const (
	ldapResultSuccess            = 0
	ldapResultProtocolError      = 2
	ldapResultInvalidCredentials = 49
	ldapResultUnwillingToPerform = 53
)

var (
	errNeedMoreData = errors.New("need more data")
	errRequestLarge = errors.New("LDAP request too large")
)

type message struct {
	ID int
	Op any
}

type bindRequest struct {
	Version  int
	Username string
	Password string
}

type unbindRequest struct{}

type unsupportedRequest struct {
	Tag byte
}

type berElement struct {
	Tag   byte
	Value []byte
}

type berReader struct {
	data []byte
	pos  int
}

func readMessage(r *bufio.Reader, maxBytes int) (message, error) {
	tag, length, err := readTLVHeader(r)
	if err != nil {
		return message{}, err
	}
	if tag != tagSequence {
		return message{}, fmt.Errorf("LDAP message must be a sequence")
	}
	total := headerSizeForLength(length) + length
	// length < 0 / total < 0 guard against int overflow on 32-bit platforms,
	// where a 4-byte BER length can wrap negative and bypass the size cap.
	if length < 0 || total < 0 || total > maxBytes {
		return message{}, errRequestLarge
	}
	value := make([]byte, length)
	if _, err := io.ReadFull(r, value); err != nil {
		return message{}, err
	}
	return parseLDAPMessage(value)
}

func parseLDAPMessage(data []byte) (message, error) {
	reader := berReader{data: data}
	idEl, err := reader.next()
	if err != nil {
		return message{}, err
	}
	if idEl.Tag != tagInteger {
		return message{}, fmt.Errorf("LDAP message id must be integer")
	}
	msg := message{ID: parseInteger(idEl.Value)}

	opEl, err := reader.next()
	if err != nil {
		return message{}, err
	}
	if !reader.done() {
		return message{}, fmt.Errorf("LDAP message has trailing data")
	}

	switch opEl.Tag {
	case tagBindRequest:
		req, err := parseBindRequest(opEl.Value)
		if err != nil {
			return message{}, err
		}
		msg.Op = req
	case tagUnbindRequest:
		msg.Op = unbindRequest{}
	default:
		msg.Op = unsupportedRequest{Tag: opEl.Tag}
	}
	return msg, nil
}

func parseBindRequest(data []byte) (bindRequest, error) {
	reader := berReader{data: data}
	versionEl, err := reader.next()
	if err != nil {
		return bindRequest{}, err
	}
	if versionEl.Tag != tagInteger {
		return bindRequest{}, fmt.Errorf("bind version must be integer")
	}
	nameEl, err := reader.next()
	if err != nil {
		return bindRequest{}, err
	}
	if nameEl.Tag != tagOctetString {
		return bindRequest{}, fmt.Errorf("bind name must be octet string")
	}
	authEl, err := reader.next()
	if err != nil {
		return bindRequest{}, err
	}
	if authEl.Tag != tagSimpleAuth {
		return bindRequest{}, fmt.Errorf("only LDAP simple bind is supported")
	}
	if !reader.done() {
		return bindRequest{}, fmt.Errorf("bind request has trailing data")
	}
	return bindRequest{
		Version:  parseInteger(versionEl.Value),
		Username: string(nameEl.Value),
		Password: string(authEl.Value),
	}, nil
}

func (r *berReader) next() (berElement, error) {
	if r.pos >= len(r.data) {
		return berElement{}, errNeedMoreData
	}
	tag := r.data[r.pos]
	r.pos++
	length, err := r.readLength()
	if err != nil {
		return berElement{}, err
	}
	if length < 0 || r.pos+length > len(r.data) {
		return berElement{}, errNeedMoreData
	}
	value := r.data[r.pos : r.pos+length]
	r.pos += length
	return berElement{Tag: tag, Value: value}, nil
}

func (r *berReader) readLength() (int, error) {
	if r.pos >= len(r.data) {
		return 0, errNeedMoreData
	}
	first := r.data[r.pos]
	r.pos++
	if first&0x80 == 0 {
		return int(first), nil
	}
	count := int(first & 0x7f)
	if count == 0 {
		return 0, fmt.Errorf("indefinite BER lengths are not supported")
	}
	if count > 4 || r.pos+count > len(r.data) {
		return 0, errNeedMoreData
	}
	length := 0
	for i := 0; i < count; i++ {
		length = length<<8 + int(r.data[r.pos])
		r.pos++
	}
	return length, nil
}

func (r *berReader) done() bool {
	return r.pos == len(r.data)
}

func readTLVHeader(r *bufio.Reader) (byte, int, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	first, err := r.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	if first&0x80 == 0 {
		return tag, int(first), nil
	}
	count := int(first & 0x7f)
	if count == 0 {
		return 0, 0, fmt.Errorf("indefinite BER lengths are not supported")
	}
	if count > 4 {
		return 0, 0, fmt.Errorf("BER length is too large")
	}
	buf := make([]byte, count)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, 0, err
	}
	var length uint32
	for _, b := range buf {
		length = length<<8 + uint32(b)
	}
	return tag, int(length), nil
}

func headerSizeForLength(length int) int {
	if length < 128 {
		return 2
	}
	switch {
	case length <= 0xff:
		return 3
	case length <= 0xffff:
		return 4
	case length <= 0xffffff:
		return 5
	default:
		return 6
	}
}

func encodeLDAPBindResponse(messageID int, resultCode int, diagnostic string) []byte {
	response := encodeElement(tagBindResponse,
		append(append(
			encodeElement(tagEnumerated, encodeIntegerValue(resultCode)),
			encodeElement(tagOctetString, nil)...),
			encodeElement(tagOctetString, []byte(diagnostic))...,
		),
	)
	body := append(encodeElement(tagInteger, encodeIntegerValue(messageID)), response...)
	return encodeElement(tagSequence, body)
}

func encodeElement(tag byte, value []byte) []byte {
	out := []byte{tag}
	out = append(out, encodeLength(len(value))...)
	out = append(out, value...)
	return out
}

func encodeLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(length))
	i := 0
	for i < len(buf) && buf[i] == 0 {
		i++
	}
	lengthBytes := buf[i:]
	out := []byte{0x80 | byte(len(lengthBytes))}
	out = append(out, lengthBytes...)
	return out
}

func parseInteger(value []byte) int {
	if len(value) == 0 {
		return 0
	}
	result := 0
	for _, b := range value {
		result = result<<8 + int(b)
	}
	return result
}

func encodeIntegerValue(value int) []byte {
	if value == 0 {
		return []byte{0}
	}
	var buf [8]byte
	u := uint64(value)
	i := len(buf)
	for u > 0 {
		i--
		buf[i] = byte(u)
		u >>= 8
	}
	out := append([]byte(nil), buf[i:]...)
	if out[0]&0x80 != 0 {
		out = append([]byte{0}, out...)
	}
	return out
}
