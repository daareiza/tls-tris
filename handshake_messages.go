// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

func writeLen(buf []byte, v, size int) {
	for i := 0; i < size; i++ {
		buf[size-i-1] = byte(v)
		v >>= 8
	}
	if v != 0 {
		panic("length is too long")
	}
}

type byteBuilder struct {
	buf       *[]byte
	start     int
	prefixLen int
	child     *byteBuilder
}

func newByteBuilder() *byteBuilder {
	buf := make([]byte, 0, 32)
	return &byteBuilder{buf: &buf}
}

func (bb *byteBuilder) len() int {
	return len(*bb.buf) - bb.start - bb.prefixLen
}

func (bb *byteBuilder) data() []byte {
	bb.flush()
	return (*bb.buf)[bb.start+bb.prefixLen:]
}

func (bb *byteBuilder) flush() {
	if bb.child == nil {
		return
	}
	bb.child.flush()
	writeLen((*bb.buf)[bb.child.start:], bb.child.len(), bb.child.prefixLen)
	bb.child = nil
	return
}

func (bb *byteBuilder) finish() []byte {
	bb.flush()
	return *bb.buf
}

func (bb *byteBuilder) addU8(u uint8) {
	bb.flush()
	*bb.buf = append(*bb.buf, u)
}

func (bb *byteBuilder) addU16(u uint16) {
	bb.flush()
	*bb.buf = append(*bb.buf, byte(u>>8), byte(u))
}

func (bb *byteBuilder) addU24(u int) {
	bb.flush()
	*bb.buf = append(*bb.buf, byte(u>>16), byte(u>>8), byte(u))
}

func (bb *byteBuilder) addU32(u uint32) {
	bb.flush()
	*bb.buf = append(*bb.buf, byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}

func (bb *byteBuilder) addU64(u uint64) {
	bb.flush()
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], u)
	*bb.buf = append(*bb.buf, b[:]...)
}

func (bb *byteBuilder) addU8LengthPrefixed() *byteBuilder {
	return bb.createChild(1)
}

func (bb *byteBuilder) addU16LengthPrefixed() *byteBuilder {
	return bb.createChild(2)
}

func (bb *byteBuilder) addU24LengthPrefixed() *byteBuilder {
	return bb.createChild(3)
}

func (bb *byteBuilder) addU32LengthPrefixed() *byteBuilder {
	return bb.createChild(4)
}

func (bb *byteBuilder) addBytes(b []byte) {
	bb.flush()
	*bb.buf = append(*bb.buf, b...)
}

func (bb *byteBuilder) createChild(lengthPrefixSize int) *byteBuilder {
	bb.flush()
	bb.child = &byteBuilder{
		buf:       bb.buf,
		start:     len(*bb.buf),
		prefixLen: lengthPrefixSize,
	}
	for i := 0; i < lengthPrefixSize; i++ {
		*bb.buf = append(*bb.buf, 0)
	}
	return bb.child
}

func (bb *byteBuilder) discardChild() {
	if bb.child == nil {
		return
	}
	*bb.buf = (*bb.buf)[:bb.child.start]
	bb.child = nil
}

type byteReader []byte

func (br *byteReader) readInternal(out *byteReader, n int) bool {
	if len(*br) < n {
		return false
	}
	*out = (*br)[:n]
	*br = (*br)[n:]
	return true
}

func (br *byteReader) readBytes(out *[]byte, n int) bool {
	var child byteReader
	if !br.readInternal(&child, n) {
		return false
	}
	*out = []byte(child)
	return true
}

func (br *byteReader) readUint(out *uint64, n int) bool {
	var b []byte
	if !br.readBytes(&b, n) {
		return false
	}
	*out = 0
	for _, v := range b {
		*out <<= 8
		*out |= uint64(v)
	}
	return true
}

func (br *byteReader) readU8(out *uint8) bool {
	var b []byte
	if !br.readBytes(&b, 1) {
		return false
	}
	*out = b[0]
	return true
}

func (br *byteReader) readU16(out *uint16) bool {
	var v uint64
	if !br.readUint(&v, 2) {
		return false
	}
	*out = uint16(v)
	return true
}

func (br *byteReader) readU24(out *uint32) bool {
	var v uint64
	if !br.readUint(&v, 3) {
		return false
	}
	*out = uint32(v)
	return true
}

func (br *byteReader) readU32(out *uint32) bool {
	var v uint64
	if !br.readUint(&v, 4) {
		return false
	}
	*out = uint32(v)
	return true
}

func (br *byteReader) readU64(out *uint64) bool {
	return br.readUint(out, 8)
}

func (br *byteReader) readLengthPrefixed(out *byteReader, n int) bool {
	var length uint64
	return br.readUint(&length, n) &&
		uint64(len(*br)) >= length &&
		br.readInternal(out, int(length))
}

func (br *byteReader) readLengthPrefixedBytes(out *[]byte, n int) bool {
	var length uint64
	return br.readUint(&length, n) &&
		uint64(len(*br)) >= length &&
		br.readBytes(out, int(length))
}

func (br *byteReader) readU8LengthPrefixed(out *byteReader) bool {
	return br.readLengthPrefixed(out, 1)
}
func (br *byteReader) readU8LengthPrefixedBytes(out *[]byte) bool {
	return br.readLengthPrefixedBytes(out, 1)
}

func (br *byteReader) readU16LengthPrefixed(out *byteReader) bool {
	return br.readLengthPrefixed(out, 2)
}
func (br *byteReader) readU16LengthPrefixedBytes(out *[]byte) bool {
	return br.readLengthPrefixedBytes(out, 2)
}

func (br *byteReader) readU24LengthPrefixed(out *byteReader) bool {
	return br.readLengthPrefixed(out, 3)
}
func (br *byteReader) readU24LengthPrefixedBytes(out *[]byte) bool {
	return br.readLengthPrefixedBytes(out, 3)
}

func (br *byteReader) readU32LengthPrefixed(out *byteReader) bool {
	return br.readLengthPrefixed(out, 4)
}
func (br *byteReader) readU32LengthPrefixedBytes(out *[]byte) bool {
	return br.readLengthPrefixedBytes(out, 4)
}

// signAlgosCertList helper function returns either list of signature algorithms in case
// signature_algorithms_cert extension should be marshalled or nil in the other case.
// signAlgos is a list of algorithms from signature_algorithms extension. signAlgosCert is a list
// of algorithms from signature_algorithms_cert extension.
func signAlgosCertList(signAlgos, signAlgosCert []SignatureScheme) []SignatureScheme {
	if eqSignatureAlgorithms(signAlgos, signAlgosCert) {
		// ensure that only supported_algorithms extension is send if supported_algorithms_cert
		// has identical content
		return nil
	}
	return signAlgosCert
}

type clientHelloMsg struct {
	raw                          []byte
	rawTruncated                 []byte // for PSK binding
	vers                         uint16
	random                       []byte
	sessionId                    []byte
	cookie                       []byte
	cipherSuites                 []uint16
	compressionMethods           []uint8
	nextProtoNeg                 bool
	serverName                   string
	ocspStapling                 bool
	sctListSupported             bool
	supportedCurves              []CurveID
	supportedPoints              []uint8
	ticketSupported              bool
	sessionTicket                []uint8
	signatureAlgorithms          []SignatureScheme
	signatureAlgorithmsCert      []SignatureScheme
	secureRenegotiation          []byte
	secureRenegotiationSupported bool
	alpnProtocols                []string
	keyShares                    []keyShareEntry
	supportedVersions            []uint16
	pskIdentities                []pskIdentity
	pskKeyExchangeModes          []uint8
	pskBinders                   [][]uint8
	pskBinderFirst               bool
	hasEarlyData                 bool
	delegatedCredentials         bool
	extendedMasterSecret         bool // RFC7627
	trailingKeyShareData         bool
	tls13Cookie                  []byte
	quicTransportParams          []byte
	duplicateExtension           bool
	channelIDSupported           bool
	tokenBindingParams           []byte
	tokenBindingVersion          uint16
	npnAfterAlpn                 bool
	srtpProtectionProfiles       []uint16
	srtpMasterKeyIdentifier      string
	customExtension              string
	pad                          int
	pqExperimentSignal           bool
}

// Function used for signature_algorithms and signature_algorithrms_cert
// extensions only (for more details, see TLS 1.3 draft 28, 4.2.3).
//
// It advances data slice and returns it, so that it can be used for further
// processing
func marshalExtensionSignatureAlgorithms(extension uint16, data []byte, schemes []SignatureScheme) []byte {
	algNum := uint16(len(schemes))
	if algNum == 0 {
		return data
	}

	binary.BigEndian.PutUint16(data, extension)
	data = data[2:]
	binary.BigEndian.PutUint16(data, (2*algNum)+2) // +1 for length
	data = data[2:]
	binary.BigEndian.PutUint16(data, (2 * algNum))
	data = data[2:]

	for _, algo := range schemes {
		binary.BigEndian.PutUint16(data, uint16(algo))
		data = data[2:]
	}
	return data
}

// Function used for unmarshalling signature_algorithms or signature_algorithms_cert extensions only
// (for more details, see TLS 1.3 draft 28, 4.2.3)
// In case of error function returns alertDecoderError otherwise filled SignatureScheme slice and alertSuccess
func unmarshalExtensionSignatureAlgorithms(data []byte, length int) ([]SignatureScheme, alert) {

	if length < 2 || length&1 != 0 {
		return nil, alertDecodeError
	}

	algLen := binary.BigEndian.Uint16(data)
	idx := 2

	if int(algLen) != length-2 {
		return nil, alertDecodeError
	}

	schemes := make([]SignatureScheme, algLen/2)
	for i := range schemes {
		schemes[i] = SignatureScheme(binary.BigEndian.Uint16(data[idx:]))
		idx += 2
	}
	return schemes, alertSuccess
}

func (m *clientHelloMsg) equal(i interface{}) bool {
	m1, ok := i.(*clientHelloMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.vers == m1.vers &&
		bytes.Equal(m.random, m1.random) &&
		bytes.Equal(m.sessionId, m1.sessionId) &&
		bytes.Equal(m.cookie, m1.cookie) &&
		eqUint16s(m.cipherSuites, m1.cipherSuites) &&
		bytes.Equal(m.compressionMethods, m1.compressionMethods) &&
		m.nextProtoNeg == m1.nextProtoNeg &&
		m.serverName == m1.serverName &&
		m.ocspStapling == m1.ocspStapling &&
		m.sctListSupported == m1.sctListSupported &&
		eqCurveIDs(m.supportedCurves, m1.supportedCurves) &&
		bytes.Equal(m.supportedPoints, m1.supportedPoints) &&
		m.ticketSupported == m1.ticketSupported &&
		bytes.Equal(m.sessionTicket, m1.sessionTicket) &&
		eqSignatureAlgorithms(m.signatureAlgorithms, m1.signatureAlgorithms) &&
		eqSignatureAlgorithms(m.signatureAlgorithmsCert, m1.signatureAlgorithmsCert) &&
		m.secureRenegotiationSupported == m1.secureRenegotiationSupported &&
		bytes.Equal(m.secureRenegotiation, m1.secureRenegotiation) &&
		eqStrings(m.alpnProtocols, m1.alpnProtocols) &&
		eqKeyShares(m.keyShares, m1.keyShares) &&
		m.trailingKeyShareData == m1.trailingKeyShareData &&
		eqPSKIdentityLists(m.pskIdentities, m1.pskIdentities) &&
		bytes.Equal(m.pskKeyExchangeModes, m1.pskKeyExchangeModes) &&
		eqByteSlices(m.pskBinders, m1.pskBinders) &&
		m.pskBinderFirst == m1.pskBinderFirst &&
		eqUint16s(m.supportedVersions, m1.supportedVersions) &&
		m.hasEarlyData == m1.hasEarlyData &&
		m.delegatedCredentials == m1.delegatedCredentials &&
		m.extendedMasterSecret == m1.extendedMasterSecret &&
		bytes.Equal(m.tls13Cookie, m1.tls13Cookie) &&
		bytes.Equal(m.quicTransportParams, m1.quicTransportParams) &&
		m.duplicateExtension == m1.duplicateExtension &&
		m.channelIDSupported == m1.channelIDSupported &&
		bytes.Equal(m.tokenBindingParams, m1.tokenBindingParams) &&
		m.tokenBindingVersion == m1.tokenBindingVersion &&
		m.npnAfterAlpn == m1.npnAfterAlpn &&
		eqUint16s(m.srtpProtectionProfiles, m1.srtpProtectionProfiles) &&
		m.srtpMasterKeyIdentifier == m1.srtpMasterKeyIdentifier &&
		m.customExtension == m1.customExtension &&
		m.pad == m1.pad &&
		m.pqExperimentSignal == m1.pqExperimentSignal
}

func (m *clientHelloMsg) marshalKeyShares(bb *byteBuilder) {
	keyShares := bb.addU16LengthPrefixed()
	for _, keyShare := range m.keyShares {
		keyShares.addU16(uint16(keyShare.group))
		keyExchange := keyShares.addU16LengthPrefixed()
		keyExchange.addBytes(keyShare.keyExchange)
	}
	if m.trailingKeyShareData {
		keyShares.addU8(0)
	}
}

func (m *clientHelloMsg) hasExtensions() bool {
	return len(m.pskIdentities) > 0 || m.duplicateExtension || m.nextProtoNeg ||
		len(m.serverName) > 0 || m.ocspStapling || len(m.supportedCurves) > 0 ||
		len(m.supportedPoints) > 0 || m.ticketSupported || len(m.signatureAlgorithms) > 0 ||
		(len(m.signatureAlgorithmsCert) > 0 && m.getSignatureAlgorithmsCert() != nil) ||
		m.secureRenegotiationSupported || len(m.alpnProtocols) > 0 ||
		m.sctListSupported || len(m.keyShares) > 0 || len(m.supportedVersions) > 0 ||
		m.hasEarlyData || m.delegatedCredentials || m.extendedMasterSecret ||
		len(m.quicTransportParams) > 0 || m.channelIDSupported || m.tokenBindingParams != nil ||
		len(m.srtpProtectionProfiles) > 0 || len(m.customExtension) > 0 || m.pqExperimentSignal ||
		len(m.pskKeyExchangeModes) > 0 || len(m.tls13Cookie) > 0
}

func (m *clientHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	handshakeMsg := newByteBuilder()
	handshakeMsg.addU8(typeClientHello)
	hello := handshakeMsg.addU24LengthPrefixed()
	hello.addU16(m.vers)

	if len(m.random) != 0 {
		hello.addBytes(m.random)
	} else {
		hello.addBytes(make([]byte, 32))
	}

	sessionId := hello.addU8LengthPrefixed()
	sessionId.addBytes(m.sessionId)

	cipherSuites := hello.addU16LengthPrefixed()
	for _, suite := range m.cipherSuites {
		cipherSuites.addU16(suite)
	}
	compressionMethods := hello.addU8LengthPrefixed()
	compressionMethods.addBytes(m.compressionMethods)

	var extensions *byteBuilder
	if m.hasExtensions() {
		extensions = hello.addU16LengthPrefixed()
	}

	if len(m.pskIdentities) > 0 && m.pskBinderFirst {
		extensions.addU16(extensionPreSharedKey)
		pskExtension := extensions.addU16LengthPrefixed()

		pskIdentities := pskExtension.addU16LengthPrefixed()
		for _, pskIdentity := range m.pskIdentities {
			pskIdentities.addU16LengthPrefixed().addBytes(pskIdentity.ticket)
			pskIdentities.addU32(pskIdentity.obfuscatedTicketAge)
		}
		pskBinders := pskExtension.addU16LengthPrefixed()
		for _, binder := range m.pskBinders {
			pskBinders.addU8LengthPrefixed().addBytes(binder)
		}
	}
	if m.duplicateExtension {
		// Add a duplicate bogus extension at the beginning and end.
		extensions.addU16(0xffff)
		extensions.addU16(0) // 0-length for empty extension
	}
	if m.nextProtoNeg && !m.npnAfterAlpn {
		extensions.addU16(extensionNextProtoNeg)
		extensions.addU16(0) // The length is always 0
	}
	if len(m.serverName) > 0 {
		extensions.addU16(extensionServerName)
		serverNameList := extensions.addU16LengthPrefixed()

		// RFC 3546, section 3.1
		//
		// struct {
		//     NameType name_type;
		//     select (name_type) {
		//         case host_name: HostName;
		//     } name;
		// } ServerName;
		//
		// enum {
		//     host_name(0), (255)
		// } NameType;
		//
		// opaque HostName<1..2^16-1>;
		//
		// struct {
		//     ServerName server_name_list<1..2^16-1>
		// } ServerNameList;

		serverName := serverNameList.addU16LengthPrefixed()
		serverName.addU8(0) // NameType host_name(0)
		hostName := serverName.addU16LengthPrefixed()
		hostName.addBytes([]byte(m.serverName))
	}
	if m.ocspStapling {
		extensions.addU16(extensionStatusRequest)
		certificateStatusRequest := extensions.addU16LengthPrefixed()

		// RFC 4366, section 3.6
		certificateStatusRequest.addU8(1) // OCSP type
		// Two zero valued uint16s for the two lengths.
		certificateStatusRequest.addU16(0) // ResponderID length
		certificateStatusRequest.addU16(0) // Extensions length
	}
	if len(m.supportedCurves) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.1.1
		extensions.addU16(extensionSupportedCurves)
		supportedCurvesList := extensions.addU16LengthPrefixed()
		supportedCurves := supportedCurvesList.addU16LengthPrefixed()
		for _, curve := range m.supportedCurves {
			supportedCurves.addU16(uint16(curve))
		}
	}
	if len(m.supportedPoints) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.1.2
		extensions.addU16(extensionSupportedPoints)
		supportedPointsList := extensions.addU16LengthPrefixed()
		supportedPoints := supportedPointsList.addU8LengthPrefixed()
		supportedPoints.addBytes(m.supportedPoints)
	}

	if m.ticketSupported {
		// http://tools.ietf.org/html/rfc5077#section-3.2
		extensions.addU16(extensionSessionTicket)
		sessionTicketExtension := extensions.addU16LengthPrefixed()
		sessionTicketExtension.addBytes(m.sessionTicket)
	}
	if len(m.signatureAlgorithms) > 0 {
		// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
		extensions.addU16(extensionSignatureAlgorithms)
		signatureAlgorithmsExtension := extensions.addU16LengthPrefixed()
		signatureAlgorithms := signatureAlgorithmsExtension.addU16LengthPrefixed()
		for _, sigAlg := range m.signatureAlgorithms {
			signatureAlgorithms.addU16(uint16(sigAlg))
		}
	}

	if len(m.signatureAlgorithmsCert) > 0 && m.getSignatureAlgorithmsCert() != nil {
		extensions.addU16(extensionSignatureAlgorithmsCert)
		signatureAlgorithmsCertExtension := extensions.addU16LengthPrefixed()
		signatureAlgorithmsCert := signatureAlgorithmsCertExtension.addU16LengthPrefixed()
		for _, sigAlg := range m.getSignatureAlgorithmsCert() {
			signatureAlgorithmsCert.addU16(uint16(sigAlg))
		}
	}

	if m.secureRenegotiationSupported {
		extensions.addU16(extensionRenegotiationInfo)
		secureRenegoExt := extensions.addU16LengthPrefixed()
		secureRenego := secureRenegoExt.addU8LengthPrefixed()
		secureRenego.addBytes(m.secureRenegotiation)
	}

	if len(m.alpnProtocols) > 0 {
		// https://tools.ietf.org/html/rfc7301#section-3.1
		extensions.addU16(extensionALPN)
		alpnExtension := extensions.addU16LengthPrefixed()

		protocolNameList := alpnExtension.addU16LengthPrefixed()
		for _, s := range m.alpnProtocols {
			if l := len(s); l == 0 || l > 255 {
				panic("invalid ALPN protocol")
			}
			protocolName := protocolNameList.addU8LengthPrefixed()
			protocolName.addBytes([]byte(s))
		}
	}

	if m.sctListSupported {
		extensions.addU16(extensionSignedCertificateTimestamp)
		extensions.addU16(0) // Length is always 0
	}

	if len(m.keyShares) > 0 {
		extensions.addU16(extensionKeyShare)
		keyShareList := extensions.addU16LengthPrefixed()
		m.marshalKeyShares(keyShareList)
	}

	if len(m.supportedVersions) > 0 {
		extensions.addU16(extensionSupportedVersions)
		supportedVersionsExtension := extensions.addU16LengthPrefixed()
		supportedVersions := supportedVersionsExtension.addU8LengthPrefixed()
		for _, version := range m.supportedVersions {
			supportedVersions.addU16(uint16(version))
		}
	}

	if m.hasEarlyData {
		extensions.addU16(extensionEarlyData)
		extensions.addU16(0) // The length is zero.
	}

	if m.delegatedCredentials {
		// https://tools.ietf.org/html/rfc7627
		extensions.addU16(extensionDelegatedCredentials)
		extensions.addU16(0)
	}

	if m.extendedMasterSecret {
		// https://tools.ietf.org/html/rfc7627
		extensions.addU16(extensionExtendedMasterSecret)
		extensions.addU16(0)
	}

	if len(m.quicTransportParams) > 0 {
		extensions.addU16(extensionQUICTransportParams)
		params := extensions.addU16LengthPrefixed()
		params.addBytes(m.quicTransportParams)
	}

	if m.channelIDSupported {
		extensions.addU16(extensionChannelID)
		extensions.addU16(0) // Length is always 0
	}

	if m.tokenBindingParams != nil {
		extensions.addU16(extensionTokenBinding)
		tokbindExtension := extensions.addU16LengthPrefixed()
		tokbindExtension.addU16(m.tokenBindingVersion)
		tokbindParams := tokbindExtension.addU8LengthPrefixed()
		tokbindParams.addBytes(m.tokenBindingParams)
	}

	if m.nextProtoNeg && m.npnAfterAlpn {
		extensions.addU16(extensionNextProtoNeg)
		extensions.addU16(0) // Length is always 0
	}

	if m.duplicateExtension {
		// Add a duplicate bogus extension at the beginning and end.
		extensions.addU16(0xffff)
		extensions.addU16(0)
	}

	if len(m.srtpProtectionProfiles) > 0 {
		// https://tools.ietf.org/html/rfc5764#section-4.1.1
		extensions.addU16(extensionUseSRTP)
		useSrtpExt := extensions.addU16LengthPrefixed()

		srtpProtectionProfiles := useSrtpExt.addU16LengthPrefixed()
		for _, p := range m.srtpProtectionProfiles {
			srtpProtectionProfiles.addU16(p)
		}
		srtpMki := useSrtpExt.addU8LengthPrefixed()
		srtpMki.addBytes([]byte(m.srtpMasterKeyIdentifier))
	}

	if len(m.customExtension) > 0 {
		extensions.addU16(extensionCustom)
		customExt := extensions.addU16LengthPrefixed()
		customExt.addBytes([]byte(m.customExtension))
	}

	if m.pqExperimentSignal {
		extensions.addU16(extensionPQExperimentSignal)
		extensions.addU16(0) // Length is always 0
	}

	if len(m.pskKeyExchangeModes) > 0 {
		extensions.addU16(extensionPSKKeyExchangeModes)
		pskModesExtension := extensions.addU16LengthPrefixed()
		pskModesExtension.addU8LengthPrefixed().addBytes(m.pskKeyExchangeModes)
	}

	if len(m.tls13Cookie) > 0 {
		extensions.addU16(extensionCookie)
		body := extensions.addU16LengthPrefixed()
		body.addU16LengthPrefixed().addBytes(m.tls13Cookie)
	}

	// The PSK extension must be last. See https://tools.ietf.org/html/rfc8446#section-4.2.11
	if len(m.pskIdentities) > 0 && !m.pskBinderFirst {
		extensions.addU16(extensionPreSharedKey)
		pskExtension := extensions.addU16LengthPrefixed()

		pskIdentities := pskExtension.addU16LengthPrefixed()
		for _, pskIdentity := range m.pskIdentities {
			pskIdentities.addU16LengthPrefixed().addBytes(pskIdentity.ticket)
			pskIdentities.addU32(pskIdentity.obfuscatedTicketAge)
		}
		pskBinders := pskExtension.addU16LengthPrefixed()
		for _, binder := range m.pskBinders {
			pskBinders.addU8LengthPrefixed().addBytes(binder)
		}
	}

	if m.pad != 0 && hello.len()%m.pad != 0 {
		if extensions == nil {
			extensions = hello.addU16LengthPrefixed()
		}
		extensions.addU16(extensionPadding)
		padding := extensions.addU16LengthPrefixed()
		// Note hello.len() has changed at this point from the length
		// prefix.
		if l := hello.len() % m.pad; l != 0 {
			padding.addBytes(make([]byte, m.pad-l))
		}
	}

	m.raw = handshakeMsg.finish()
	// Sanity-check padding.
	if m.pad != 0 && (len(m.raw)-4)%m.pad != 0 {
		panic(fmt.Sprintf("%d is not a multiple of %d", len(m.raw)-4, m.pad))
	}
	return m.raw
}

func (m *clientHelloMsg) unmarshal(data []byte) alert {
	if len(data) < 42 {
		return alertDecodeError
	}
	m.raw = data
	reader := byteReader(data[4:])
	if !reader.readU16(&m.vers) ||
		!reader.readBytes(&m.random, 32) ||
		!reader.readU8LengthPrefixedBytes(&m.sessionId) ||
		len(m.sessionId) > 32 {
		return alertDecodeError
	}

	var cipherSuites byteReader
	if !reader.readU16LengthPrefixed(&cipherSuites) ||
		!reader.readU8LengthPrefixedBytes(&m.compressionMethods) {
		return alertDecodeError
	}

	m.cipherSuites = make([]uint16, 0, len(cipherSuites)/2)
	for len(cipherSuites) > 0 {
		var v uint16
		if !cipherSuites.readU16(&v) {
			return alertDecodeError
		}
		m.cipherSuites = append(m.cipherSuites, v)
		if v == scsvRenegotiation {
			m.secureRenegotiation = []byte{}
			m.secureRenegotiationSupported = true
		}
	}

	m.nextProtoNeg = false
	m.serverName = ""
	m.ocspStapling = false
	m.keyShares = nil
	m.pskIdentities = nil
	m.pskKeyExchangeModes = nil
	m.hasEarlyData = false
	m.ticketSupported = false
	m.sessionTicket = nil
	m.signatureAlgorithms = nil
	m.signatureAlgorithmsCert = nil
	m.supportedVersions = nil
	m.alpnProtocols = nil
	m.sctListSupported = false
	m.extendedMasterSecret = false
	m.customExtension = ""
	m.delegatedCredentials = false
	m.pqExperimentSignal = false

	if len(reader) == 0 {
		// ClientHello is optionally followed by extension data
		return alertSuccess
	}

	var extensions byteReader
	if !reader.readU16LengthPrefixed(&extensions) || len(reader) != 0 || !checkDuplicateExtensions(extensions) {
		return alertDecodeError
	}
	for len(extensions) > 0 {
		var extension uint16
		var body byteReader
		if !extensions.readU16(&extension) ||
			!extensions.readU16LengthPrefixed(&body) {
			return alertDecodeError
		}
		switch extension {
		case extensionServerName:
			var names byteReader
			if !body.readU16LengthPrefixed(&names) || len(body) != 0 {
				return alertDecodeError
			}
			for len(names) > 0 {
				var nameType byte
				var name []byte
				if !names.readU8(&nameType) ||
					!names.readU16LengthPrefixedBytes(&name) {
					return alertDecodeError
				}
				if nameType == 0 {
					m.serverName = string(name)
					// An SNI value may not include a
					// trailing dot. See
					// https://tools.ietf.org/html/rfc6066#section-3.
					if strings.HasSuffix(m.serverName, ".") {
						// TODO use alertDecodeError?
						return alertUnexpectedMessage
					}
				}
			}
		case extensionNextProtoNeg:
			if len(body) != 0 {
				return alertDecodeError
			}
			m.nextProtoNeg = true
		case extensionStatusRequest:
			m.ocspStapling = len(body) > 0 && body[0] == statusTypeOCSP
		case extensionSupportedCurves:
			// http://tools.ietf.org/html/rfc4492#section-5.5.1
			var curves byteReader
			if !body.readU16LengthPrefixed(&curves) || len(body) != 0 {
				return alertDecodeError
			}
			m.supportedCurves = make([]CurveID, 0, len(curves)/2)
			for len(curves) > 0 {
				var v uint16
				if !curves.readU16(&v) {
					return alertDecodeError
				}
				m.supportedCurves = append(m.supportedCurves, CurveID(v))
			}
		case extensionSupportedPoints:
			// http://tools.ietf.org/html/rfc4492#section-5.5.2
			if !body.readU8LengthPrefixedBytes(&m.supportedPoints) || len(body) != 0 {
				return alertDecodeError
			}
		case extensionSessionTicket:
			// http://tools.ietf.org/html/rfc5077#section-3.2
			m.ticketSupported = true
			m.sessionTicket = []byte(body)
		case extensionKeyShare:
			// https://tools.ietf.org/html/rfc8446#section-4.2.8
			var keyShares byteReader
			if !body.readU16LengthPrefixed(&keyShares) || len(body) != 0 {
				return alertDecodeError
			}
			for len(keyShares) > 0 {
				var entry keyShareEntry
				var group uint16
				if !keyShares.readU16(&group) ||
					!keyShares.readU16LengthPrefixedBytes(&entry.keyExchange) {
					return alertDecodeError
				}
				entry.group = CurveID(group)
				m.keyShares = append(m.keyShares, entry)
			}
		case extensionPreSharedKey:
			// https://tools.ietf.org/html/rfc8446#section-4.2.11
			var psks, binders byteReader
			if !body.readU16LengthPrefixed(&psks) ||
				!body.readU16LengthPrefixed(&binders) ||
				len(body) != 0 {
				return alertDecodeError
			}
			for len(psks) > 0 {
				var psk pskIdentity
				if !psks.readU16LengthPrefixedBytes(&psk.ticket) ||
					!psks.readU32(&psk.obfuscatedTicketAge) {
					return alertDecodeError
				}
				m.pskIdentities = append(m.pskIdentities, psk)
			}
			for len(binders) > 0 {
				var binder []byte
				if !binders.readU8LengthPrefixedBytes(&binder) {
					return alertDecodeError
				}
				m.pskBinders = append(m.pskBinders, binder)
			}

			// There must be the same number of identities as binders.
			if len(m.pskIdentities) != len(m.pskBinders) {
				return alertDecodeError
			}
		case extensionPSKKeyExchangeModes:
			// https://tools.ietf.org/html/rfc8446#section-4.2.9
			if !body.readU8LengthPrefixedBytes(&m.pskKeyExchangeModes) || len(body) != 0 {
				return alertDecodeError
			}
		case extensionEarlyData:
			// https://tools.ietf.org/html/rfc8446#section-4.2.10
			if len(body) != 0 {
				return alertDecodeError
			}
			m.hasEarlyData = true
		case extensionCookie:
			if !body.readU16LengthPrefixedBytes(&m.tls13Cookie) || len(body) != 0 {
				return alertDecodeError
			}
		case extensionSignatureAlgorithms:
			// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
			if !parseSignatureAlgorithms(&body, &m.signatureAlgorithms, false) || len(body) != 0 {
				return alertDecodeError
			}
		case extensionSignatureAlgorithmsCert:
			if !parseSignatureAlgorithms(&body, &m.signatureAlgorithmsCert, false) || len(body) != 0 {
				return alertDecodeError
			}
		case extensionSupportedVersions:
			var versions byteReader
			if !body.readU8LengthPrefixed(&versions) || len(body) != 0 {
				return alertDecodeError
			}
			m.supportedVersions = make([]uint16, 0, len(versions)/2)
			for len(versions) > 0 {
				var v uint16
				if !versions.readU16(&v) {
					return alertDecodeError
				}
				m.supportedVersions = append(m.supportedVersions, v)
			}
		case extensionRenegotiationInfo:
			if !body.readU8LengthPrefixedBytes(&m.secureRenegotiation) || len(body) != 0 {
				return alertDecodeError
			}
			m.secureRenegotiationSupported = true
		case extensionALPN:
			var protocols byteReader
			if !body.readU16LengthPrefixed(&protocols) || len(body) != 0 {
				return alertDecodeError
			}
			for len(protocols) > 0 {
				var protocol []byte
				if !protocols.readU8LengthPrefixedBytes(&protocol) {
					return alertDecodeError
				}
				m.alpnProtocols = append(m.alpnProtocols, string(protocol))
			}
		case extensionQUICTransportParams:
			m.quicTransportParams = body
		case extensionChannelID:
			if len(body) != 0 {
				return alertDecodeError
			}
			m.channelIDSupported = true
		case extensionTokenBinding:
			if !body.readU16(&m.tokenBindingVersion) ||
				!body.readU8LengthPrefixedBytes(&m.tokenBindingParams) ||
				len(body) != 0 {
				return alertDecodeError
			}
		case extensionExtendedMasterSecret:
			if len(body) != 0 {
				return alertDecodeError
			}
			m.extendedMasterSecret = true
		case extensionUseSRTP:
			var profiles byteReader
			var mki []byte
			if !body.readU16LengthPrefixed(&profiles) ||
				!body.readU8LengthPrefixedBytes(&mki) ||
				len(body) != 0 {
				return alertDecodeError
			}
			m.srtpProtectionProfiles = make([]uint16, 0, len(profiles)/2)
			for len(profiles) > 0 {
				var v uint16
				if !profiles.readU16(&v) {
					return alertDecodeError
				}
				m.srtpProtectionProfiles = append(m.srtpProtectionProfiles, v)
			}
			m.srtpMasterKeyIdentifier = string(mki)
		case extensionSignedCertificateTimestamp:
			if len(body) != 0 {
				return alertDecodeError
			}
			m.sctListSupported = true
		case extensionCustom:
			m.customExtension = string(body)
		case extensionPadding:
			// Padding bytes must be all zero.
			for _, b := range body {
				if b != 0 {
					return alertDecodeError
				}
			}
		case extensionDelegatedCredentials:
			if len(body) != 0 {
				return alertDecodeError
			}
			m.delegatedCredentials = true
		case extensionPQExperimentSignal:
			if len(body) != 0 {
				return alertDecodeError
			}
			m.pqExperimentSignal = true
		}
	}

	return alertSuccess
}

func (m *clientHelloMsg) getSignatureAlgorithmsCert() []SignatureScheme {
	return signAlgosCertList(m.signatureAlgorithms, m.signatureAlgorithmsCert)
}

type serverHelloMsg struct {
	raw                          []byte
	vers                         uint16
	random                       []byte
	sessionId                    []byte
	cipherSuite                  uint16
	compressionMethod            uint8
	nextProtoNeg                 bool
	nextProtos                   []string
	ocspStapling                 bool
	scts                         [][]byte
	ticketSupported              bool
	secureRenegotiation          []byte
	secureRenegotiationSupported bool
	alpnProtocol                 string

	// TLS 1.3
	keyShare    keyShareEntry
	psk         bool
	pskIdentity uint16

	// RFC7627
	extendedMSSupported bool
}

func (m *serverHelloMsg) equal(i interface{}) bool {
	m1, ok := i.(*serverHelloMsg)
	if !ok {
		return false
	}

	if len(m.scts) != len(m1.scts) {
		return false
	}
	for i, sct := range m.scts {
		if !bytes.Equal(sct, m1.scts[i]) {
			return false
		}
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.vers == m1.vers &&
		bytes.Equal(m.random, m1.random) &&
		bytes.Equal(m.sessionId, m1.sessionId) &&
		m.cipherSuite == m1.cipherSuite &&
		m.compressionMethod == m1.compressionMethod &&
		m.nextProtoNeg == m1.nextProtoNeg &&
		eqStrings(m.nextProtos, m1.nextProtos) &&
		m.ocspStapling == m1.ocspStapling &&
		m.ticketSupported == m1.ticketSupported &&
		m.secureRenegotiationSupported == m1.secureRenegotiationSupported &&
		bytes.Equal(m.secureRenegotiation, m1.secureRenegotiation) &&
		m.alpnProtocol == m1.alpnProtocol &&
		m.keyShare.group == m1.keyShare.group &&
		bytes.Equal(m.keyShare.keyExchange, m1.keyShare.keyExchange) &&
		m.psk == m1.psk &&
		m.pskIdentity == m1.pskIdentity &&
		m.extendedMSSupported == m1.extendedMSSupported
}

func (m *serverHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 38 + len(m.sessionId)
	numExtensions := 0
	extensionsLength := 0

	nextProtoLen := 0
	if m.nextProtoNeg {
		numExtensions++
		for _, v := range m.nextProtos {
			nextProtoLen += len(v)
		}
		nextProtoLen += len(m.nextProtos)
		extensionsLength += nextProtoLen
	}
	if m.ocspStapling {
		numExtensions++
	}
	if m.ticketSupported {
		numExtensions++
	}
	if m.secureRenegotiationSupported {
		extensionsLength += 1 + len(m.secureRenegotiation)
		numExtensions++
	}
	if m.extendedMSSupported {
		numExtensions++
	}
	if alpnLen := len(m.alpnProtocol); alpnLen > 0 {
		if alpnLen >= 256 {
			panic("invalid ALPN protocol")
		}
		extensionsLength += 2 + 1 + alpnLen
		numExtensions++
	}
	sctLen := 0
	if len(m.scts) > 0 {
		for _, sct := range m.scts {
			sctLen += len(sct) + 2
		}
		extensionsLength += 2 + sctLen
		numExtensions++
	}
	if m.keyShare.group != 0 {
		extensionsLength += 4 + len(m.keyShare.keyExchange)
		numExtensions++
	}
	if m.psk {
		extensionsLength += 2
		numExtensions++
	}
	// supported_versions extension
	if m.vers >= VersionTLS13 {
		extensionsLength += 2
		numExtensions++
	}

	if numExtensions > 0 {
		extensionsLength += 4 * numExtensions
		length += 2 + extensionsLength
	}

	x := make([]byte, 4+length)
	x[0] = typeServerHello
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	if m.vers >= VersionTLS13 {
		x[4] = 3
		x[5] = 3
	} else {
		x[4] = uint8(m.vers >> 8)
		x[5] = uint8(m.vers)
	}
	copy(x[6:38], m.random)
	z := x[38:]
	x[38] = uint8(len(m.sessionId))
	copy(x[39:39+len(m.sessionId)], m.sessionId)
	z = x[39+len(m.sessionId):]
	z[0] = uint8(m.cipherSuite >> 8)
	z[1] = uint8(m.cipherSuite)
	z[2] = m.compressionMethod
	z = z[3:]

	if numExtensions > 0 {
		z[0] = byte(extensionsLength >> 8)
		z[1] = byte(extensionsLength)
		z = z[2:]
	}
	if m.vers >= VersionTLS13 {
		z[0] = byte(extensionSupportedVersions >> 8)
		z[1] = byte(extensionSupportedVersions)
		z[3] = 2
		z[4] = uint8(m.vers >> 8)
		z[5] = uint8(m.vers)
		z = z[6:]
	}
	if m.nextProtoNeg {
		z[0] = byte(extensionNextProtoNeg >> 8)
		z[1] = byte(extensionNextProtoNeg & 0xff)
		z[2] = byte(nextProtoLen >> 8)
		z[3] = byte(nextProtoLen)
		z = z[4:]

		for _, v := range m.nextProtos {
			l := len(v)
			if l > 255 {
				l = 255
			}
			z[0] = byte(l)
			copy(z[1:], []byte(v[0:l]))
			z = z[1+l:]
		}
	}
	if m.ocspStapling {
		z[0] = byte(extensionStatusRequest >> 8)
		z[1] = byte(extensionStatusRequest)
		z = z[4:]
	}
	if m.ticketSupported {
		z[0] = byte(extensionSessionTicket >> 8)
		z[1] = byte(extensionSessionTicket)
		z = z[4:]
	}
	if m.secureRenegotiationSupported {
		z[0] = byte(extensionRenegotiationInfo >> 8)
		z[1] = byte(extensionRenegotiationInfo & 0xff)
		z[2] = 0
		z[3] = byte(len(m.secureRenegotiation) + 1)
		z[4] = byte(len(m.secureRenegotiation))
		z = z[5:]
		copy(z, m.secureRenegotiation)
		z = z[len(m.secureRenegotiation):]
	}
	if alpnLen := len(m.alpnProtocol); alpnLen > 0 {
		z[0] = byte(extensionALPN >> 8)
		z[1] = byte(extensionALPN & 0xff)
		l := 2 + 1 + alpnLen
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l -= 2
		z[4] = byte(l >> 8)
		z[5] = byte(l)
		l -= 1
		z[6] = byte(l)
		copy(z[7:], []byte(m.alpnProtocol))
		z = z[7+alpnLen:]
	}
	if sctLen > 0 {
		z[0] = byte(extensionSignedCertificateTimestamp >> 8)
		z[1] = byte(extensionSignedCertificateTimestamp)
		l := sctLen + 2
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z[4] = byte(sctLen >> 8)
		z[5] = byte(sctLen)

		z = z[6:]
		for _, sct := range m.scts {
			z[0] = byte(len(sct) >> 8)
			z[1] = byte(len(sct))
			copy(z[2:], sct)
			z = z[len(sct)+2:]
		}
	}
	if m.keyShare.group != 0 {
		z[0] = uint8(extensionKeyShare >> 8)
		z[1] = uint8(extensionKeyShare)
		l := 4 + len(m.keyShare.keyExchange)
		z[2] = uint8(l >> 8)
		z[3] = uint8(l)
		z[4] = uint8(m.keyShare.group >> 8)
		z[5] = uint8(m.keyShare.group)
		l -= 4
		z[6] = uint8(l >> 8)
		z[7] = uint8(l)
		copy(z[8:], m.keyShare.keyExchange)
		z = z[8+l:]
	}

	if m.psk {
		z[0] = byte(extensionPreSharedKey >> 8)
		z[1] = byte(extensionPreSharedKey)
		z[3] = 2
		z[4] = byte(m.pskIdentity >> 8)
		z[5] = byte(m.pskIdentity)
		z = z[6:]
	}
	if m.extendedMSSupported {
		binary.BigEndian.PutUint16(z, extensionExtendedMasterSecret)
		z = z[4:]
	}

	m.raw = x

	return x
}

func (m *serverHelloMsg) unmarshal(data []byte) alert {
	if len(data) < 42 {
		return alertDecodeError
	}
	m.raw = data
	m.vers = uint16(data[4])<<8 | uint16(data[5])
	m.random = data[6:38]
	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return alertDecodeError
	}
	m.sessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	if len(data) < 3 {
		return alertDecodeError
	}
	m.cipherSuite = uint16(data[0])<<8 | uint16(data[1])
	m.compressionMethod = data[2]
	data = data[3:]

	m.nextProtoNeg = false
	m.nextProtos = nil
	m.ocspStapling = false
	m.scts = nil
	m.ticketSupported = false
	m.alpnProtocol = ""
	m.keyShare.group = 0
	m.keyShare.keyExchange = nil
	m.psk = false
	m.pskIdentity = 0
	m.extendedMSSupported = false

	if len(data) == 0 {
		// ServerHello is optionally followed by extension data
		return alertSuccess
	}
	if len(data) < 2 {
		return alertDecodeError
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) != extensionsLength {
		return alertDecodeError
	}

	svData := findExtension(data, extensionSupportedVersions)
	if svData != nil {
		if len(svData) != 2 {
			return alertDecodeError
		}
		if m.vers != VersionTLS12 {
			return alertDecodeError
		}
		rcvVer := binary.BigEndian.Uint16(svData[0:])
		if rcvVer < VersionTLS13 {
			return alertIllegalParameter
		}
		m.vers = rcvVer
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return alertDecodeError
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return alertDecodeError
		}

		switch extension {
		case extensionNextProtoNeg:
			m.nextProtoNeg = true
			d := data[:length]
			for len(d) > 0 {
				l := int(d[0])
				d = d[1:]
				if l == 0 || l > len(d) {
					return alertDecodeError
				}
				m.nextProtos = append(m.nextProtos, string(d[:l]))
				d = d[l:]
			}
		case extensionStatusRequest:
			if length > 0 {
				return alertDecodeError
			}
			m.ocspStapling = true
		case extensionSessionTicket:
			if length > 0 {
				return alertDecodeError
			}
			m.ticketSupported = true
		case extensionRenegotiationInfo:
			if length == 0 {
				return alertDecodeError
			}
			d := data[:length]
			l := int(d[0])
			d = d[1:]
			if l != len(d) {
				return alertDecodeError
			}

			m.secureRenegotiation = d
			m.secureRenegotiationSupported = true
		case extensionALPN:
			d := data[:length]
			if len(d) < 3 {
				return alertDecodeError
			}
			l := int(d[0])<<8 | int(d[1])
			if l != len(d)-2 {
				return alertDecodeError
			}
			d = d[2:]
			l = int(d[0])
			if l != len(d)-1 {
				return alertDecodeError
			}
			d = d[1:]
			if len(d) == 0 {
				// ALPN protocols must not be empty.
				return alertDecodeError
			}
			m.alpnProtocol = string(d)
		case extensionSignedCertificateTimestamp:
			d := data[:length]

			if len(d) < 2 {
				return alertDecodeError
			}
			l := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != l || l == 0 {
				return alertDecodeError
			}

			m.scts = make([][]byte, 0, 3)
			for len(d) != 0 {
				if len(d) < 2 {
					return alertDecodeError
				}
				sctLen := int(d[0])<<8 | int(d[1])
				d = d[2:]
				if sctLen == 0 || len(d) < sctLen {
					return alertDecodeError
				}
				m.scts = append(m.scts, d[:sctLen])
				d = d[sctLen:]
			}
		case extensionKeyShare:
			d := data[:length]

			if len(d) < 4 {
				return alertDecodeError
			}
			m.keyShare.group = CurveID(d[0])<<8 | CurveID(d[1])
			l := int(d[2])<<8 | int(d[3])
			d = d[4:]
			if len(d) != l {
				return alertDecodeError
			}
			m.keyShare.keyExchange = d[:l]
		case extensionPreSharedKey:
			if length != 2 {
				return alertDecodeError
			}
			m.psk = true
			m.pskIdentity = uint16(data[0])<<8 | uint16(data[1])
		case extensionExtendedMasterSecret:
			m.extendedMSSupported = true
		}
		data = data[length:]
	}

	return alertSuccess
}

type encryptedExtensionsMsg struct {
	raw          []byte
	alpnProtocol string
	earlyData    bool
}

func (m *encryptedExtensionsMsg) equal(i interface{}) bool {
	m1, ok := i.(*encryptedExtensionsMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.alpnProtocol == m1.alpnProtocol &&
		m.earlyData == m1.earlyData
}

func (m *encryptedExtensionsMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 2

	if m.earlyData {
		length += 4
	}
	alpnLen := len(m.alpnProtocol)
	if alpnLen > 0 {
		if alpnLen >= 256 {
			panic("invalid ALPN protocol")
		}
		length += 2 + 2 + 2 + 1 + alpnLen
	}

	x := make([]byte, 4+length)
	x[0] = typeEncryptedExtensions
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	length -= 2
	x[4] = uint8(length >> 8)
	x[5] = uint8(length)

	z := x[6:]
	if alpnLen > 0 {
		z[0] = byte(extensionALPN >> 8)
		z[1] = byte(extensionALPN)
		l := 2 + 1 + alpnLen
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l -= 2
		z[4] = byte(l >> 8)
		z[5] = byte(l)
		l -= 1
		z[6] = byte(l)
		copy(z[7:], []byte(m.alpnProtocol))
		z = z[7+alpnLen:]
	}

	if m.earlyData {
		z[0] = byte(extensionEarlyData >> 8)
		z[1] = byte(extensionEarlyData)
		z = z[4:]
	}

	m.raw = x
	return x
}

func (m *encryptedExtensionsMsg) unmarshal(data []byte) alert {
	if len(data) < 6 {
		return alertDecodeError
	}
	m.raw = data

	m.alpnProtocol = ""
	m.earlyData = false

	extensionsLength := int(data[4])<<8 | int(data[5])
	data = data[6:]
	if len(data) != extensionsLength {
		return alertDecodeError
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return alertDecodeError
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return alertDecodeError
		}

		switch extension {
		case extensionALPN:
			d := data[:length]
			if len(d) < 3 {
				return alertDecodeError
			}
			l := int(d[0])<<8 | int(d[1])
			if l != len(d)-2 {
				return alertDecodeError
			}
			d = d[2:]
			l = int(d[0])
			if l != len(d)-1 {
				return alertDecodeError
			}
			d = d[1:]
			if len(d) == 0 {
				// ALPN protocols must not be empty.
				return alertDecodeError
			}
			m.alpnProtocol = string(d)
		case extensionEarlyData:
			// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.8
			m.earlyData = true
		}

		data = data[length:]
	}

	return alertSuccess
}

type certificateMsg struct {
	raw          []byte
	certificates [][]byte
}

func (m *certificateMsg) equal(i interface{}) bool {
	m1, ok := i.(*certificateMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		eqByteSlices(m.certificates, m1.certificates)
}

func (m *certificateMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	var i int
	for _, slice := range m.certificates {
		i += len(slice)
	}

	length := 3 + 3*len(m.certificates) + i
	x = make([]byte, 4+length)
	x[0] = typeCertificate
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	certificateOctets := length - 3
	x[4] = uint8(certificateOctets >> 16)
	x[5] = uint8(certificateOctets >> 8)
	x[6] = uint8(certificateOctets)

	y := x[7:]
	for _, slice := range m.certificates {
		y[0] = uint8(len(slice) >> 16)
		y[1] = uint8(len(slice) >> 8)
		y[2] = uint8(len(slice))
		copy(y[3:], slice)
		y = y[3+len(slice):]
	}

	m.raw = x
	return
}

func (m *certificateMsg) unmarshal(data []byte) alert {
	if len(data) < 7 {
		return alertDecodeError
	}

	m.raw = data
	certsLen := uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6])
	if uint32(len(data)) != certsLen+7 {
		return alertDecodeError
	}

	numCerts := 0
	d := data[7:]
	for certsLen > 0 {
		if len(d) < 4 {
			return alertDecodeError
		}
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		if uint32(len(d)) < 3+certLen {
			return alertDecodeError
		}
		d = d[3+certLen:]
		certsLen -= 3 + certLen
		numCerts++
	}

	m.certificates = make([][]byte, numCerts)
	d = data[7:]
	for i := 0; i < numCerts; i++ {
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		m.certificates[i] = d[3 : 3+certLen]
		d = d[3+certLen:]
	}

	return alertSuccess
}

type certificateEntry struct {
	data                []byte
	ocspStaple          []byte
	sctList             [][]byte
	delegatedCredential []byte
}

type certificateMsg13 struct {
	raw            []byte
	requestContext []byte
	certificates   []certificateEntry
}

func (m *certificateMsg13) equal(i interface{}) bool {
	m1, ok := i.(*certificateMsg13)
	if !ok {
		return false
	}

	if len(m.certificates) != len(m1.certificates) {
		return false
	}
	for i, _ := range m.certificates {
		ok := bytes.Equal(m.certificates[i].data, m1.certificates[i].data)
		ok = ok && bytes.Equal(m.certificates[i].ocspStaple, m1.certificates[i].ocspStaple)
		ok = ok && eqByteSlices(m.certificates[i].sctList, m1.certificates[i].sctList)
		ok = ok && bytes.Equal(m.certificates[i].delegatedCredential, m1.certificates[i].delegatedCredential)
		if !ok {
			return false
		}
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.requestContext, m1.requestContext)
}

func (m *certificateMsg13) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	var i int
	for _, cert := range m.certificates {
		i += len(cert.data)
		if len(cert.ocspStaple) != 0 {
			i += 8 + len(cert.ocspStaple)
		}
		if len(cert.sctList) != 0 {
			i += 6
			for _, sct := range cert.sctList {
				i += 2 + len(sct)
			}
		}
		if len(cert.delegatedCredential) != 0 {
			i += 4 + len(cert.delegatedCredential)
		}
	}

	length := 3 + 3*len(m.certificates) + i
	length += 2 * len(m.certificates) // extensions
	length += 1 + len(m.requestContext)
	x = make([]byte, 4+length)
	x[0] = typeCertificate
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	z := x[4:]

	z[0] = byte(len(m.requestContext))
	copy(z[1:], m.requestContext)
	z = z[1+len(m.requestContext):]

	certificateOctets := len(z) - 3
	z[0] = uint8(certificateOctets >> 16)
	z[1] = uint8(certificateOctets >> 8)
	z[2] = uint8(certificateOctets)

	z = z[3:]
	for _, cert := range m.certificates {
		z[0] = uint8(len(cert.data) >> 16)
		z[1] = uint8(len(cert.data) >> 8)
		z[2] = uint8(len(cert.data))
		copy(z[3:], cert.data)
		z = z[3+len(cert.data):]

		extLenPos := z[:2]
		z = z[2:]

		extensionLen := 0
		if len(cert.ocspStaple) != 0 {
			stapleLen := 4 + len(cert.ocspStaple)
			z[0] = uint8(extensionStatusRequest >> 8)
			z[1] = uint8(extensionStatusRequest)
			z[2] = uint8(stapleLen >> 8)
			z[3] = uint8(stapleLen)

			stapleLen -= 4
			z[4] = statusTypeOCSP
			z[5] = uint8(stapleLen >> 16)
			z[6] = uint8(stapleLen >> 8)
			z[7] = uint8(stapleLen)
			copy(z[8:], cert.ocspStaple)
			z = z[8+stapleLen:]

			extensionLen += 8 + stapleLen
		}
		if len(cert.sctList) != 0 {
			z[0] = uint8(extensionSignedCertificateTimestamp >> 8)
			z[1] = uint8(extensionSignedCertificateTimestamp)
			sctLenPos := z[2:6]
			z = z[6:]
			extensionLen += 6

			sctLen := 2
			for _, sct := range cert.sctList {
				z[0] = uint8(len(sct) >> 8)
				z[1] = uint8(len(sct))
				copy(z[2:], sct)
				z = z[2+len(sct):]

				extensionLen += 2 + len(sct)
				sctLen += 2 + len(sct)
			}
			sctLenPos[0] = uint8(sctLen >> 8)
			sctLenPos[1] = uint8(sctLen)
			sctLen -= 2
			sctLenPos[2] = uint8(sctLen >> 8)
			sctLenPos[3] = uint8(sctLen)
		}
		if len(cert.delegatedCredential) != 0 {
			binary.BigEndian.PutUint16(z, extensionDelegatedCredentials)
			binary.BigEndian.PutUint16(z[2:], uint16(len(cert.delegatedCredential)))
			z = z[4:]
			copy(z, cert.delegatedCredential)
			z = z[len(cert.delegatedCredential):]
			extensionLen += 4 + len(cert.delegatedCredential)
		}

		extLenPos[0] = uint8(extensionLen >> 8)
		extLenPos[1] = uint8(extensionLen)
	}

	m.raw = x
	return
}

func (m *certificateMsg13) unmarshal(data []byte) alert {
	if len(data) < 5 {
		return alertDecodeError
	}

	m.raw = data

	ctxLen := data[4]
	if len(data) < int(ctxLen)+5+3 {
		return alertDecodeError
	}
	m.requestContext = data[5 : 5+ctxLen]

	d := data[5+ctxLen:]
	certsLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
	if uint32(len(d)) != certsLen+3 {
		return alertDecodeError
	}

	numCerts := 0
	d = d[3:]
	for certsLen > 0 {
		if len(d) < 4 {
			return alertDecodeError
		}
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		if uint32(len(d)) < 3+certLen {
			return alertDecodeError
		}
		d = d[3+certLen:]

		if len(d) < 2 {
			return alertDecodeError
		}
		extLen := uint16(d[0])<<8 | uint16(d[1])
		if uint16(len(d)) < 2+extLen {
			return alertDecodeError
		}
		d = d[2+extLen:]

		certsLen -= 3 + certLen + 2 + uint32(extLen)
		numCerts++
	}

	m.certificates = make([]certificateEntry, numCerts)
	d = data[8+ctxLen:]
	for i := 0; i < numCerts; i++ {
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		m.certificates[i].data = d[3 : 3+certLen]
		d = d[3+certLen:]

		extLen := uint16(d[0])<<8 | uint16(d[1])
		d = d[2:]
		for extLen > 0 {
			if extLen < 4 {
				return alertDecodeError
			}
			typ := uint16(d[0])<<8 | uint16(d[1])
			bodyLen := uint16(d[2])<<8 | uint16(d[3])
			if extLen < 4+bodyLen {
				return alertDecodeError
			}
			body := d[4 : 4+bodyLen]
			d = d[4+bodyLen:]
			extLen -= 4 + bodyLen

			switch typ {
			case extensionStatusRequest:
				if len(body) < 4 || body[0] != 0x01 {
					return alertDecodeError
				}
				ocspLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
				if len(body) != 4+ocspLen {
					return alertDecodeError
				}
				m.certificates[i].ocspStaple = body[4:]

			case extensionSignedCertificateTimestamp:
				if len(body) < 2 {
					return alertDecodeError
				}
				listLen := int(body[0])<<8 | int(body[1])
				body = body[2:]
				if len(body) != listLen {
					return alertDecodeError
				}
				for len(body) > 0 {
					if len(body) < 2 {
						return alertDecodeError
					}
					sctLen := int(body[0])<<8 | int(body[1])
					if len(body) < 2+sctLen {
						return alertDecodeError
					}
					m.certificates[i].sctList = append(m.certificates[i].sctList, body[2:2+sctLen])
					body = body[2+sctLen:]
				}
			case extensionDelegatedCredentials:
				m.certificates[i].delegatedCredential = body
			}
		}
	}

	return alertSuccess
}

type serverKeyExchangeMsg struct {
	raw []byte
	key []byte
}

func (m *serverKeyExchangeMsg) equal(i interface{}) bool {
	m1, ok := i.(*serverKeyExchangeMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.key, m1.key)
}

func (m *serverKeyExchangeMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	length := len(m.key)
	x := make([]byte, length+4)
	x[0] = typeServerKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.key)

	m.raw = x
	return x
}

func (m *serverKeyExchangeMsg) unmarshal(data []byte) alert {
	m.raw = data
	if len(data) < 4 {
		return alertDecodeError
	}
	m.key = data[4:]
	return alertSuccess
}

type certificateStatusMsg struct {
	raw        []byte
	statusType uint8
	response   []byte
}

func (m *certificateStatusMsg) equal(i interface{}) bool {
	m1, ok := i.(*certificateStatusMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.statusType == m1.statusType &&
		bytes.Equal(m.response, m1.response)
}

func (m *certificateStatusMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var x []byte
	if m.statusType == statusTypeOCSP {
		x = make([]byte, 4+4+len(m.response))
		x[0] = typeCertificateStatus
		l := len(m.response) + 4
		x[1] = byte(l >> 16)
		x[2] = byte(l >> 8)
		x[3] = byte(l)
		x[4] = statusTypeOCSP

		l -= 4
		x[5] = byte(l >> 16)
		x[6] = byte(l >> 8)
		x[7] = byte(l)
		copy(x[8:], m.response)
	} else {
		x = []byte{typeCertificateStatus, 0, 0, 1, m.statusType}
	}

	m.raw = x
	return x
}

func (m *certificateStatusMsg) unmarshal(data []byte) alert {
	m.raw = data
	if len(data) < 5 {
		return alertDecodeError
	}
	m.statusType = data[4]

	m.response = nil
	if m.statusType == statusTypeOCSP {
		if len(data) < 8 {
			return alertDecodeError
		}
		respLen := uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])
		if uint32(len(data)) != 4+4+respLen {
			return alertDecodeError
		}
		m.response = data[8:]
	}
	return alertSuccess
}

type serverHelloDoneMsg struct{}

func (m *serverHelloDoneMsg) equal(i interface{}) bool {
	_, ok := i.(*serverHelloDoneMsg)
	return ok
}

func (m *serverHelloDoneMsg) marshal() []byte {
	x := make([]byte, 4)
	x[0] = typeServerHelloDone
	return x
}

func (m *serverHelloDoneMsg) unmarshal(data []byte) alert {
	if len(data) != 4 {
		return alertDecodeError
	}
	return alertSuccess
}

type clientKeyExchangeMsg struct {
	raw        []byte
	ciphertext []byte
}

func (m *clientKeyExchangeMsg) equal(i interface{}) bool {
	m1, ok := i.(*clientKeyExchangeMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.ciphertext, m1.ciphertext)
}

func (m *clientKeyExchangeMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	length := len(m.ciphertext)
	x := make([]byte, length+4)
	x[0] = typeClientKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.ciphertext)

	m.raw = x
	return x
}

func (m *clientKeyExchangeMsg) unmarshal(data []byte) alert {
	m.raw = data
	if len(data) < 4 {
		return alertDecodeError
	}
	l := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if l != len(data)-4 {
		return alertDecodeError
	}
	m.ciphertext = data[4:]
	return alertSuccess
}

type finishedMsg struct {
	raw        []byte
	verifyData []byte
}

func (m *finishedMsg) equal(i interface{}) bool {
	m1, ok := i.(*finishedMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.verifyData, m1.verifyData)
}

func (m *finishedMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	x = make([]byte, 4+len(m.verifyData))
	x[0] = typeFinished
	x[3] = byte(len(m.verifyData))
	copy(x[4:], m.verifyData)
	m.raw = x
	return
}

func (m *finishedMsg) unmarshal(data []byte) alert {
	m.raw = data
	if len(data) < 4 {
		return alertDecodeError
	}
	m.verifyData = data[4:]
	return alertSuccess
}

type nextProtoMsg struct {
	raw   []byte
	proto string
}

func (m *nextProtoMsg) equal(i interface{}) bool {
	m1, ok := i.(*nextProtoMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.proto == m1.proto
}

func (m *nextProtoMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	l := len(m.proto)
	if l > 255 {
		l = 255
	}

	padding := 32 - (l+2)%32
	length := l + padding + 2
	x := make([]byte, length+4)
	x[0] = typeNextProtocol
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	y := x[4:]
	y[0] = byte(l)
	copy(y[1:], []byte(m.proto[0:l]))
	y = y[1+l:]
	y[0] = byte(padding)

	m.raw = x

	return x
}

func (m *nextProtoMsg) unmarshal(data []byte) alert {
	m.raw = data

	if len(data) < 5 {
		return alertDecodeError
	}
	data = data[4:]
	protoLen := int(data[0])
	data = data[1:]
	if len(data) < protoLen {
		return alertDecodeError
	}
	m.proto = string(data[0:protoLen])
	data = data[protoLen:]

	if len(data) < 1 {
		return alertDecodeError
	}
	paddingLen := int(data[0])
	data = data[1:]
	if len(data) != paddingLen {
		return alertDecodeError
	}

	return alertSuccess
}

type certificateRequestMsg struct {
	raw []byte
	// hasSignatureAndHash indicates whether this message includes a list
	// of signature and hash functions. This change was introduced with TLS
	// 1.2.
	hasSignatureAndHash bool

	certificateTypes             []byte
	supportedSignatureAlgorithms []SignatureScheme
	certificateAuthorities       [][]byte
}

func (m *certificateRequestMsg) equal(i interface{}) bool {
	m1, ok := i.(*certificateRequestMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.certificateTypes, m1.certificateTypes) &&
		eqByteSlices(m.certificateAuthorities, m1.certificateAuthorities) &&
		eqSignatureAlgorithms(m.supportedSignatureAlgorithms, m1.supportedSignatureAlgorithms)
}

func (m *certificateRequestMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See http://tools.ietf.org/html/rfc4346#section-7.4.4
	length := 1 + len(m.certificateTypes) + 2
	casLength := 0
	for _, ca := range m.certificateAuthorities {
		casLength += 2 + len(ca)
	}
	length += casLength

	if m.hasSignatureAndHash {
		length += 2 + 2*len(m.supportedSignatureAlgorithms)
	}

	x = make([]byte, 4+length)
	x[0] = typeCertificateRequest
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	x[4] = uint8(len(m.certificateTypes))

	copy(x[5:], m.certificateTypes)
	y := x[5+len(m.certificateTypes):]

	if m.hasSignatureAndHash {
		n := len(m.supportedSignatureAlgorithms) * 2
		y[0] = uint8(n >> 8)
		y[1] = uint8(n)
		y = y[2:]
		for _, sigAlgo := range m.supportedSignatureAlgorithms {
			y[0] = uint8(sigAlgo >> 8)
			y[1] = uint8(sigAlgo)
			y = y[2:]
		}
	}

	y[0] = uint8(casLength >> 8)
	y[1] = uint8(casLength)
	y = y[2:]
	for _, ca := range m.certificateAuthorities {
		y[0] = uint8(len(ca) >> 8)
		y[1] = uint8(len(ca))
		y = y[2:]
		copy(y, ca)
		y = y[len(ca):]
	}

	m.raw = x
	return
}

func (m *certificateRequestMsg) unmarshal(data []byte) alert {
	m.raw = data

	if len(data) < 5 {
		return alertDecodeError
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return alertDecodeError
	}

	numCertTypes := int(data[4])
	data = data[5:]
	if numCertTypes == 0 || len(data) <= numCertTypes {
		return alertDecodeError
	}

	m.certificateTypes = make([]byte, numCertTypes)
	if copy(m.certificateTypes, data) != numCertTypes {
		return alertDecodeError
	}

	data = data[numCertTypes:]

	if m.hasSignatureAndHash {
		if len(data) < 2 {
			return alertDecodeError
		}
		sigAndHashLen := uint16(data[0])<<8 | uint16(data[1])
		data = data[2:]
		if sigAndHashLen&1 != 0 {
			return alertDecodeError
		}
		if len(data) < int(sigAndHashLen) {
			return alertDecodeError
		}
		numSigAlgos := sigAndHashLen / 2
		m.supportedSignatureAlgorithms = make([]SignatureScheme, numSigAlgos)
		for i := range m.supportedSignatureAlgorithms {
			m.supportedSignatureAlgorithms[i] = SignatureScheme(data[0])<<8 | SignatureScheme(data[1])
			data = data[2:]
		}
	}

	if len(data) < 2 {
		return alertDecodeError
	}
	casLength := uint16(data[0])<<8 | uint16(data[1])
	data = data[2:]
	if len(data) < int(casLength) {
		return alertDecodeError
	}
	cas := make([]byte, casLength)
	copy(cas, data)
	data = data[casLength:]

	m.certificateAuthorities = nil
	for len(cas) > 0 {
		if len(cas) < 2 {
			return alertDecodeError
		}
		caLen := uint16(cas[0])<<8 | uint16(cas[1])
		cas = cas[2:]

		if len(cas) < int(caLen) {
			return alertDecodeError
		}

		m.certificateAuthorities = append(m.certificateAuthorities, cas[:caLen])
		cas = cas[caLen:]
	}

	if len(data) != 0 {
		return alertDecodeError
	}

	return alertSuccess
}

type certificateRequestMsg13 struct {
	raw []byte

	requestContext                   []byte
	supportedSignatureAlgorithms     []SignatureScheme
	supportedSignatureAlgorithmsCert []SignatureScheme
	certificateAuthorities           [][]byte
}

func (m *certificateRequestMsg13) equal(i interface{}) bool {
	m1, ok := i.(*certificateRequestMsg13)
	return ok &&
		bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.requestContext, m1.requestContext) &&
		eqByteSlices(m.certificateAuthorities, m1.certificateAuthorities) &&
		eqSignatureAlgorithms(m.supportedSignatureAlgorithms, m1.supportedSignatureAlgorithms) &&
		eqSignatureAlgorithms(m.supportedSignatureAlgorithmsCert, m1.supportedSignatureAlgorithmsCert)
}

func (m *certificateRequestMsg13) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See https://tools.ietf.org/html/draft-ietf-tls-tls13-21#section-4.3.2
	length := 1 + len(m.requestContext)
	numExtensions := 1
	extensionsLength := 2 + 2*len(m.supportedSignatureAlgorithms)

	if m.getSignatureAlgorithmsCert() != nil {
		numExtensions += 1
		extensionsLength += 2 + 2*len(m.getSignatureAlgorithmsCert())
	}

	casLength := 0
	if len(m.certificateAuthorities) > 0 {
		for _, ca := range m.certificateAuthorities {
			casLength += 2 + len(ca)
		}
		extensionsLength += 2 + casLength
		numExtensions++
	}

	extensionsLength += 4 * numExtensions
	length += 2 + extensionsLength

	x = make([]byte, 4+length)
	x[0] = typeCertificateRequest
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	x[4] = uint8(len(m.requestContext))
	copy(x[5:], m.requestContext)
	z := x[5+len(m.requestContext):]

	z[0] = byte(extensionsLength >> 8)
	z[1] = byte(extensionsLength)
	z = z[2:]

	// TODO: this function should be reused by CH
	z = marshalExtensionSignatureAlgorithms(extensionSignatureAlgorithms, z, m.supportedSignatureAlgorithms)

	if m.getSignatureAlgorithmsCert() != nil {
		z = marshalExtensionSignatureAlgorithms(extensionSignatureAlgorithmsCert, z, m.getSignatureAlgorithmsCert())
	}
	// certificate_authorities
	if casLength > 0 {
		z[0] = byte(extensionCertificateAuthorities >> 8)
		z[1] = byte(extensionCertificateAuthorities)
		l := 2 + casLength
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		z[0] = uint8(casLength >> 8)
		z[1] = uint8(casLength)
		z = z[2:]
		for _, ca := range m.certificateAuthorities {
			z[0] = uint8(len(ca) >> 8)
			z[1] = uint8(len(ca))
			z = z[2:]
			copy(z, ca)
			z = z[len(ca):]
		}
	}

	m.raw = x
	return
}

func (m *certificateRequestMsg13) unmarshal(data []byte) alert {
	m.raw = data
	m.supportedSignatureAlgorithms = nil
	m.certificateAuthorities = nil

	if len(data) < 5 {
		return alertDecodeError
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return alertDecodeError
	}

	ctxLen := data[4]
	if len(data) < 5+int(ctxLen)+2 {
		return alertDecodeError
	}
	m.requestContext = data[5 : 5+ctxLen]
	data = data[5+ctxLen:]

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) != extensionsLength {
		return alertDecodeError
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return alertDecodeError
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return alertDecodeError
		}

		switch extension {
		case extensionSignatureAlgorithms:
			// TODO: unmarshalExtensionSignatureAlgorithms should be shared with CH and pre-1.3 CV
			// https://tools.ietf.org/html/draft-ietf-tls-tls13-21#section-4.2.3
			var err alert
			m.supportedSignatureAlgorithms, err = unmarshalExtensionSignatureAlgorithms(data, length)
			if err != alertSuccess {
				return err
			}
		case extensionSignatureAlgorithmsCert:
			var err alert
			m.supportedSignatureAlgorithmsCert, err = unmarshalExtensionSignatureAlgorithms(data, length)
			if err != alertSuccess {
				return err
			}
		case extensionCertificateAuthorities:
			// TODO DRY: share code with CH
			if length < 2 {
				return alertDecodeError
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 || l < 3 {
				return alertDecodeError
			}
			cas := make([]byte, l)
			copy(cas, data[2:])
			m.certificateAuthorities = nil
			for len(cas) > 0 {
				if len(cas) < 2 {
					return alertDecodeError
				}
				caLen := uint16(cas[0])<<8 | uint16(cas[1])
				cas = cas[2:]

				if len(cas) < int(caLen) {
					return alertDecodeError
				}

				m.certificateAuthorities = append(m.certificateAuthorities, cas[:caLen])
				cas = cas[caLen:]
			}
		}
		data = data[length:]
	}

	if len(m.supportedSignatureAlgorithms) == 0 {
		return alertDecodeError
	}
	return alertSuccess
}

func (m *certificateRequestMsg13) getSignatureAlgorithmsCert() []SignatureScheme {
	return signAlgosCertList(m.supportedSignatureAlgorithms, m.supportedSignatureAlgorithmsCert)
}

type certificateVerifyMsg struct {
	raw                 []byte
	hasSignatureAndHash bool
	signatureAlgorithm  SignatureScheme
	signature           []byte
}

func (m *certificateVerifyMsg) equal(i interface{}) bool {
	m1, ok := i.(*certificateVerifyMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.hasSignatureAndHash == m1.hasSignatureAndHash &&
		m.signatureAlgorithm == m1.signatureAlgorithm &&
		bytes.Equal(m.signature, m1.signature)
}

func (m *certificateVerifyMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See http://tools.ietf.org/html/rfc4346#section-7.4.8
	siglength := len(m.signature)
	length := 2 + siglength
	if m.hasSignatureAndHash {
		length += 2
	}
	x = make([]byte, 4+length)
	x[0] = typeCertificateVerify
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	y := x[4:]
	if m.hasSignatureAndHash {
		y[0] = uint8(m.signatureAlgorithm >> 8)
		y[1] = uint8(m.signatureAlgorithm)
		y = y[2:]
	}
	y[0] = uint8(siglength >> 8)
	y[1] = uint8(siglength)
	copy(y[2:], m.signature)

	m.raw = x

	return
}

func (m *certificateVerifyMsg) unmarshal(data []byte) alert {
	m.raw = data

	if len(data) < 6 {
		return alertDecodeError
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return alertDecodeError
	}

	data = data[4:]
	if m.hasSignatureAndHash {
		m.signatureAlgorithm = SignatureScheme(data[0])<<8 | SignatureScheme(data[1])
		data = data[2:]
	}

	if len(data) < 2 {
		return alertDecodeError
	}
	siglength := int(data[0])<<8 + int(data[1])
	data = data[2:]
	if len(data) != siglength {
		return alertDecodeError
	}

	m.signature = data

	return alertSuccess
}

type newSessionTicketMsg struct {
	raw    []byte
	ticket []byte
}

func (m *newSessionTicketMsg) equal(i interface{}) bool {
	m1, ok := i.(*newSessionTicketMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.ticket, m1.ticket)
}

func (m *newSessionTicketMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See http://tools.ietf.org/html/rfc5077#section-3.3
	ticketLen := len(m.ticket)
	length := 2 + 4 + ticketLen
	x = make([]byte, 4+length)
	x[0] = typeNewSessionTicket
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[8] = uint8(ticketLen >> 8)
	x[9] = uint8(ticketLen)
	copy(x[10:], m.ticket)

	m.raw = x

	return
}

func (m *newSessionTicketMsg) unmarshal(data []byte) alert {
	m.raw = data

	if len(data) < 10 {
		return alertDecodeError
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return alertDecodeError
	}

	ticketLen := int(data[8])<<8 + int(data[9])
	if len(data)-10 != ticketLen {
		return alertDecodeError
	}

	m.ticket = data[10:]

	return alertSuccess
}

type newSessionTicketMsg13 struct {
	raw                []byte
	lifetime           uint32
	ageAdd             uint32
	nonce              []byte
	ticket             []byte
	withEarlyDataInfo  bool
	maxEarlyDataLength uint32
}

func (m *newSessionTicketMsg13) equal(i interface{}) bool {
	m1, ok := i.(*newSessionTicketMsg13)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.lifetime == m1.lifetime &&
		m.ageAdd == m1.ageAdd &&
		bytes.Equal(m.nonce, m1.nonce) &&
		bytes.Equal(m.ticket, m1.ticket) &&
		m.withEarlyDataInfo == m1.withEarlyDataInfo &&
		m.maxEarlyDataLength == m1.maxEarlyDataLength
}

func (m *newSessionTicketMsg13) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See https://tools.ietf.org/html/draft-ietf-tls-tls13-21#section-4.6.1
	nonceLen := len(m.nonce)
	ticketLen := len(m.ticket)
	length := 13 + nonceLen + ticketLen
	if m.withEarlyDataInfo {
		length += 8
	}
	x = make([]byte, 4+length)
	x[0] = typeNewSessionTicket
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	x[4] = uint8(m.lifetime >> 24)
	x[5] = uint8(m.lifetime >> 16)
	x[6] = uint8(m.lifetime >> 8)
	x[7] = uint8(m.lifetime)
	x[8] = uint8(m.ageAdd >> 24)
	x[9] = uint8(m.ageAdd >> 16)
	x[10] = uint8(m.ageAdd >> 8)
	x[11] = uint8(m.ageAdd)

	x[12] = uint8(nonceLen)
	copy(x[13:13+nonceLen], m.nonce)

	y := x[13+nonceLen:]
	y[0] = uint8(ticketLen >> 8)
	y[1] = uint8(ticketLen)
	copy(y[2:2+ticketLen], m.ticket)

	if m.withEarlyDataInfo {
		z := y[2+ticketLen:]
		// z[0] is already 0, this is the extensions vector length.
		z[1] = 8
		z[2] = uint8(extensionEarlyData >> 8)
		z[3] = uint8(extensionEarlyData)
		z[5] = 4
		z[6] = uint8(m.maxEarlyDataLength >> 24)
		z[7] = uint8(m.maxEarlyDataLength >> 16)
		z[8] = uint8(m.maxEarlyDataLength >> 8)
		z[9] = uint8(m.maxEarlyDataLength)
	}

	m.raw = x

	return
}

func (m *newSessionTicketMsg13) unmarshal(data []byte) alert {
	m.raw = data
	m.maxEarlyDataLength = 0
	m.withEarlyDataInfo = false

	if len(data) < 17 {
		return alertDecodeError
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return alertDecodeError
	}

	m.lifetime = uint32(data[4])<<24 | uint32(data[5])<<16 |
		uint32(data[6])<<8 | uint32(data[7])
	m.ageAdd = uint32(data[8])<<24 | uint32(data[9])<<16 |
		uint32(data[10])<<8 | uint32(data[11])

	nonceLen := int(data[12])
	if nonceLen == 0 || 13+nonceLen+2 > len(data) {
		return alertDecodeError
	}
	m.nonce = data[13 : 13+nonceLen]

	data = data[13+nonceLen:]
	ticketLen := int(data[0])<<8 + int(data[1])
	if ticketLen == 0 || 2+ticketLen+2 > len(data) {
		return alertDecodeError
	}
	m.ticket = data[2 : 2+ticketLen]

	data = data[2+ticketLen:]
	extLen := int(data[0])<<8 + int(data[1])
	if extLen != len(data)-2 {
		return alertDecodeError
	}

	data = data[2:]
	for len(data) > 0 {
		if len(data) < 4 {
			return alertDecodeError
		}
		extType := uint16(data[0])<<8 + uint16(data[1])
		length := int(data[2])<<8 + int(data[3])
		data = data[4:]

		switch extType {
		case extensionEarlyData:
			if length != 4 {
				return alertDecodeError
			}
			m.withEarlyDataInfo = true
			m.maxEarlyDataLength = uint32(data[0])<<24 | uint32(data[1])<<16 |
				uint32(data[2])<<8 | uint32(data[3])
		}
		data = data[length:]
	}

	return alertSuccess
}

type endOfEarlyDataMsg struct {
}

func (*endOfEarlyDataMsg) marshal() []byte {
	return []byte{typeEndOfEarlyData, 0, 0, 0}
}

func (*endOfEarlyDataMsg) unmarshal(data []byte) alert {
	if len(data) != 4 {
		return alertDecodeError
	}
	return alertSuccess
}

type helloRequestMsg struct {
}

func (*helloRequestMsg) marshal() []byte {
	return []byte{typeHelloRequest, 0, 0, 0}
}

func (*helloRequestMsg) unmarshal(data []byte) alert {
	if len(data) != 4 {
		return alertDecodeError
	}
	return alertSuccess
}

func eqUint16s(x, y []uint16) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if y[i] != v {
			return false
		}
	}
	return true
}

func eqCurveIDs(x, y []CurveID) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if y[i] != v {
			return false
		}
	}
	return true
}

func eqStrings(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if y[i] != v {
			return false
		}
	}
	return true
}

func eqByteSlices(x, y [][]byte) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if !bytes.Equal(v, y[i]) {
			return false
		}
	}
	return true
}

func eqSignatureAlgorithms(x, y []SignatureScheme) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if v != y[i] {
			return false
		}
	}
	return true
}

func eqKeyShares(x, y []keyShareEntry) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i].group != y[i].group {
			return false
		}
		if !bytes.Equal(x[i].keyExchange, y[i].keyExchange) {
			return false
		}
	}
	return true
}

func findExtension(data []byte, extensionType uint16) []byte {
	for len(data) != 0 {
		if len(data) < 4 {
			return nil
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return nil
		}
		if extension == extensionType {
			return data[:length]
		}
		data = data[length:]
	}
	return nil
}

func eqPSKIdentityLists(x, y []pskIdentity) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if !bytes.Equal(y[i].ticket, v.ticket) || !bytes.Equal(y[i].identity, v.identity) || !bytes.Equal(y[i].binder, v.binder) || y[i].obfuscatedTicketAge != v.obfuscatedTicketAge {
			return false
		}
	}
	return true

}

func checkDuplicateExtensions(extensions byteReader) bool {
	seen := make(map[uint16]struct{})
	for len(extensions) > 0 {
		var extension uint16
		var body byteReader
		if !extensions.readU16(&extension) ||
			!extensions.readU16LengthPrefixed(&body) {
			return false
		}
		if _, ok := seen[extension]; ok {
			return false
		}
		seen[extension] = struct{}{}
	}
	return true
}

func parseSignatureAlgorithms(reader *byteReader, out *[]SignatureScheme, allowEmpty bool) bool {
	var sigAlgs byteReader
	if !reader.readU16LengthPrefixed(&sigAlgs) {
		return false
	}
	if !allowEmpty && len(sigAlgs) == 0 {
		return false
	}
	*out = make([]SignatureScheme, 0, len(sigAlgs)/2)
	for len(sigAlgs) > 0 {
		var v uint16
		if !sigAlgs.readU16(&v) {
			return false
		}
		*out = append(*out, SignatureScheme(v))
	}
	return true
}
