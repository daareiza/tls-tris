// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"encoding/binary"
	"strings"
)

func (m *clientHelloMsg) marshalOld() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 2 + 32 + 1 + len(m.sessionId) + 2 + len(m.cipherSuites)*2 + 1 + len(m.compressionMethods)
	numExtensions := 0
	extensionsLength := 0

	if m.nextProtoNeg {
		numExtensions++
	}
	if m.ocspStapling {
		extensionsLength += 1 + 2 + 2
		numExtensions++
	}
	if len(m.serverName) > 0 {
		extensionsLength += 5 + len(m.serverName)
		numExtensions++
	}
	if len(m.supportedCurves) > 0 {
		extensionsLength += 2 + 2*len(m.supportedCurves)
		numExtensions++
	}
	if len(m.supportedPoints) > 0 {
		extensionsLength += 1 + len(m.supportedPoints)
		numExtensions++
	}
	if m.ticketSupported {
		extensionsLength += len(m.sessionTicket)
		numExtensions++
	}
	if len(m.signatureAlgorithms) > 0 {
		extensionsLength += 2 + 2*len(m.signatureAlgorithms)
		numExtensions++
	}
	if m.getSignatureAlgorithmsCert() != nil {
		extensionsLength += 2 + 2*len(m.getSignatureAlgorithmsCert())
		numExtensions++
	}
	if m.secureRenegotiationSupported {
		extensionsLength += 1 + len(m.secureRenegotiation)
		numExtensions++
	}
	if len(m.alpnProtocols) > 0 {
		extensionsLength += 2
		for _, s := range m.alpnProtocols {
			if l := len(s); l == 0 || l > 255 {
				panic("invalid ALPN protocol")
			}
			extensionsLength++
			extensionsLength += len(s)
		}
		numExtensions++
	}
	if m.sctListSupported {
		numExtensions++
	}
	if len(m.keyShares) > 0 {
		extensionsLength += 2
		for _, k := range m.keyShares {
			extensionsLength += 4 + len(k.keyExchange)
		}
		numExtensions++
	}
	if len(m.supportedVersions) > 0 {
		extensionsLength += 1 + 2*len(m.supportedVersions)
		numExtensions++
	}
	if m.hasEarlyData {
		numExtensions++
	}
	if m.delegatedCredentials {
		numExtensions++
	}
	if m.extendedMasterSecret {
		numExtensions++
	}
	if numExtensions > 0 {
		extensionsLength += 4 * numExtensions
		length += 2 + extensionsLength
	}

	x := make([]byte, 4+length)
	x[0] = typeClientHello
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.vers >> 8)
	x[5] = uint8(m.vers)
	copy(x[6:38], m.random)
	x[38] = uint8(len(m.sessionId))
	copy(x[39:39+len(m.sessionId)], m.sessionId)
	y := x[39+len(m.sessionId):]
	y[0] = uint8(len(m.cipherSuites) >> 7)
	y[1] = uint8(len(m.cipherSuites) << 1)
	for i, suite := range m.cipherSuites {
		y[2+i*2] = uint8(suite >> 8)
		y[3+i*2] = uint8(suite)
	}
	z := y[2+len(m.cipherSuites)*2:]
	z[0] = uint8(len(m.compressionMethods))
	copy(z[1:], m.compressionMethods)

	z = z[1+len(m.compressionMethods):]
	if numExtensions > 0 {
		z[0] = byte(extensionsLength >> 8)
		z[1] = byte(extensionsLength)
		z = z[2:]
	}
	if m.nextProtoNeg {
		z[0] = byte(extensionNextProtoNeg >> 8)
		z[1] = byte(extensionNextProtoNeg & 0xff)
		// The length is always 0
		z = z[4:]
	}
	if len(m.serverName) > 0 {
		z[0] = byte(extensionServerName >> 8)
		z[1] = byte(extensionServerName & 0xff)
		l := len(m.serverName) + 5
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

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

		z[0] = byte((len(m.serverName) + 3) >> 8)
		z[1] = byte(len(m.serverName) + 3)
		z[3] = byte(len(m.serverName) >> 8)
		z[4] = byte(len(m.serverName))
		copy(z[5:], []byte(m.serverName))
		z = z[l:]
	}
	if m.ocspStapling {
		// RFC 4366, section 3.6
		z[0] = byte(extensionStatusRequest >> 8)
		z[1] = byte(extensionStatusRequest)
		z[2] = 0
		z[3] = 5
		z[4] = 1 // OCSP type
		// Two zero valued uint16s for the two lengths.
		z = z[9:]
	}
	if len(m.supportedCurves) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.5.1
		// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.4
		z[0] = byte(extensionSupportedCurves >> 8)
		z[1] = byte(extensionSupportedCurves)
		l := 2 + 2*len(m.supportedCurves)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l -= 2
		z[4] = byte(l >> 8)
		z[5] = byte(l)
		z = z[6:]
		for _, curve := range m.supportedCurves {
			z[0] = byte(curve >> 8)
			z[1] = byte(curve)
			z = z[2:]
		}
	}
	if len(m.supportedPoints) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.5.2
		z[0] = byte(extensionSupportedPoints >> 8)
		z[1] = byte(extensionSupportedPoints)
		l := 1 + len(m.supportedPoints)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l--
		z[4] = byte(l)
		z = z[5:]
		for _, pointFormat := range m.supportedPoints {
			z[0] = pointFormat
			z = z[1:]
		}
	}
	if m.ticketSupported {
		// http://tools.ietf.org/html/rfc5077#section-3.2
		z[0] = byte(extensionSessionTicket >> 8)
		z[1] = byte(extensionSessionTicket)
		l := len(m.sessionTicket)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]
		copy(z, m.sessionTicket)
		z = z[len(m.sessionTicket):]
	}

	if len(m.signatureAlgorithms) > 0 {
		z = marshalExtensionSignatureAlgorithms(extensionSignatureAlgorithms, z, m.signatureAlgorithms)
	}
	if m.getSignatureAlgorithmsCert() != nil {
		// Ensure only one list of algorithms is sent if supported_algorithms and supported_algorithms_cert are the same
		z = marshalExtensionSignatureAlgorithms(extensionSignatureAlgorithmsCert, z, m.getSignatureAlgorithmsCert())
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
	if len(m.alpnProtocols) > 0 {
		z[0] = byte(extensionALPN >> 8)
		z[1] = byte(extensionALPN & 0xff)
		lengths := z[2:]
		z = z[6:]

		stringsLength := 0
		for _, s := range m.alpnProtocols {
			l := len(s)
			z[0] = byte(l)
			copy(z[1:], s)
			z = z[1+l:]
			stringsLength += 1 + l
		}

		lengths[2] = byte(stringsLength >> 8)
		lengths[3] = byte(stringsLength)
		stringsLength += 2
		lengths[0] = byte(stringsLength >> 8)
		lengths[1] = byte(stringsLength)
	}
	if m.sctListSupported {
		// https://tools.ietf.org/html/rfc6962#section-3.3.1
		z[0] = byte(extensionSignedCertificateTimestamp >> 8)
		z[1] = byte(extensionSignedCertificateTimestamp)
		// zero uint16 for the zero-length extension_data
		z = z[4:]
	}
	if len(m.keyShares) > 0 {
		// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.5
		z[0] = byte(extensionKeyShare >> 8)
		z[1] = byte(extensionKeyShare)
		lengths := z[2:]
		z = z[6:]

		totalLength := 0
		for _, ks := range m.keyShares {
			z[0] = byte(ks.group >> 8)
			z[1] = byte(ks.group)
			z[2] = byte(len(ks.keyExchange) >> 8)
			z[3] = byte(len(ks.keyExchange))
			copy(z[4:], ks.keyExchange)
			z = z[4+len(ks.keyExchange):]
			totalLength += 4 + len(ks.keyExchange)
		}

		lengths[2] = byte(totalLength >> 8)
		lengths[3] = byte(totalLength)
		totalLength += 2
		lengths[0] = byte(totalLength >> 8)
		lengths[1] = byte(totalLength)
	}
	if len(m.supportedVersions) > 0 {
		z[0] = byte(extensionSupportedVersions >> 8)
		z[1] = byte(extensionSupportedVersions)
		l := 1 + 2*len(m.supportedVersions)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l -= 1
		z[4] = byte(l)
		z = z[5:]
		for _, v := range m.supportedVersions {
			z[0] = byte(v >> 8)
			z[1] = byte(v)
			z = z[2:]
		}
	}
	if m.hasEarlyData {
		z[0] = byte(extensionEarlyData >> 8)
		z[1] = byte(extensionEarlyData)
		z = z[4:]
	}
	if m.delegatedCredentials {
		binary.BigEndian.PutUint16(z, extensionDelegatedCredentials)
		z = z[4:]
	}
	if m.extendedMasterSecret {
		binary.BigEndian.PutUint16(z, extensionExtendedMasterSecret)
		z = z[4:]
	}

	m.raw = x

	return x
}

func (m *clientHelloMsg) unmarshalOld(data []byte) alert {
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
	bindersOffset := 39 + sessionIdLen
	if len(data) < 2 {
		return alertDecodeError
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return alertDecodeError
	}
	numCipherSuites := cipherSuiteLen / 2
	m.cipherSuites = make([]uint16, numCipherSuites)
	for i := 0; i < numCipherSuites; i++ {
		m.cipherSuites[i] = uint16(data[2+2*i])<<8 | uint16(data[3+2*i])
		if m.cipherSuites[i] == scsvRenegotiation {
			m.secureRenegotiationSupported = true
		}
	}
	data = data[2+cipherSuiteLen:]
	bindersOffset += 2 + cipherSuiteLen
	if len(data) < 1 {
		return alertDecodeError
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return alertDecodeError
	}
	m.compressionMethods = data[1 : 1+compressionMethodsLen]

	data = data[1+compressionMethodsLen:]
	bindersOffset += 1 + compressionMethodsLen

	m.nextProtoNeg = false
	m.serverName = ""
	m.ocspStapling = false
	m.ticketSupported = false
	m.sessionTicket = nil
	m.signatureAlgorithms = nil
	m.alpnProtocols = nil
	m.sctListSupported = false
	m.keyShares = nil
	m.supportedVersions = nil
	m.pskIdentities = nil
	m.pskKeyExchangeModes = nil
	m.hasEarlyData = false
	m.delegatedCredentials = false
	m.extendedMasterSecret = false

	if len(data) == 0 {
		// ClientHello is optionally followed by extension data
		return alertSuccess
	}
	if len(data) < 2 {
		return alertDecodeError
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	bindersOffset += 2
	if extensionsLength != len(data) {
		return alertDecodeError
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return alertDecodeError
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		bindersOffset += 4
		if len(data) < length {
			return alertDecodeError
		}

		switch extension {
		case extensionServerName:
			d := data[:length]
			if len(d) < 2 {
				return alertDecodeError
			}
			namesLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != namesLen {
				return alertDecodeError
			}
			for len(d) > 0 {
				if len(d) < 3 {
					return alertDecodeError
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return alertDecodeError
				}
				if nameType == 0 {
					m.serverName = string(d[:nameLen])
					// An SNI value may not include a
					// trailing dot. See
					// https://tools.ietf.org/html/rfc6066#section-3.
					if strings.HasSuffix(m.serverName, ".") {
						// TODO use alertDecodeError?
						return alertUnexpectedMessage
					}
					break
				}
				d = d[nameLen:]
			}
		case extensionNextProtoNeg:
			if length > 0 {
				return alertDecodeError
			}
			m.nextProtoNeg = true
		case extensionStatusRequest:
			m.ocspStapling = length > 0 && data[0] == statusTypeOCSP
		case extensionSupportedCurves:
			// http://tools.ietf.org/html/rfc4492#section-5.5.1
			// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.4
			if length < 2 {
				return alertDecodeError
			}
			l := int(data[0])<<8 | int(data[1])
			if l%2 == 1 || length != l+2 {
				return alertDecodeError
			}
			numCurves := l / 2
			m.supportedCurves = make([]CurveID, numCurves)
			d := data[2:]
			for i := 0; i < numCurves; i++ {
				m.supportedCurves[i] = CurveID(d[0])<<8 | CurveID(d[1])
				d = d[2:]
			}
		case extensionSupportedPoints:
			// http://tools.ietf.org/html/rfc4492#section-5.5.2
			if length < 1 {
				return alertDecodeError
			}
			l := int(data[0])
			if length != l+1 {
				return alertDecodeError
			}
			m.supportedPoints = make([]uint8, l)
			copy(m.supportedPoints, data[1:])
		case extensionSessionTicket:
			// http://tools.ietf.org/html/rfc5077#section-3.2
			m.ticketSupported = true
			m.sessionTicket = data[:length]
		case extensionSignatureAlgorithms:
			// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
			// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.3
			if length < 2 || length&1 != 0 {
				return alertDecodeError
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return alertDecodeError
			}
			n := l / 2
			d := data[2:]
			m.signatureAlgorithms = make([]SignatureScheme, n)
			for i := range m.signatureAlgorithms {
				m.signatureAlgorithms[i] = SignatureScheme(d[0])<<8 | SignatureScheme(d[1])
				d = d[2:]
			}
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
			if length < 2 {
				return alertDecodeError
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return alertDecodeError
			}
			d := data[2:length]
			for len(d) != 0 {
				stringLen := int(d[0])
				d = d[1:]
				if stringLen == 0 || stringLen > len(d) {
					return alertDecodeError
				}
				m.alpnProtocols = append(m.alpnProtocols, string(d[:stringLen]))
				d = d[stringLen:]
			}
		case extensionSignedCertificateTimestamp:
			m.sctListSupported = true
			if length != 0 {
				return alertDecodeError
			}
		case extensionKeyShare:
			// https://tools.ietf.org/html/rfc8446#section-4.2.8
			if length < 2 {
				return alertDecodeError
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return alertDecodeError
			}
			d := data[2:length]
			for len(d) != 0 {
				if len(d) < 4 {
					return alertDecodeError
				}
				dataLen := int(d[2])<<8 | int(d[3])
				if dataLen == 0 || 4+dataLen > len(d) {
					return alertDecodeError
				}
				m.keyShares = append(m.keyShares, keyShareEntry{
					group:       CurveID(d[0])<<8 | CurveID(d[1]),
					keyExchange: d[4 : 4+dataLen],
				})
				d = d[4+dataLen:]
			}
		case extensionSupportedVersions:
			// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.1
			if length < 1 {
				return alertDecodeError
			}
			l := int(data[0])
			if l%2 == 1 || length != l+1 {
				return alertDecodeError
			}
			n := l / 2
			d := data[1:]
			for i := 0; i < n; i++ {
				v := uint16(d[0])<<8 + uint16(d[1])
				m.supportedVersions = append(m.supportedVersions, v)
				d = d[2:]
			}
		case extensionPreSharedKey:
			// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.6
			if length < 2 {
				return alertDecodeError
			}
			// Ensure this extension is the last one in the Client Hello
			if len(data) != length {
				return alertIllegalParameter
			}
			li := int(data[0])<<8 | int(data[1])
			if 2+li+2 > length {
				return alertDecodeError
			}
			d := data[2 : 2+li]
			bindersOffset += 2 + li
			for len(d) > 0 {
				if len(d) < 6 {
					return alertDecodeError
				}
				l := int(d[0])<<8 | int(d[1])
				if len(d) < 2+l+4 {
					return alertDecodeError
				}
				m.pskIdentities = append(m.pskIdentities, pskIdentity{
					identity: d[2 : 2+l],
					obfuscatedTicketAge: uint32(d[l+2])<<24 | uint32(d[l+3])<<16 |
						uint32(d[l+4])<<8 | uint32(d[l+5]),
				})
				d = d[2+l+4:]
			}
			lb := int(data[li+2])<<8 | int(data[li+3])
			d = data[2+li+2:]
			if lb != len(d) || lb == 0 {
				return alertDecodeError
			}
			i := 0
			for len(d) > 0 {
				if i >= len(m.pskIdentities) {
					return alertIllegalParameter
				}
				if len(d) < 1 {
					return alertDecodeError
				}
				l := int(d[0])
				if l > len(d)-1 {
					return alertDecodeError
				}
				if i >= len(m.pskIdentities) {
					return alertIllegalParameter
				}
				m.pskIdentities[i].binder = d[1 : 1+l]
				d = d[1+l:]
				i++
			}
			if i != len(m.pskIdentities) {
				return alertIllegalParameter
			}
			m.rawTruncated = m.raw[:bindersOffset]
		case extensionPSKKeyExchangeModes:
			if length < 2 {
				return alertDecodeError
			}
			l := int(data[0])
			if length != l+1 {
				return alertDecodeError
			}
			m.pskKeyExchangeModes = data[1:length]
		case extensionEarlyData:
			// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.8
			m.hasEarlyData = true
		case extensionDelegatedCredentials:
			// https://tools.ietf.org/html/draft-ietf-tls-subcerts-02
			m.delegatedCredentials = true
		case extensionExtendedMasterSecret:
			// RFC 7627
			m.extendedMasterSecret = true
			if length != 0 {
				return alertDecodeError
			}
		}
		data = data[length:]
		bindersOffset += length
	}

	return alertSuccess
}
