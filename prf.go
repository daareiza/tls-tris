// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
)

// Split a premaster secret in two as specified in RFC 4346, section 5.
func splitPreMasterSecret(secret []byte) (s1, s2 []byte) {
	s1 = secret[0 : (len(secret)+1)/2]
	s2 = secret[len(secret)/2:]
	return
}

// pHash implements the P_hash function, as defined in RFC 4346, section 5.
func pHash(result, secret, seed []byte, hash func() hash.Hash) {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		copy(result[j:], b)
		j += len(b)

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

// prf10 implements the TLS 1.0 pseudo-random function, as defined in RFC 2246, section 5.
func prf10(result, secret, label, seed []byte) {
	hashSHA1 := sha1.New
	hashMD5 := md5.New

	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	s1, s2 := splitPreMasterSecret(secret)
	pHash(result, s1, labelAndSeed, hashMD5)
	result2 := make([]byte, len(result))
	pHash(result2, s2, labelAndSeed, hashSHA1)

	for i, b := range result2 {
		result[i] ^= b
	}
}

// prf12 implements the TLS 1.2 pseudo-random function, as defined in RFC 5246, section 5.
func prf12(hashFunc func() hash.Hash) func(result, secret, label, seed []byte) {
	return func(result, secret, label, seed []byte) {
		labelAndSeed := make([]byte, len(label)+len(seed))
		copy(labelAndSeed, label)
		copy(labelAndSeed[len(label):], seed)

		pHash(result, secret, labelAndSeed, hashFunc)
	}
}

// prf30 implements the SSL 3.0 pseudo-random function, as defined in
// www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt section 6.
func prf30(result, secret, label, seed []byte) {
	hashSHA1 := sha1.New()
	hashMD5 := md5.New()

	done := 0
	i := 0
	// RFC 5246 section 6.3 says that the largest PRF output needed is 128
	// bytes. Since no more ciphersuites will be added to SSLv3, this will
	// remain true. Each iteration gives us 16 bytes so 10 iterations will
	// be sufficient.
	var b [11]byte
	for done < len(result) {
		for j := 0; j <= i; j++ {
			b[j] = 'A' + byte(i)
		}

		hashSHA1.Reset()
		hashSHA1.Write(b[:i+1])
		hashSHA1.Write(secret)
		hashSHA1.Write(seed)
		digest := hashSHA1.Sum(nil)

		hashMD5.Reset()
		hashMD5.Write(secret)
		hashMD5.Write(digest)

		done += copy(result[done:], hashMD5.Sum(nil))
		i++
	}
}

const (
	tlsRandomLength      = 32 // Length of a random nonce in TLS 1.1.
	masterSecretLength   = 48 // Length of a master secret in TLS 1.1.
	finishedVerifyLength = 12 // Length of verify_data in a Finished message.
)

var masterSecretLabel = []byte("master secret")
var keyExpansionLabel = []byte("key expansion")
var clientFinishedLabel = []byte("client finished")
var serverFinishedLabel = []byte("server finished")
var extendedMasterSecretLabel = []byte("extended master secret")
var finishedLabel = []byte("finished")
var channelIDLabel = []byte("TLS Channel ID signature\x00")
var channelIDResumeLabel = []byte("Resumption\x00")

func prfAndHashForVersion(version uint16, suite *cipherSuite) (func(result, secret, label, seed []byte), crypto.Hash) {
	switch version {
	case VersionSSL30:
		return prf30, crypto.Hash(0)
	case VersionTLS10, VersionTLS11:
		return prf10, crypto.Hash(0)
	case VersionTLS12:
		if suite.flags&suiteSHA384 != 0 {
			return prf12(sha512.New384), crypto.SHA384
		}
		return prf12(sha256.New), crypto.SHA256
	default:
		panic("unknown version")
	}
}

func prfForVersion(version uint16, suite *cipherSuite) func(result, secret, label, seed []byte) {
	prf, _ := prfAndHashForVersion(version, suite)
	return prf
}

// masterFromPreMasterSecret generates the master secret from the pre-master
// secret. See http://tools.ietf.org/html/rfc5246#section-8.1
func masterFromPreMasterSecret(version uint16, suite *cipherSuite, preMasterSecret, clientRandom, serverRandom []byte, fin finishedHash, ems bool) []byte {
	if ems {
		session_hash := fin.Sum()
		masterSecret := make([]byte, masterSecretLength)
		prfForVersion(version, suite)(masterSecret, preMasterSecret, extendedMasterSecretLabel, session_hash)
		return masterSecret
	} else {
		seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
		seed = append(seed, clientRandom...)
		seed = append(seed, serverRandom...)

		masterSecret := make([]byte, masterSecretLength)
		prfForVersion(version, suite)(masterSecret, preMasterSecret, masterSecretLabel, seed)
		return masterSecret
	}
}

// keysFromMasterSecret generates the connection keys from the master
// secret, given the lengths of the MAC key, cipher key and IV, as defined in
// RFC 2246, section 6.3.
func keysFromMasterSecret(version uint16, suite *cipherSuite, masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte) {
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	n := 2*macLen + 2*keyLen + 2*ivLen
	keyMaterial := make([]byte, n)
	prfForVersion(version, suite)(keyMaterial, masterSecret, keyExpansionLabel, seed)
	clientMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	serverMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	clientKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	clientIV = keyMaterial[:ivLen]
	keyMaterial = keyMaterial[ivLen:]
	serverIV = keyMaterial[:ivLen]
	return
}

// lookupTLSHash looks up the corresponding crypto.Hash for a given
// hash from a TLS SignatureScheme.
func lookupTLSHash(signatureAlgorithm SignatureScheme) (crypto.Hash, error) {
	switch signatureAlgorithm {
	case PKCS1WithSHA1, ECDSAWithSHA1:
		return crypto.SHA1, nil
	case PKCS1WithSHA256, PSSWithSHA256, ECDSAWithP256AndSHA256:
		return crypto.SHA256, nil
	case PKCS1WithSHA384, PSSWithSHA384, ECDSAWithP384AndSHA384:
		return crypto.SHA384, nil
	case PKCS1WithSHA512, PSSWithSHA512, ECDSAWithP521AndSHA512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("tls: unsupported signature algorithm: %#04x", signatureAlgorithm)
	}
}

func newFinishedHash(version uint16, cipherSuite *cipherSuite) finishedHash {
	var buffer []byte
	if version == VersionSSL30 || version >= VersionTLS12 {
		buffer = []byte{}
	}

	prf, hash := prfAndHashForVersion(version, cipherSuite)
	if hash != 0 {
		return finishedHash{client: hash.New(), server: hash.New(), clientMD5: nil, serverMD5: nil, buffer: buffer, version: version, prf: prf}
	}

	return finishedHash{client: sha1.New(), server: sha1.New(), clientMD5: md5.New(), serverMD5: md5.New(), buffer: buffer, version: version, prf: prf}
}

// A finishedHash calculates the hash of a set of handshake messages suitable
// for including in a Finished message.
type finishedHash struct {
	hash crypto.Hash

	client hash.Hash
	server hash.Hash

	// Prior to TLS 1.2, an additional MD5 hash is required.
	clientMD5 hash.Hash
	serverMD5 hash.Hash

	// In TLS 1.2, a full buffer is sadly required.
	buffer []byte

	version uint16
	prf     func(result, secret, label, seed []byte)

	// secret, in TLS 1.3, is the running input secret.
	secret []byte
}

func (h *finishedHash) UpdateForHelloRetryRequest() (err error) {
	data := newByteBuilder()
	data.addU8(typeMessageHash)
	data.addU24(h.hash.Size())
	data.addBytes(h.Sum())
	h.client = h.hash.New()
	h.server = h.hash.New()
	if h.buffer != nil {
		h.buffer = []byte{}
	}
	h.Write(data.finish())
	return nil
}

func (h *finishedHash) Write(msg []byte) (n int, err error) {
	h.client.Write(msg)
	h.server.Write(msg)

	if h.version < VersionTLS12 {
		h.clientMD5.Write(msg)
		h.serverMD5.Write(msg)
	}

	if h.buffer != nil {
		h.buffer = append(h.buffer, msg...)
	}

	return len(msg), nil
}

func (h finishedHash) Sum() []byte {
	if h.version >= VersionTLS12 {
		return h.client.Sum(nil)
	}

	out := make([]byte, 0, md5.Size+sha1.Size)
	out = h.clientMD5.Sum(out)
	return h.client.Sum(out)
}

// finishedSum30 calculates the contents of the verify_data member of a SSLv3
// Finished message given the MD5 and SHA1 hashes of a set of handshake
// messages.
func finishedSum30(md5, sha1 hash.Hash, masterSecret []byte, magic []byte) []byte {
	md5.Write(magic)
	md5.Write(masterSecret)
	md5.Write(ssl30Pad1[:])
	md5Digest := md5.Sum(nil)

	md5.Reset()
	md5.Write(masterSecret)
	md5.Write(ssl30Pad2[:])
	md5.Write(md5Digest)
	md5Digest = md5.Sum(nil)

	sha1.Write(magic)
	sha1.Write(masterSecret)
	sha1.Write(ssl30Pad1[:40])
	sha1Digest := sha1.Sum(nil)

	sha1.Reset()
	sha1.Write(masterSecret)
	sha1.Write(ssl30Pad2[:40])
	sha1.Write(sha1Digest)
	sha1Digest = sha1.Sum(nil)

	ret := make([]byte, len(md5Digest)+len(sha1Digest))
	copy(ret, md5Digest)
	copy(ret[len(md5Digest):], sha1Digest)
	return ret
}

var ssl3ClientFinishedMagic = [4]byte{0x43, 0x4c, 0x4e, 0x54}
var ssl3ServerFinishedMagic = [4]byte{0x53, 0x52, 0x56, 0x52}

// clientSum returns the contents of the verify_data member of a client's
// Finished message.
func (h finishedHash) clientSum(masterSecret []byte) []byte {
	if h.version == VersionSSL30 {
		return finishedSum30(h.clientMD5, h.client, masterSecret, ssl3ClientFinishedMagic[:])
	}

	if h.version < VersionTLS13 {
		out := make([]byte, finishedVerifyLength)
		h.prf(out, masterSecret, clientFinishedLabel, h.Sum())
		return out
	}

	clientFinishedKey := hkdfExpandLabel(h.hash, masterSecret, nil, "finished", h.hash.Size())
	finishedHMAC := hmac.New(h.hash.New, clientFinishedKey)
	finishedHMAC.Write(h.appendContextHashes(nil))
	return finishedHMAC.Sum(nil)
}

// serverSum returns the contents of the verify_data member of a server's
// Finished message.
func (h finishedHash) serverSum(masterSecret []byte) []byte {
	if h.version == VersionSSL30 {
		return finishedSum30(h.serverMD5, h.server, masterSecret, ssl3ServerFinishedMagic[:])
	}

	out := make([]byte, finishedVerifyLength)
	h.prf(out, masterSecret, serverFinishedLabel, h.Sum())
	return out
}

// hashForClientCertificate returns a digest over the handshake messages so far,
// suitable for signing by a TLS client certificate.
func (h finishedHash) hashForClientCertificate(sigType uint8, hashAlg crypto.Hash, masterSecret []byte) ([]byte, error) {
	if (h.version == VersionSSL30 || h.version >= VersionTLS12) && h.buffer == nil {
		panic("a handshake hash for a client-certificate was requested after discarding the handshake buffer")
	}

	if h.version == VersionSSL30 {
		if sigType != signaturePKCS1v15 {
			return nil, errors.New("tls: unsupported signature type for client certificate")
		}

		md5Hash := md5.New()
		md5Hash.Write(h.buffer)
		sha1Hash := sha1.New()
		sha1Hash.Write(h.buffer)
		return finishedSum30(md5Hash, sha1Hash, masterSecret, nil), nil
	}
	if h.version >= VersionTLS12 {
		hash := hashAlg.New()
		hash.Write(h.buffer)
		return hash.Sum(nil), nil
	}

	if sigType == signatureECDSA {
		return h.server.Sum(nil), nil
	}

	return h.Sum(), nil
}

// discardHandshakeBuffer is called when there is no more need to
// buffer the entirety of the handshake messages.
func (h *finishedHash) discardHandshakeBuffer() {
	h.buffer = nil
}

// zeroSecretTLS13 returns the default all zeros secret for TLS 1.3, used when a
// given secret is not available in the handshake. See RFC 8446, section 7.1.
func (h *finishedHash) zeroSecret() []byte {
	return make([]byte, h.hash.Size())
}

// addEntropy incorporates ikm into the running TLS 1.3 secret with HKDF-Expand.
func (h *finishedHash) addEntropy(ikm []byte) {
	h.secret = hkdfExtract(h.hash, h.secret, ikm)
}

func (h *finishedHash) nextSecret() {
	h.secret = hkdfExpandLabel(h.hash, h.secret, h.hash.New().Sum(nil), "derived", h.hash.Size())
}

// appendContextHashes returns the concatenation of the handshake hash and the
// resumption context hash, as used in TLS 1.3.
func (h *finishedHash) appendContextHashes(b []byte) []byte {
	b = h.client.Sum(b)
	return b
}

// The following are labels for traffic secret derivation in TLS 1.3.
var (
	externalPSKBinderLabel        = "ext binder"
	resumptionPSKBinderLabel      = "res binder"
	earlyTrafficLabel             = "c e traffic"
	clientHandshakeTrafficLabel   = "c hs traffic"
	serverHandshakeTrafficLabel   = "s hs traffic"
	clientApplicationTrafficLabel = "c ap traffic"
	serverApplicationTrafficLabel = "s ap traffic"
	applicationTrafficLabel       = "traffic upd"
	earlyExporterLabel            = "e exp master"
	exporterLabel                 = "exp master"
	resumptionLabel               = "res master"
	resumptionPSKLabel            = "resumption"
)

// deriveSecret implements TLS 1.3's Derive-Secret function, as defined in
// section 7.1 of draft ietf-tls-tls13-16.
func (h *finishedHash) deriveSecret(label []byte) []byte {
	return hkdfExpandLabel(h.hash, h.secret, h.appendContextHashes(nil), string(label), h.hash.Size())
}

// The following are context strings for CertificateVerify in TLS 1.3.
var (
	clientCertificateVerifyContextTLS13 = []byte("TLS 1.3, client CertificateVerify")
	serverCertificateVerifyContextTLS13 = []byte("TLS 1.3, server CertificateVerify")
	channelIDContextTLS13               = []byte("TLS 1.3, Channel ID")
)

// certificateVerifyMessage returns the input to be signed for CertificateVerify
// in TLS 1.3.
func (h *finishedHash) certificateVerifyInput(context []byte) []byte {
	const paddingLen = 64
	b := make([]byte, paddingLen, paddingLen+len(context)+1+2*h.hash.Size())
	for i := 0; i < paddingLen; i++ {
		b[i] = 32
	}
	b = append(b, context...)
	b = append(b, 0)
	b = h.appendContextHashes(b)
	return b
}

type trafficDirection int

const (
	clientWrite trafficDirection = iota
	serverWrite
)

// deriveTrafficAEAD derives traffic keys and constructs an AEAD given a traffic
// secret.
func deriveTrafficAEAD(version uint16, suite *cipherSuite, secret []byte, side trafficDirection) interface{} {
	hash := hashForSuite(suite)
	key := hkdfExpandLabel(hash, secret, nil, "key", suite.keyLen)
	iv := hkdfExpandLabel(hash, secret, nil, "iv", suite.ivLen)

	return suite.aead(version, key, iv)
}

func updateTrafficSecret(hash crypto.Hash, version uint16, secret []byte) []byte {
	return hkdfExpandLabel(hash, secret, nil, applicationTrafficLabel, hash.Size())
}

func computePSKBinder(psk []byte, version uint16, label []byte, cipherSuite *cipherSuite, clientHello, helloRetryRequest, truncatedHello []byte) []byte {
	finishedHash := newFinishedHash(version, cipherSuite)
	finishedHash.addEntropy(psk)
	binderKey := finishedHash.deriveSecret(label)
	finishedHash.Write(clientHello)
	if len(helloRetryRequest) != 0 {
		finishedHash.UpdateForHelloRetryRequest()
	}
	finishedHash.Write(helloRetryRequest)
	finishedHash.Write(truncatedHello)
	return finishedHash.clientSum(binderKey)
}

func deriveSessionPSK(suite *cipherSuite, version uint16, masterSecret []byte, nonce []byte) []byte {
	hash := hashForSuite(suite)
	return hkdfExpandLabel(hash, masterSecret, nonce, resumptionPSKLabel, hash.Size())
}
