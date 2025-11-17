---
layout: post
title: Application Layer Crypto
subtitle: Trust no-one hack everything!
gh-repo: spellshift/realm
gh-badge: [star, fork, follow]
tags: [tavern, imix]
comments: true
mathjax: true
author: Hulto
---

## Why not just use TLS?

While TLS provides strong encryption for data in transit, relying solely on TLS for C2 communications introduces two key security concerns:

C2 traffic contains highly sensitive information that requires additional protection beyond standard transport encryption, including agent tasking and responses that may contain privileged credentials such as Domain Admin credentials, API keys, and session tokens

Many enterprise environments implement TLS inspection at network boundaries, where corporate proxies decrypt, inspect, and re-encrypt all HTTPS traffic. This breaks the end-to-end encryption model—your traffic is only encrypted to the inspection point, not to your actual C2 server. Network defenders can observe your C2 communications in plaintext, and third-party security vendors processing this traffic may log or analyze your operations indefinitely

## Security Requirements

Any application-layer encryption needs to maintain confidentiality and integrity even in adverse situations to do this we need to ensure:
- Forward secrecy
- Capturing an agent doesn't jeapordize sent data
- Even with a full network capture data is protected

**Forward Secrecy** guarantees that compromise of long-term agent/server keys does not compromise past sessions. Each session uses ephemeral keys that are destroyed after use, implementing perfect forward secrecy to ensure that traffic captured now cannot be decrypted later even with full agent/server compromise.

**Capturing an agent doesn't jeapordize sent data** - We have to assume that defenders possess the agent binary and can perform static and dynamic analysis. The design ensures that possession of the binary does not enable traffic decryption, static analysis reveals no useful key material, and embedded cryptographic material is limited to public keys only. Even keys in memory are expired so that limited messages can be decrypted given a full memory dump.

**Even with a full network capture data is protected** - Ensure that network monitoring and full packet capture yield no useful plaintext. Historical traffic must remain encrypted even if current session keys are compromised, and no metadata or patterns should leak operational details that could aid an attacker.


## Implementation

Our implementation combines modern cryptographic primitives to meet these security requirements. At its core is XChaCha20-Poly1305, an authenticated encryption algorithm that provides both confidentiality through stream encryption and integrity through AEAD (Authenticated Encryption with Associated Data). This means every message is encrypted and authenticated to prevent tampering.

The key exchange uses Ephemeral Diffie-Hellman, where the client generates a temporary keypairs that get destroyed when they're no longer needed. The agent embeds the server's long-term public key at compile time for trust establishment, while client keys stay ephemeral and regenerate for each session. This design ensures that capturing an agent binary only reveals the server's public key—nothing more. The key derivation follows NIST SP 800-56A Rev. 3, specifically section 6.2 covering "Schemes Using One Ephemeral Key Pair" (C(1e) Schemes). Following established standards ensures the implementation stays cryptographically sound.


Here's where things got interesting on the server side. gRPC codecs don't let you pass state between marshal and unmarshal functions, which meant we couldn't directly share the encryption key between decrypt and encrypt operations. Our solution? A thread-safe LRU that indexes keys by Goroutine ID. This worked great until we hit streaming scenarios where the server spawns a new goroutine to handle the conversation. Since the new goroutine has a different ID, we perform a stack trace to find the parent's Goroutine ID and retrieve the correct key. Turns out we weren't alone in facing this challenge—others encountered similar issues ([grpc-go#3906](https://github.com/grpc/grpc-go/issues/3906), [grpc#9985](https://github.com/grpc/grpc/issues/9985)).

```go
func (csvc *CryptoSvc) Decrypt(in_arr []byte) ([]byte, []byte) {
	// Read in pub key
	if len(in_arr) < x25519.Size {
		slog.Error(fmt.Sprintf("input bytes to short %d expected at least %d", len(in_arr), x25519.Size))
		return FAILURE_BYTES, FAILURE_BYTES
	}

	client_pub_key_bytes := in_arr[:x25519.Size]

	ids, err := goAllIds()
	if err != nil {
		slog.Error("failed to get goid")
		return FAILURE_BYTES, FAILURE_BYTES
	}
	session_pub_keys.Store(ids.Id, client_pub_key_bytes)

    // ...
}

func (csvc *CryptoSvc) Encrypt(in_arr []byte) []byte {
	ids, err := goAllIds()
	if err != nil {
		slog.Error(fmt.Sprintf("unable to find GOID %s", err))
		return FAILURE_BYTES
	}

	var id int
	var client_pub_key_bytes []byte
	ok := false
	for idx, id := range []int{ids.Id, ids.ParentId} {
		client_pub_key_bytes, ok = session_pub_keys.Load(id)
		if ok {
			slog.Info(fmt.Sprintf("found public key for id: %d idx: %d", id, idx))
			break
		}
	}
    // ...
}

type GoidTrace struct {
	Id       int
	ParentId int
	Others   []int
}

func goAllIds() (GoidTrace, error) {
	buf := debug.Stack()
	// slog.Info(fmt.Sprintf("debug stack: %s", buf))
	var ids []int
	elems := bytes.Fields(buf)
	for i, elem := range elems {
		if bytes.Equal(elem, []byte("goroutine")) && i+1 < len(elems) {
			id, err := strconv.Atoi(string(elems[i+1]))
			if err != nil {
				return GoidTrace{}, err
			}
			ids = append(ids, id)
		}
	}
	res := GoidTrace{
		Id:       ids[0],
		ParentId: ids[1],
		Others:   ids[2:],
	}
	return res, nil
}
```

### Cryptographic Flow
1. Agent embeds server's long-term public key at compile time
2. For each session, client generates ephemeral Curve25519 keypair
3. Client sends its ephemeral public key to server
4. Both parties perform Diffie-Hellman exchange to derive shared secret
5. Shared secret is used to derive XChaCha20-Poly1305 session keys
6. All messages encrypted and authenticated with session keys
7. Ephemeral keys discarded at session end