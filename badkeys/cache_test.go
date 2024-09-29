package badkeys

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/sirupsen/logrus"
)

func TestCacheBasics(t *testing.T) {
	pubRaw, err := base64.StdEncoding.DecodeString(TestKeyDebOpenSSLRSA3072BE3229491)
	if err != nil {
		t.Fatalf("failed to decode public key: %v", err)
	}

	pubKey, err := ssh.ParsePublicKey(pubRaw)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	hash, err := PrefixFromPublicKey(pubKey)
	if err != nil {
		t.Fatalf("failed to obtain prefix hash: %v", err)
	}

	expHash := []byte{0x00, 0x00, 0x00, 0xe1, 0xbf, 0xda, 0x4c, 0xbe, 0xd1, 0xc8, 0x11, 0x56, 0x1f, 0x11, 0xae}
	if !bytes.Equal(hash, expHash) {
		t.Fatalf("rsa key did not match expected hash: got %s wanted %s", hex.EncodeToString(hash), hex.EncodeToString(expHash))
	}

	texp := &Result{
		Repo:     "badkeys/debianopenssl",
		RepoID:   1,
		RepoType: "github",
		RepoPath: "main",
		RepoName: "debianssl",
		KeyPath:  "rsa3072/ssh/be32/29491.key",
	}

	cache := NewCache(logrus.StandardLogger())
	if err != nil {
		t.Fatalf("could not create cache: %v", err)
	}

	if _, _, err := cache.Update(); err != nil {
		t.Fatalf("could not update blocklist: %v", err)
	}

	bl, err := cache.LoadBlocklist()
	if err != nil {
		t.Fatalf("could not load blocklist: %v", err)
	}

	res, err := bl.LookupPrefix(hash)
	if err != nil {
		t.Fatalf("failed to find: %v", err)
	}

	if diff := cmp.Diff(res, texp); diff != "" {
		t.Errorf("unexpected result: %s", diff)
	}
	expURL := "https://github.com/badkeys/debianopenssl/blob/main/rsa3072/ssh/be32/29491.key"
	resURL := res.ToURL()
	if resURL != expURL {
		t.Errorf("unexpected url %s got %s", expURL, resURL)
	}

	hash = []byte{0xff, 0xff, 0x00, 0xe1, 0xbf, 0xda, 0x4c, 0xbe, 0xd1, 0xc8, 0x11, 0x56, 0x1f, 0x11, 0xae}
	res, err = bl.LookupPrefix(hash)
	if err == nil {
		t.Fatalf("bad hash returned result: %v", res)
	}
}

// TestKeyDebOpenSSLRSA3072BE3229491 is the public key from https://github.com/badkeys/debianopenssl/blob/main/rsa3072/ssh/be32/29491.key
var TestKeyDebOpenSSLRSA3072BE3229491 = `AAAAB3NzaC1yc2EAAAABIwAAAYEAvhvE7T48ibbjuayQYscQiVCKJ6bGx8xktWPNoIX1f7iDz9tK1YQ+KyPMlwvtoohiDTAGJ6uDMcjauoKnuwi0eM28sNwZr5Ijhb4TL761IHpLta+arf/CPfFuWtPNtYDH/aZsh3ZzX0VbxTAKLFCJuxSfAapHanQpv9fDQ25io48qCCJGMvXZNU2QZJY1hvTYtgVyc2RhHBJvT1s58GCDj4nlzhZnYWUlmMQ/rYgB4pPx/RuG8yKOSg5aoxt2i4BE9AfHidFcxtAPw9Gtzi+r5B6zLi0jzNtTUQlgz5u53nU7E+GD09Zf6CztM4aa54K+mNbnVxt++GWfdVR9e5N0B94jyLX6oCWGCG9exHY8lbFNwXDJd3LifjHKxb6OEWuq+FZciwV0Z/RG/bgJXSpu7hUsbpodh5kOvioZUfVSChnCLu67JgbhJ8bP0ZWRj7cF2JFa+XRPM9LHPRDFbJlBfYZfyRqVL0Yv1M9JaJhnPNC30wMBFN2Nujy2SNGv5qU7`
