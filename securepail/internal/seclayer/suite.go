package seclayer

// A Suite is one way of encrypting objects. They differ in what they need and
// where the data can be opened again, so the user picks per rule.
type Suite struct {
	ID     string // stored in rules and in the pail-secure object marker
	Name   string
	Suffix string // added to the object key
	// NeedsGPG: the gpg command-line tool must be installed (desktop only).
	NeedsGPG bool
	// Mobile: can be implemented with the platform crypto libraries of iOS
	// (CryptoKit) and Android (javax.crypto) alone.
	Mobile bool
	// Streaming: encrypts in authenticated chunks, so large files need little
	// memory and a truncated file is detected.
	Streaming bool
	// PassphraseKeys: a typed passphrase can be the key (otherwise only a
	// generated key).
	PassphraseKeys bool
	Summary        string
}

// Suite IDs.
const (
	SuiteGPG     = "gpg"
	SuiteAESGCM  = "aesgcm"
	SuffixGPG    = ".gpg"
	SuffixAESGCM = ".spe"
)

// Suites lists the available suites, portable first (the recommended default).
var Suites = []Suite{
	{ID: SuiteAESGCM, Name: "AES-256-GCM (portable)", Suffix: SuffixAESGCM, Mobile: true, Streaming: true,
		Summary: "No extra software. Opens on desktop, iOS and Android. Needs a generated key."},
	{ID: SuiteGPG, Name: "GPG (OpenPGP)", Suffix: SuffixGPG, NeedsGPG: true, PassphraseKeys: true,
		Summary: "Standard OpenPGP files that any gpg can open. Desktop only; needs gpg installed."},
}

// SuiteByID returns the suite with the given ID.
func SuiteByID(id string) (Suite, bool) {
	for _, s := range Suites {
		if s.ID == id {
			return s, true
		}
	}
	return Suite{}, false
}
