package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// Get RSA public key
func (r *Signature) GetAdminKey() []byte {
	r.RLock()
	defer r.RUnlock()
	result := r.Cert.SubjectKeyId
	return result
}

// Generate signature from key string
func (r *Signature) GenerateSign(data string) ([]byte, error) {
	r.Lock()
	defer r.Unlock()

	opts := new(rsa.PSSOptions)
	opts.SaltLength = rsa.PSSSaltLengthAuto
	newhash := crypto.SHA256
	pssh := newhash.New()

	_, err := pssh.Write([]byte(data))

	if err != nil {
		return nil, err
	}

	hashed := pssh.Sum(nil)

	byteHash, err := rsa.SignPSS(rand.Reader, r.Key, newhash, hashed, opts)

	if err != nil {
		return nil, err
	}

	return byteHash, nil
}

// Verify signature with key string
func (r *Signature) VerifyHash(data string, signature []byte) (bool, error) {
	r.Lock()
	defer r.Unlock()

	opts := new(rsa.PSSOptions)

	hashed := sha256.Sum256([]byte(data))

	err := rsa.VerifyPSS(&r.Key.PublicKey, crypto.SHA256, hashed[:], signature, opts)

	if err != nil {
		return false, err
	}

	return true, nil
}
