package gpsw06

import "errors"

var (
	ErrAttrOutOfRange   = errors.New("attribute Index out of range")
	ErrBadAttributeList = errors.New("incomplete attribute list (universe) or not sorted")
	ErrBadNodeJSON      = errors.New("bad structured json for node")
	ErrEncAttrNotExist  = errors.New("encrypted key not exist for such attribute")
	ErrInvalidG1        = errors.New("could not find well-formed string describing g1")
	ErrInvalidG2        = errors.New("could not find well-formed string describing g2")
	ErrUnknownNodeType  = errors.New("unknown node type")
	ErrTreeNotSatisfied = errors.New("ciphertext does not Satisfy decryption key policy")

	ErrExpectingMasterKey  = errors.New("key provided is not a master key")
	ErrExpectingPrivateKey = errors.New("key provided is not a private key")
	ErrExpectingPublicKey  = errors.New("key provided is not a public key")
)
