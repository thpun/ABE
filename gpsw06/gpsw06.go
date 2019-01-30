package gpsw06

func (algo *GPSW06) Setup() (PublicKey, MasterKey, error) {

}

func (algo *GPSW06) Encrypt(msg Message, atts []uint, key PublicKey) (Ciphertext, error) {

}

func (algo *GPSW06) KeyGen(Tree, msk MasterKey) (DecryptKey, error) {

}

func (algo *GPSW06) Decrypt(ciphertext Ciphertext, dk DecryptKey) (Message, error) {

}

func (algo *GPSW06) decryptNode(ciphertext Ciphertext, key DecryptKey, attId uint) {

}
