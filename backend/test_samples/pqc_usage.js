// PQC-compliant JS sample — should trigger positive JS rules.
import { mlkem768 } from '@noble/post-quantum/ml-kem';
import { mldsa65 } from '@noble/post-quantum/ml-dsa';
import { slhdsa_sha2_128s } from '@noble/post-quantum/slh-dsa';

const kemKeys = mlkem768.keygen();
const { cipherText, sharedSecret } = mlkem768.encapsulate(kemKeys.publicKey);

const sigKeys = mldsa65.keygen();
const signature = mldsa65.sign(sigKeys.secretKey, new TextEncoder().encode('msg'));

const backupKeys = slhdsa_sha2_128s.keygen();
const backupSig = slhdsa_sha2_128s.sign(backupKeys.secretKey, new TextEncoder().encode('msg'));
