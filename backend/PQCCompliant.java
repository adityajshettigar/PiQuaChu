// PQC-compliant sample — should trigger the positive FIPS 203/204/205 Java rules.
import org.bouncycastle.pqc.crypto.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyPairGenerator;

public class PQCCompliant {

    // FIPS 203 — ML-KEM (Kyber) key encapsulation
    public void mlKemKeyExchange() {
        KyberKeyPairGenerator kyberGen = new KyberKeyPairGenerator();
        kyberGen.init(null);
        kyberGen.generateKeyPair();
    }

    // FIPS 204 — ML-DSA (Dilithium) digital signatures
    public void mlDsaSigning() {
        DilithiumKeyPairGenerator dilithiumGen = new DilithiumKeyPairGenerator();
        dilithiumGen.init(null);
        dilithiumGen.generateKeyPair();
    }

    // FIPS 205 — SLH-DSA (SPHINCS+) backup signatures
    public void slhDsaBackup() {
        SPHINCSPlusKeyPairGenerator sphincsGen = new SPHINCSPlusKeyPairGenerator();
        sphincsGen.init(null);
        sphincsGen.generateKeyPair();
    }
}
