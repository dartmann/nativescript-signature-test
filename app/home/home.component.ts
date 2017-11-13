import {Component} from "@angular/core";

declare let android: any, java: any;

@Component({
    selector: "Home",
    moduleId: module.id,
    templateUrl: "./home.component.html",
    styleUrls: ['./home.component.css']
})
export class HomeComponent {

    private ANDROID_KEYSTORE: string = "AndroidKeyStore";
    private keyStore: java.security.KeyStore;

    constructor() {
        this.keyStore = java.security.KeyStore.getInstance(this.ANDROID_KEYSTORE);
        this.keyStore.load(null);
    }

    public testSignature() {
        console.log("START SIGNING PROCEDURE");
        let keyPair: java.security.KeyPair = this.createKeyPair(4, "signatureAlias", "RSA");
        console.log("ALGO\nPK: " + keyPair.getPublic().getAlgorithm() + "\nSK: " + keyPair.getPrivate().getAlgorithm());
    }

    private createKeyPair(purpose: number, alias: string, algorithm: string): java.security.KeyPair {
        if (!this.keyStore.containsAlias(alias)) {
            console.log("NEW");
            let keyPairGenerator: java.security.KeyPairGenerator = java.security.KeyPairGenerator
                .getInstance(algorithm, this.ANDROID_KEYSTORE);
            console.log("KeyPairGenerator created");
            // android.security.keyStore.KeyGenParameterSpec is not exported
            let keyGenParameterSpec: any =
                new android.security.keystore.KeyGenParameterSpec.Builder(
                    alias,
                    purpose)
                    .setAlgorithmParameterSpec(new java.security.spec.RSAKeyGenParameterSpec(2048,
                        java.security.spec.RSAKeyGenParameterSpec.F4))
                    .setDigests("SHA-256")//android.security.keyStore.KeyProperties.DIGEST_SHA256
                    //.setSignaturePaddings("PSS")
                    .setSignaturePaddings("PKCS1")//android.security.keyStore.KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
                    .build();
            console.log("KeyGenParameterSpec created");
            keyPairGenerator.initialize(keyGenParameterSpec);
            console.log("KeyPairGenerator initialized");
            return keyPairGenerator.generateKeyPair();
        } else {
            console.log("EXISTING");
            let keyEntry: java.security.KeyStore.Entry = this.keyStore.getEntry(alias, null);
            let privateKey: java.security.PrivateKey = (<java.security.KeyStore.PrivateKeyEntry>keyEntry)
                .getPrivateKey();
            let publicKey: java.security.PublicKey = this.keyStore.getCertificate(alias).getPublicKey();
            return new java.security.KeyPair(publicKey, privateKey);
        }
    }

    private sign(privateKey: java.security.PrivateKey, data: native.Array<number>): native.Array<number> {
        //let s: java.security.Signature = java.security.Signature.getInstance("SHA256withRSA/PSS");
        let s: java.security.Signature = java.security.Signature.getInstance("SHA256withRSA");
        s.initSign(privateKey);
        s.update(data);
        return s.sign();
    }
}
