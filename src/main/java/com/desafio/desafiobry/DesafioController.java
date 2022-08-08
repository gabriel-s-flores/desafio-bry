package com.desafio.desafiobry;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class DesafioController {

    @PostMapping("/verify")
    String verify(@RequestParam("doc") MultipartFile doc) throws OperatorCreationException, CMSException, IOException, CertificateException{

        CMSSignedDataParser work = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider("BC").
        build(), doc.getInputStream());

        work.getSignedContent().drain();
        Store<?> store = work.getCertificates(); 
        SignerInformationStore signers = work.getSignerInfos(); 
        Collection<?> c = signers.getSigners(); 
        Iterator<?> it = c.iterator();
        while (it.hasNext()) { 
            SignerInformation sig = (SignerInformation)it.next(); 
            Collection<?> certCollection = store.getMatches(sig.getSID()); 
            Iterator<?> certIt = certCollection.iterator();
            X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
            X509Certificate certFromSignedData = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
            try{
			if (sig.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certFromSignedData))) {
                System.out.println("Signature verified");
            } else {
                System.out.println("Signature verification failed");
                return "INVALIDO";
            }
			}catch(Exception e){
				System.out.println("Invalid Certificate");
                return "INVALIDO";
			}
        }
        
        return "VALIDO";
    }

    @PostMapping("/signature")
    String signature(@RequestParam("txt") MultipartFile txt, @RequestParam("sig")MultipartFile sig, @RequestParam("password") String password) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException, CMSException{
        String alias = "f22c0321-1a9a-4877-9295-73092bb9aa94";

		KeyStore keystore = KeyStore.getInstance("PKCS12");
		keystore.load(sig.getInputStream(), password.toCharArray());
		PrivateKey key = (PrivateKey) keystore.getKey(alias,
				password.toCharArray());

        Certificate certificate = keystore.getCertificate(alias);

		ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSAEncryption").setProvider("BC").build(key);

		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

		generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").
                build()).build(signer, (X509Certificate) certificate));
				
		generator.addCertificate(new X509CertificateHolder(certificate.getEncoded()));

		CMSTypedData cmsdata = new CMSProcessableByteArray(txt.getBytes());
		CMSSignedData signeddata = generator.generate(cmsdata, true);

		byte[] signedDocument = signeddata.getEncoded();

        
        return Base64.getEncoder().encodeToString(signedDocument);

        
    }

}
