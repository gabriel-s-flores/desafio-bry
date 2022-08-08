package com.desafio.desafiobry;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DesafiobryApplication {

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
			KeyStoreException, CertificateException, UnrecoverableKeyException, OperatorCreationException,
			CMSException {
		SpringApplication.run(DesafiobryApplication.class, args);

		
		//add Bouncy Castle as a Security Provider
		Security.addProvider(new BouncyCastleProvider());
		
		//getting the certificate and text file as an inputstream
		final InputStream doc = DesafiobryApplication.class.getClassLoader().getResourceAsStream("arquivos/doc.txt");
		final InputStream cert = DesafiobryApplication.class.getClassLoader()
				.getResourceAsStream("pkcs12/Desafio Estagio Java.p12");
		
		//Step 1 getting the hash sha-256 algorithm
		String txt = IOUtils.toString(doc, "utf8");

		System.out.println(txt);

		MessageDigest digest = MessageDigest.getInstance("SHA-256", "BC");

		byte[] hash = digest.digest(txt.getBytes(StandardCharsets.UTF_8));

		String sha256 = new String(Hex.encode(hash));

		System.out.println(sha256);
		

		//Step 2 Signing the doc.txt file
		String alias = "f22c0321-1a9a-4877-9295-73092bb9aa94";
		String password = "123456789";

		KeyStore keystore = KeyStore.getInstance("PKCS12");
		keystore.load(cert, password.toCharArray());
		PrivateKey key = (PrivateKey) keystore.getKey(alias,
				password.toCharArray());

		Certificate certificate = keystore.getCertificate(alias);

		ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSAEncryption").setProvider("BC").build(key);

		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

		generator.addSignerInfoGenerator(
				new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
						.build(signer, (X509Certificate) certificate));

		generator.addCertificate(new X509CertificateHolder(certificate.getEncoded()));

		CMSTypedData cmsdata = new CMSProcessableByteArray(txt.getBytes());
		CMSSignedData signeddata = generator.generate(cmsdata, true);

		byte[] signedDocument = signeddata.getEncoded();

		FileUtils.writeByteArrayToFile(Paths.get("output", "signedtxt.p7s").toFile(), signedDocument);
		

		//Step 3 Verifying signature
		Store<?> store = signeddata.getCertificates();
		SignerInformationStore signers = signeddata.getSignerInfos();
		Collection<?> c = signers.getSigners();
		Iterator<?> it = c.iterator();
		while (it.hasNext()) {
			SignerInformation sig = (SignerInformation) it.next();
			Collection<?> certCollection = store.getMatches(sig.getSID());
			Iterator<?> certIt = certCollection.iterator();
			X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
			X509Certificate certFromSignedData = new JcaX509CertificateConverter().setProvider("BC")
					.getCertificate(certHolder);
			try {
				if (sig.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certFromSignedData))) {
					System.out.println("Signature verified");
				} else {
					System.out.println("Signature verification failed");
				}
			} catch (Exception e) {
				System.out.println("Invalid Certificate");
			}

		}

	}

}
