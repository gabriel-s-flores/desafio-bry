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
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
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
			KeyStoreException, CertificateException, UnrecoverableKeyException, OperatorCreationException, CMSException {
		SpringApplication.run(DesafiobryApplication.class, args);

		Security.addProvider(new BouncyCastleProvider());

		final InputStream doc = DesafiobryApplication.class.getClassLoader().getResourceAsStream("arquivos/doc.txt");
		final InputStream cert = DesafiobryApplication.class.getClassLoader()
				.getResourceAsStream("pkcs12/Desafio Estagio Java.p12");

		String txt = IOUtils.toString(doc, "utf8");

		System.out.println(txt);

		MessageDigest digest = MessageDigest.getInstance("SHA-256", "BC");

		byte[] hash = digest.digest(txt.getBytes(StandardCharsets.UTF_8));

		String sha256 = new String(Hex.encode(hash));

		System.out.println(sha256);


		String alias = "f22c0321-1a9a-4877-9295-73092bb9aa94";
		String password = "123456789";

		KeyStore keystore = KeyStore.getInstance("PKCS12");
		keystore.load(cert, password.toCharArray());
		PrivateKey key = (PrivateKey) keystore.getKey(alias,
				password.toCharArray());

		Certificate[] certchain = (Certificate[]) keystore.getCertificateChain(alias);
        final List<Certificate> certlist = new ArrayList<Certificate>();

		for (int i = 0, length = certchain == null ? 0 : certchain.length; i < length; i++) {
            certlist.add(certchain[i]);
        }

        Store<?> certstore = new JcaCertStore(certlist);
        Certificate certificate = keystore.getCertificate(alias);

		ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(key);

		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

		generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").
                build()).build(signer, (X509Certificate) certificate));
				
		generator.addCertificates(certstore);

		CMSTypedData cmsdata = new CMSProcessableByteArray(txt.getBytes());
		CMSSignedData signeddata = generator.generate(cmsdata, true);

		byte[] signedDocument = signeddata.getEncoded();

		FileUtils.writeByteArrayToFile(Paths.get("output", "signedtxt.p7s").toFile(), signedDocument);

		System.out.println(signedDocument);



	}

}
