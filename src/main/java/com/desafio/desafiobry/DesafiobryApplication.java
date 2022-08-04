package com.desafio.desafiobry;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DesafiobryApplication {

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
		SpringApplication.run(DesafiobryApplication.class, args);

		Security.addProvider(new BouncyCastleProvider());
		

		final InputStream doc = DesafiobryApplication.class.getClassLoader().getResourceAsStream("arquivos/doc.txt");
	

		String txt = IOUtils.toString(doc, "utf8");

		System.out.println(txt);

		MessageDigest digest = MessageDigest.getInstance("SHA-256", "BC");

		byte[] hash = digest.digest(txt.getBytes(StandardCharsets.UTF_8));

		String sha256 = new String(Hex.encode(hash));

		System.out.println(sha256);

	}

}
