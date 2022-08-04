package com.desafio.desafiobry;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
@SpringBootApplication
public class DesafiobryApplication {

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		SpringApplication.run(DesafiobryApplication.class, args);
		

        final InputStream doc = DesafiobryApplication.class.getClassLoader().getResourceAsStream("arquivos/doc.txt");
        //final InputStream signatures = DesafiobryApplication.class.getClassLoader().getResourceAsStream("pkcs12/Desafio Estagio Java.p12");


		String txt = IOUtils.toString(doc, "utf8");

		System.out.println(txt);

		MessageDigest digest = MessageDigest.getInstance("SHA-256");

		byte[] hash = digest.digest(txt.getBytes(StandardCharsets.UTF_8));

		String sha256 = new String (Hex.encode(hash));

		System.out.println(sha256);

		

	}

}
