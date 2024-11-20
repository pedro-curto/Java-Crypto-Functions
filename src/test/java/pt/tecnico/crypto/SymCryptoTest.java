package pt.tecnico.crypto;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.Test;

public class SymCryptoTest {
	/** Plain text to cipher. */
	private final String plainText = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	private final String stringForTime = "A".repeat(200);
	private final byte[] bytesForTime = stringForTime.getBytes();
	/** Plain text bytes. */
	private final byte[] plainBytes = plainText.getBytes();

	/** Symmetric cryptography algorithm. */
	private static final String SYM_ALGO = "AES";
	/** Symmetric algorithm key size. */
	private static final int SYM_KEY_SIZE = 128;
	/**
	 * Symmetric cipher: combination of algorithm, block processing, and padding.
	 */
	private static final String SYM_CIPHER_ECB = "AES/ECB/PKCS5Padding";
	private static final String SYM_CIPHER_CBC = "AES/CBC/PKCS5Padding";

	/**
	 * Secret key cryptography test.
	 * 
	 * @throws Exception because test is not concerned with exception handling
	 */
	@Test
	public void testSymCryptoECB() throws Exception {
		System.out.print("TEST '");
		System.out.print(SYM_CIPHER_ECB);
		System.out.println("'");

		System.out.println("Text:");
		System.out.println(plainText);
		System.out.println("Bytes:");
		System.out.println(printHexBinary(plainBytes));

		// get a AES private key
		System.out.println("Generating AES key...");
		KeyGenerator keyGen = KeyGenerator.getInstance(SYM_ALGO);
		keyGen.init(SYM_KEY_SIZE);
		Key key = keyGen.generateKey();
		System.out.print("Key: ");
		System.out.println(printHexBinary(key.getEncoded()));

		// get a AES cipher object and print the provider
		Cipher cipher = Cipher.getInstance(SYM_CIPHER_ECB);
		System.out.println(cipher.getProvider().getInfo());

		// encrypt using the key and the plain text
		System.out.println("Ciphering...");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherBytes = cipher.doFinal(plainBytes);
		System.out.print("Result: ");
		System.out.println(printHexBinary(cipherBytes));

		// decipher the cipher text using the same key
		System.out.println("Deciphering...");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] newPlainBytes = cipher.doFinal(cipherBytes);
		System.out.print("Result: ");
		System.out.println(printHexBinary(newPlainBytes));

		System.out.println("Text:");
		String newPlainText = new String(newPlainBytes);
		System.out.println(newPlainText);

		assertEquals(plainText, newPlainText);

		System.out.println();
		System.out.println();
	}

	@Test
	public void testSymCryptoCBC() throws Exception {
		System.out.print("TEST '");
		System.out.print(SYM_CIPHER_CBC);
		System.out.println("'");

		System.out.println("Text:");
		System.out.println(plainText);
		System.out.println("Bytes:");
		System.out.println(printHexBinary(plainBytes));

		// get a AES private key
		System.out.println("Generating AES key...");
		KeyGenerator keyGen = KeyGenerator.getInstance(SYM_ALGO);
		keyGen.init(SYM_KEY_SIZE);
		Key key = keyGen.generateKey();
		System.out.print("Key: ");
		System.out.println(printHexBinary(key.getEncoded()));

		// generate initialization vector (IV)
		IvParameterSpec ivSpec = generateIv();
		System.out.print("IV: ");
		System.out.println(printHexBinary(ivSpec.getIV()));

		// get a AES cipher object and print the provider
		Cipher cipher = Cipher.getInstance(SYM_CIPHER_CBC);
		System.out.println(cipher.getProvider().getInfo());

		// encrypt using the key and the plain text
		System.out.println("Ciphering...");
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		byte[] cipherBytes = cipher.doFinal(plainBytes);
		System.out.print("Result: ");
		System.out.println(printHexBinary(cipherBytes));

		// decipher the cipher text using the same key
		System.out.println("Deciphering...");
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		byte[] newPlainBytes = cipher.doFinal(cipherBytes);
		System.out.print("Result: ");
		System.out.println(printHexBinary(newPlainBytes));

		System.out.println("Text:");
		String newPlainText = new String(newPlainBytes);
		System.out.println(newPlainText);

		assertEquals(plainText, newPlainText);

		System.out.println();
		System.out.println();
	}

	@Test
	public void testSymCryptoECBWithTiming() throws Exception {
		System.out.print("TEST '");
		System.out.print(SYM_CIPHER_ECB);
		System.out.println("' with timing");

		System.out.println("Text:");
		System.out.println(stringForTime);
		System.out.println("Bytes:");
		System.out.println(printHexBinary(bytesForTime));

		long startTime, endTime;
		long keyGenTime, encryptionTime, decryptionTime;

		startTime = System.nanoTime();
		KeyGenerator keyGen = KeyGenerator.getInstance(SYM_ALGO);
		keyGen.init(SYM_KEY_SIZE);
		Key key = keyGen.generateKey();
		endTime = System.nanoTime();
		keyGenTime = endTime - startTime;
		System.out.println("Key generation time (ns): " + keyGenTime);

		Cipher cipher = Cipher.getInstance(SYM_CIPHER_ECB);

		// encryption timing
		startTime = System.nanoTime();
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherBytes = cipher.doFinal(bytesForTime);
		endTime = System.nanoTime();
		encryptionTime = endTime - startTime;
		System.out.println("Encryption time (ns): " + encryptionTime);

		// decryption timing
		startTime = System.nanoTime();
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] newPlainBytes = cipher.doFinal(cipherBytes);
		endTime = System.nanoTime();
		decryptionTime = endTime - startTime;
		System.out.println("Decryption time (ns): " + decryptionTime);

		// verify result
		String newPlainText = new String(newPlainBytes);
		assertEquals(stringForTime, newPlainText);

		// output total times
		System.out.println("AES Key Generation Time (ns): " + keyGenTime);
		System.out.println("AES Encryption Time (ns): " + encryptionTime);
		System.out.println("AES Decryption Time (ns): " + decryptionTime);
	}


	public static IvParameterSpec generateIv() {
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}
}
