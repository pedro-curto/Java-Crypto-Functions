package pt.tecnico.crypto;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.Test;

/**
 * Test suite to show how the Java Security API can be used for MAC (Message
 * Authentication Codes).
 */
public class MACTest {

	/** Plain text to protect with the message authentication code. */
	final String plainText = "This is the plain text!";
	final String tamperedText = "This is tampered text!";
	/** Plain text bytes. */
	final byte[] plainBytes = plainText.getBytes();
	final byte[] tamperedBytes = tamperedText.getBytes();

	/** Symmetric cryptography algorithm. */
	private static final String SYM_ALGO = "AES";
	/** Symmetric algorithm key size. */
	private static final int SYM_KEY_SIZE = 128;

	/** Message authentication code algorithm. */
	private static final String MAC_ALGO = "HmacSHA256";

	/**
	 * Symmetric cipher: combination of algorithm, block processing, and padding.
	 */
	private static final String SYM_CIPHER = "AES/ECB/PKCS5Padding";
	/** Digest algorithm. */
	private static final String DIGEST_ALGO = "SHA-256";

	/**
	 * Generate a Message Authentication Code using the Mac object provided by Java
	 */
	@Test
	public void testMACObject() throws Exception {
		System.out.print("TEST '");
		System.out.print(MAC_ALGO);
		System.out.println("' message authentication code.");

		System.out.println("Text:");
		System.out.println(plainText);
		System.out.println("Bytes:");
		System.out.println(printHexBinary(plainBytes));

		// generate AES secret key
		SecretKey key = generateMACKey(SYM_KEY_SIZE);

		// make MAC
		System.out.println("Signing...");
		byte[] cipherDigest = makeMAC(plainBytes, key);
		System.out.println("CipherDigest:");
		System.out.println(printHexBinary(cipherDigest));

		// verify the MAC
		System.out.println("Verifying...");
		boolean result = verifyMAC(cipherDigest, plainBytes, key);
		System.out.println("MAC is " + (result ? "right" : "wrong"));
		assertTrue(result);

		System.out.println();
		System.out.println();
	}

	/** Generates a SecretKey for using in message authentication code. */
	private static SecretKey generateMACKey(int keySize) throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance(SYM_ALGO);
		keyGen.init(keySize);
		SecretKey key = keyGen.generateKey();

		return key;
	}

	/** Makes a message authentication code. */
	private static byte[] makeMAC(byte[] bytes, SecretKey key) throws Exception {
		Mac mac = Mac.getInstance(MAC_ALGO);
		mac.init(key);
		byte[] macBytes = mac.doFinal(bytes);

		return macBytes;
	}

	/**
	 * Calculates new digest from text and compare it to the to deciphered digest.
	 */
	private static boolean verifyMAC(byte[] receivedMacBytes, byte[] bytes, SecretKey key) throws Exception {
		Mac mac = Mac.getInstance(MAC_ALGO);
		mac.init(key);
		byte[] recomputedMacBytes = mac.doFinal(bytes);
		return Arrays.equals(receivedMacBytes, recomputedMacBytes);
	}

	/**
	 * Generate a Message Authentication Code by performing all the steps separately
	 * (for illustration purposes). It is better to use the Mac object.
	 */
	@Test
	public void testSignatureStepByStep() throws Exception {
		System.out.print("TEST step-by-step message authentication code using cipher '");
		System.out.print(SYM_CIPHER);
		System.out.print("' and digest '");
		System.out.print(DIGEST_ALGO);
		System.out.println("'");

		final byte[] plainBytes = plainText.getBytes();

		System.out.println("Text:");
		System.out.println(plainText);
		System.out.println("Bytes:");
		System.out.println(printHexBinary(plainBytes));

		// generate AES secret key
		SecretKey key = generateMACKey(SYM_KEY_SIZE);

		// make MAC
		System.out.println("Signing...");
		byte[] cipherDigest = digestAndCipher(plainBytes, key);
		System.out.println("CipherDigest:");
		System.out.println(printHexBinary(cipherDigest));

		// verify the MAC
		System.out.println("Verifying...");
		boolean result = redigestDecipherAndCompare(cipherDigest, plainBytes, key);
		System.out.println("MAC is " + (result ? "right" : "wrong"));
		assertTrue(result);

		System.out.println();
		System.out.println();
	}

	/** auxiliary method to calculate digest from text and cipher it */
	private static byte[] digestAndCipher(byte[] bytes, SecretKey key) throws Exception {

		// get a message digest object using the specified algorithm
		MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);

		// calculate the digest and print it out
		messageDigest.update(bytes);
		byte[] digest = messageDigest.digest();
		System.out.println("Digest:");
		System.out.println(printHexBinary(digest));

		// get an AES cipher object
		Cipher cipher = Cipher.getInstance(SYM_CIPHER);

		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherDigest = cipher.doFinal(digest);

		return cipherDigest;
	}

	/**
	 * auxiliary method to calculate new digest from text and compare it to the to
	 * deciphered digest
	 */
	private static boolean redigestDecipherAndCompare(byte[] cipherDigest, byte[] bytes, SecretKey key)
			throws Exception {

		// get a message digest object using the specified algorithm
		MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);

		// calculate the digest and print it out
		messageDigest.update(bytes);
		byte[] digest = messageDigest.digest();
		System.out.println("New digest:");
		System.out.println(printHexBinary(digest));

		// get an AES cipher object
		Cipher cipher = Cipher.getInstance(SYM_CIPHER);

		// decipher digest using the public key
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decipheredDigest = cipher.doFinal(cipherDigest);
		System.out.println("Deciphered Digest:");
		System.out.println(printHexBinary(decipheredDigest));

		// compare digests
		if (digest.length != decipheredDigest.length)
			return false;

		for (int i = 0; i < digest.length; i++)
			if (digest[i] != decipheredDigest[i])
				return false;
		return true;
	}


	@Test
	public void testTamperDetectionMAC() throws Exception {
		// generate secret key and MAC for plain text
		SecretKey key = generateMACKey(SYM_KEY_SIZE);
		byte[] originalMAC = makeMAC(plainBytes, key);

		// alter the message
		byte[] tamperedMessage = tamperedBytes;

		// attempt to verify the MAC with the tampered message
		boolean isValid = verifyMAC(originalMAC, tamperedMessage, key);

		// output result and assert that the verification should fail
		System.out.println("MAC verification result: " + (isValid ? "Valid" : "Tampered!"));
		assertFalse(isValid, "MAC verification must fail for tampered data");
	}

	@Test
	public void testMACWithNonce() throws Exception {
		System.out.print("TEST '");
		System.out.print(MAC_ALGO);
		System.out.println("' message authentication code with nonce.");

		// registry for used nonces
		Set<String> nonceRegistry = new HashSet<>();

		// generate key and nonce
		SecretKey key = generateMACKey(SYM_KEY_SIZE);
		byte[] nonce = generateNonce();
		String nonceHex = printHexBinary(nonce);
		System.out.println("Nonce: ");
		System.out.println(nonceHex);

		// append nonce to plaintext
		byte[] msgWithNonce = concatenate(plainBytes, nonce);
		System.out.println("Text with nonce: ");
		System.out.println(printHexBinary(msgWithNonce));

		// compute MAC with nonce
		System.out.println("Computing MAC with nonce...");
		byte[] macWithNonce = makeMAC(msgWithNonce, key);
		System.out.print("MAC: ");
		System.out.println(printHexBinary(macWithNonce));

		// simulate verification and add to registry
		System.out.println("Verifying...");
		boolean isReplay = nonceRegistry.contains(nonceHex); // Check if nonce is reused
		boolean isValid = verifyMAC(macWithNonce, msgWithNonce, key) && !isReplay;
		System.out.println("MAC verification result: " + (isValid ? "Valid" : "Replay Attack Detected"));
		nonceRegistry.add(nonceHex);

		assertTrue(isValid, "MAC must match for untampered data and fresh nonce");

		// simulate replay attack by reusing the same nonce
		System.out.println("Simulating replay attack...");
		byte[] replayedMessageWithNonce = concatenate(plainBytes, nonce);
		boolean isReplayAttack = nonceRegistry.contains(nonceHex); // Nonce already in registry

		// replay detection logic
		assertTrue(isReplayAttack, "Replay attack must fail due to reused nonce");
		System.out.println("Replay attack detected: " + (isReplayAttack ? "Yes" : "No"));
	}

	private byte[] generateNonce() {
		byte[] nonce = new byte[16];
		SecureRandom random = new SecureRandom();
		random.nextBytes(nonce);
		return nonce;
	}

	private static byte[] concatenate(byte[] nonce, byte[] data) {
		byte[] result = new byte[nonce.length + data.length];
		System.arraycopy(nonce, 0, result, 0, nonce.length);
		System.arraycopy(data, 0, result, nonce.length, data.length);
		return result;
	}
}
