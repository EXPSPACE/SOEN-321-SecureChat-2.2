package codebase;

import java.io.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import java.security.*;
import java.util.Arrays;

/* Author : Sebastian Rafique Proctor-Shah
 * SID# : 29649727
 */

public class Encryption {

	// function that uses SHA-256 hashing algorithm to compute hash value
	public static byte[] getPasswordHash(String password) {
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
			messageDigest.update(password.getBytes("UTF-8"));
			byte[] digest = messageDigest.digest();
			// converts byte array to hex string
			return digest;
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}

	// function uses SHAH-256 hashing algorithm to generate a valid AES 128 bit keyfrom the users password
	public static SecretKey getKeyFromPassword(String password) {
		byte[] key = getPasswordHash(password);
		// take the first 16 bytes for a 128 bit AES key
		key = Arrays.copyOf(key, 16);
		return new SecretKeySpec(key, "AES");
	}

	//decrypts the log encryption key sent from the server using the hash of the users password
	public static SecretKey getLogEncryptionKey(SecretKey keyPass, byte[] eLogKey) {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/ECB/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, keyPass);
			byte[] key = cipher.doFinal(eLogKey);
			return new SecretKeySpec(key, "AES");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static OutputStream getEncryptionStream(String fileLocation, SecretKey key, String curUser) {
		Cipher cipher;
		OutputStream outputStream = null;

		byte[] iv = retrieveIV("log/" + curUser + ".iv");

		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
			outputStream = new CipherOutputStream(new FileOutputStream(
					fileLocation), cipher);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		return outputStream;

	}

	public static InputStream getDecryptionStream(String fileLocation, SecretKey key, String curUser) {
		Cipher cipher;
		InputStream inputStream = null;

		byte[] iv = retrieveIV("log/" + curUser + ".iv");

		try {

			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
			inputStream = new CipherInputStream(new FileInputStream(
					fileLocation), cipher);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			System.err.println("Chatlog file could not be opened.");
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}

		return inputStream;

	}

	//gets unique 16 byte initialization vector from a user iv file
	public static byte[] retrieveIV(String fileLocation) {

		byte[] iv = new byte[16];
		try {
			FileInputStream findIV = new FileInputStream(fileLocation);
			findIV.read(iv);
			findIV.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return iv;
	}

	// utility methods
	public static String convertToHex(byte[] digest) {
		return String.format("%064x", new java.math.BigInteger(1, digest));
	}

	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character
					.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

}