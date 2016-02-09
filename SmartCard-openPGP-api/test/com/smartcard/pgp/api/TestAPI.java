package com.smartcard.pgp.api;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.smartcardio.CardException;

import com.smartcard.pgp.api.CryptoTools;
import com.smartcard.pgp.api.OpenPgpSmartCard;



public class TestAPI {
	

	public static void main(String[] args) throws CardException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		
		CryptoTools.enableBouncyCastle();

		SecretKey symmetricKey = CryptoTools.desKeyGenerate();

		byte[] message = "This should be encrypted".getBytes();
		byte[] encryptedMessage = CryptoTools.desEncrypt(message, symmetricKey);

		OpenPgpSmartCard card = OpenPgpSmartCard.getYubiKey();

		try {
			card.selectApplet();
			card.verify("123456"); 
			
			PublicKey key = card.getPublicKey();
			byte[] encryptedKey = CryptoTools.rsaEncrypt(key, symmetricKey.getEncoded());

			//--------

			byte[] decrypted = card.decipher_original(encryptedKey);

			byte[] decryptedMessage = CryptoTools.desDecrypt(encryptedMessage, CryptoTools.desKeyFromBytes(decrypted));
			System.out.println("The message was:\n" + new String(decryptedMessage, StandardCharsets.UTF_8));

		} catch(Exception e) {
			e.printStackTrace();
		} finally {
			card.disconnect();
		}
	}

	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}

}
