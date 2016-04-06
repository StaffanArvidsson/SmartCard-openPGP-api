package com.smartcard.pgp.api;

import java.io.IOException;
import java.nio.charset.Charset;
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

import org.junit.Assert;
import org.junit.Test;

import com.smartcard.pgp.api.CryptoTools;
import com.smartcard.pgp.api.OpenPgpSmartCard;



public class TestAPI {
	
	private static Charset charset = StandardCharsets.UTF_8;

	@Test
	public void testWithDES() throws CardException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		

		SecretKey symmetricKey = CryptoTools.desKeyGenerate();
		
		String msg1 = "This should be encrypted";
		String msg2 = "This String is VERY secret, do not tell it to anyone!";

		byte[] encryptedMessage = CryptoTools.desEncrypt(msg1.getBytes(charset), symmetricKey);
		byte[] encryptedMessage2 = CryptoTools.desEncrypt(msg2.getBytes(charset), symmetricKey);
		
		String msg1_result=null, msg2_result=null;

		OpenPgpSmartCard card = OpenPgpSmartCard.getYubiKey();

		try {
			card.selectApplet();
			card.verify("123456"); 
			
			PublicKey key = card.getPublicKey();
			byte[] encryptedKey = CryptoTools.rsaEncrypt(key, symmetricKey.getEncoded());

			//--------
			// YubiKey step
			byte[] decrypted = card.decipher(encryptedKey);

			//--------
			byte[] decryptedMessage = CryptoTools.desDecrypt(encryptedMessage, CryptoTools.desKeyFromBytes(decrypted));
			byte[] decryptedMessage2 = CryptoTools.desDecrypt(encryptedMessage2, CryptoTools.desKeyFromBytes(decrypted));
			msg1_result = new String(decryptedMessage, charset);
			msg2_result = new String(decryptedMessage2, charset);

		} catch(Exception e) {
			e.printStackTrace();
			Assert.fail();
		} finally {
			card.disconnect();
		}
		
		Assert.assertEquals(msg1, msg1_result);
		Assert.assertEquals(msg2, msg2_result);
		
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
