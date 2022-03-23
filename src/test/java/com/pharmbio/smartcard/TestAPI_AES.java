package com.pharmbio.smartcard;


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

import com.pharmbio.smartcard.utils.CryptoTools;

import org.junit.Assert;
import org.junit.Test;



public class TestAPI_AES {
	
	private static Charset charset = StandardCharsets.UTF_8;
	
	@Test
	public void testAES_WithYubikey() throws CardException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {

		SecretKey symmetricKey = CryptoTools.aesKeyGenerate();

		String msg1 = "This should be encrypted";
		String msg2 = "This String is VERY secret, do not tell it to anyone!";
		
//		byte[] message = ;
		byte[] encryptedMessage = CryptoTools.aesEncrypt(msg1.getBytes(charset), symmetricKey);
		byte[] encryptedMessage2 = CryptoTools.aesEncrypt(msg2.getBytes(charset), symmetricKey);
//		System.out.println("The encrypted message:\n" + new String(encryptedMessage, StandardCharsets.UTF_8));
		
		String msg1_result=null, msg2_result=null;

		OpenPgpSmartCard card = OpenPgpSmartCard.getYubiKey();

		try {
			card.selectApplet();
			card.verify("123456"); 
			
			PublicKey key = card.getPublicKey();
			byte[] encryptedKey = CryptoTools.rsaEncrypt(key, symmetricKey.getEncoded());

			//--------

			byte[] decryptedKey = card.decipher(encryptedKey);

			byte[] decryptedMessage = CryptoTools.aesDecrypt(encryptedMessage, CryptoTools.aesKeyFromBytes(decryptedKey));
			byte[] decryptedMessage2 = CryptoTools.aesDecrypt(encryptedMessage2, CryptoTools.aesKeyFromBytes(decryptedKey));
			msg1_result = new String(decryptedMessage, charset);
			msg2_result = new String(decryptedMessage2, charset);
//			System.out.println("The message was:\n" + new String(decryptedMessage, StandardCharsets.UTF_8));

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
