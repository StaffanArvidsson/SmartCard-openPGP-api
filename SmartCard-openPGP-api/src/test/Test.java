package test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import com.smartcard.pgp.api.CryptoTools;
import com.smartcard.pgp.api.OpenPgpSmartCard;

public class Test {
	
	private static Charset charset = StandardCharsets.UTF_8;
	
	public static void main(String[] args) throws Exception {
		SecretKey symmetricKey = CryptoTools.aesKeyGenerate();

		String msg1 = "very secret String";
		
		System.out.println("Attempting to encrypt the following string:\n" + msg1);
		
		byte[] encryptedMessage = CryptoTools.aesEncrypt(msg1.getBytes(charset), symmetricKey);
		System.out.println("The encrypted message:\n" + new String(encryptedMessage, charset));
		
		String msg1_result=null; 

		OpenPgpSmartCard card = OpenPgpSmartCard.getYubiKey();

		try {
			card.selectApplet();
			card.verify("123456"); 
			
			PublicKey key = card.getPublicKey();
			byte[] encryptedKey = CryptoTools.rsaEncrypt(key, symmetricKey.getEncoded());

			//--------
			// The card-stuff
			byte[] decryptedKey = card.decipher(encryptedKey);
			//--------
			
			byte[] decryptedMessage = CryptoTools.aesDecrypt(encryptedMessage, CryptoTools.aesKeyFromBytes(decryptedKey));

			msg1_result = new String(decryptedMessage, charset);

			System.out.println("The message was (after decrypting it):\n" + msg1_result);

		} catch(Exception e) {
			e.printStackTrace();
//			Assert.fail();
		} finally {
			card.disconnect();
		}
		
//		Assert.assertEquals(msg1, msg1_result);
//		Assert.assertEquals(msg2, msg2_result);
	}

}
