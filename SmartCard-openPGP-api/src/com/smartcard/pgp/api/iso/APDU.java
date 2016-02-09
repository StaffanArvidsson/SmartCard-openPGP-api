package com.smartcard.pgp.api.iso;

import java.nio.charset.StandardCharsets;

import javax.smartcardio.CommandAPDU;

public class APDU {
	// CLA INS PI P2 LC CDATA
	private static final byte[] OPEN_PGP_AID = {(byte)0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};

	public enum Pin { Pin1, Pin2 };

	//TODO 0x81
	public static CommandAPDU verify(String pin){
		return verify(pin, 0x82);
	}

	public static CommandAPDU verify(String pin, int p2) {
		if(p2 != 0x82 && p2 != 0x81 && p2 != 0x83)
			throw new IllegalArgumentException("only 0x81 and 0x82 allowed for PIN verification");
		if((p2 == 0x81 || p2 == 0x82) && (pin.length()< 4 || pin.length() > 8))
			throw new IllegalArgumentException("PIN must be 4 to 8 chars long (ASCII format)");
		byte[] header = {0x00, 0x20, 0x00, (byte) p2, (byte) pin.length()};
		byte[] body = pin.getBytes(StandardCharsets.UTF_8);
		byte[] data = new byte[header.length + body.length];
		System.arraycopy(header, 0, data, 0, header.length);
		System.arraycopy(body, 0, data, header.length, body.length);

		return new CommandAPDU(data);
	}

	public static CommandAPDU sign(byte[] body) {
		byte[] header = {0x00, 0x2a, (byte) 0x9e, (byte) 0x9a, (byte) body.length};

		byte[] data = new byte[header.length + body.length + 1];
		System.arraycopy(header, 0, data, 0, header.length);
		System.arraycopy(body, 0, data, header.length, body.length);
		data[data.length] = 0x00;
		//      return CommandAPDU(bytes(0x00, 0x2a, 0x9e, 0x9a, data.size) + data + bytes(0x00))
		return new CommandAPDU(data);
	}


	public static CommandAPDU decipher(byte[] data){
		return decipher(data, false);
	}

	public static CommandAPDU decipher(byte [] data, boolean chain) {
		int length = data.length;

		byte lenBytes = (byte ) length; 

		byte cla;
		if(chain) 
			cla = 0x10; 
		else 
			cla = 0x00;
		byte[] header = {cla, 0x2a, (byte) 0x80, (byte) 0x86, lenBytes};
		byte[] bytes = new byte[data.length + 6];

		System.arraycopy(header, 0, bytes, 0, header.length);
		System.arraycopy(data, 0, bytes, header.length, data.length);

		bytes[bytes.length-1] = 0x00;

		return new CommandAPDU(bytes);
	}



	public static CommandAPDU decipher_all_in_one(byte [] data) {
		int length = data.length +1 +1; // +1 for the 0x00 indicating RSA, +1 for Le
		byte[] header = null;

		if(length >= 256){
			// Lc is here 0x00 and b1 + b2
			byte b1 = (byte) ((length >> 8) & 0xFF);
			byte b2 = (byte) (length & 0xFF);
			header = new byte[]{0x00, 0x2a, (byte) 0x80, (byte) 0x86, 0x00, b1, b2, 0x00}; //last 0x00 is for indicating RSA

		} else {
			// Lc is only the first byte now!
			byte lenBytes = (byte ) length; 
			header = new byte[]{0x00, 0x2a, (byte) 0x80, (byte) 0x86, lenBytes, 0x00}; //last 0x00 is for indicating RSA
		}

		byte[] bytes = new byte[header.length + data.length + 1]; // +1 for Le= 0x00

		System.arraycopy(header, 0, bytes, 0, header.length);
		System.arraycopy(data, 0, bytes, header.length, data.length);

		bytes[bytes.length-1] = 0x00; //Le (get all)

		return new CommandAPDU(bytes);
	}

	public static CommandAPDU decipher_break_into_two(byte[] data, boolean chain){
		int length = data.length;

		byte lenBytes = (byte ) (length +1); // should be 0x00 padding before key, to specify RSA

		byte cla;
		if(chain) 
			cla = 0x10; 
		else 
			cla = 0x00;
		byte[] header = {cla, 0x2a, (byte) 0x80, (byte) 0x86, lenBytes, 0x00}; // added 0x00 in the end for RSA
		byte[] bytes = new byte[data.length + header.length + 1];

		System.arraycopy(header, 0, bytes, 0, header.length);
		System.arraycopy(data, 0, bytes, header.length, data.length);
		bytes[bytes.length-1] = 0x00;
		return new CommandAPDU(bytes);
	}

	public static CommandAPDU selectApplet(){
		return selectApplet(OPEN_PGP_AID);
	}

	public static CommandAPDU selectApplet(byte[] aid) {
		return new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid);
	}

	public static CommandAPDU getPublicKey() {
		// Page 58 in OpenPGP 3.0 manual
		return new CommandAPDU(new byte[]{0x00, 0x47, (byte) 0x81, 0x00, 0x02, (byte) 0xB8, 0x00});
	}

	// TODO: use this instead of the System.arraycopy?
	private static byte[] getByteArr(int... byteArray) {
		byte[] bytes = new byte[byteArray.length];
		for(int i=0; i< byteArray.length; i++){
			if(byteArray[i] >255){
				throw new IllegalArgumentException("Value to big: "+ byteArray[i]);
			}
			bytes[i] = (byte) byteArray[i];
		}

		return bytes;
	}

	public static CommandAPDU getData(int tag1, int tag2) {
		byte[] bytes = {0x00, (byte) 0xca,(byte)tag1, (byte)tag2, 0x00};
		return new CommandAPDU(bytes);
	}

	final private static char[] hexArray = "0123456789ABCDEF".toCharArray();
	private static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for ( int j = 0; j < bytes.length; j++ ) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
}
