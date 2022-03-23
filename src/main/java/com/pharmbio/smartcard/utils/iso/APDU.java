package com.pharmbio.smartcard.utils.iso;

import java.nio.charset.StandardCharsets;

import javax.smartcardio.CommandAPDU;

public class APDU {
	// CLA INS PI P2 LC CDATA
	private static final byte[] OPEN_PGP_AID = {(byte)0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};

	//TODO 0x81
	public static CommandAPDU verify(String pin){
		return verify(pin, 0x82);
	}

	public static CommandAPDU verify(String pin, int p2) {
		if (p2 != 0x82 && p2 != 0x81 && p2 != 0x83)
			throw new IllegalArgumentException("only 0x81, 0x82 o 0x83 allowed for PIN verification");
		if ((p2 == 0x81 || p2 == 0x82) && (pin.length()< 4 || pin.length() > 8))
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
		return new CommandAPDU(data);
	}


	public static CommandAPDU decipher(byte[] data){
		return decipher(data, false);
	}

	public static CommandAPDU decipher(byte [] data, boolean chain) {

		byte cla;
		if (chain) 
			cla = 0x10; 
		else 
			cla = 0x00;
		byte[] header = {cla, 0x2a, (byte) 0x80, (byte) 0x86, (byte) data.length};
		byte[] bytes = new byte[data.length + 6];

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

	public static CommandAPDU getData(int tag1, int tag2) {
		byte[] bytes = {0x00, (byte) 0xca,(byte)tag1, (byte)tag2, 0x00};
		return new CommandAPDU(bytes);
	}

}
