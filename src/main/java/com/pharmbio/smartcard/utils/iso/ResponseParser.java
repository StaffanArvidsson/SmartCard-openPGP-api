package com.pharmbio.smartcard.utils.iso;


import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import com.pharmbio.smartcard.utils.OffsetBytes;


public class ResponseParser {

	/**
	 * Parses a Public Key given from the Smart Card
	 * @param byteArray
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PublicKey parsePublicKey(byte[] byteArray) throws NoSuchAlgorithmException, InvalidKeySpecException {
		OffsetBytes bytes = new OffsetBytes(byteArray, 0);

		if(!bytes.check(0x7f, 0x49)) 
			throw new IllegalArgumentException("Expecting 0x7f 0x49");

		readLength(bytes);

		if(!bytes.check(0x81)) 
			throw new IllegalArgumentException("Expecting 0x81 - modulus");

		int modulusLength = readLength(bytes);
		byte[] modulusBytes = bytes.next(modulusLength);

		if(!bytes.check(0x82)) 
			throw new IllegalArgumentException("Expecting 0x82 - exponent");

		int exponentLength = bytes.nextAsInt();
		byte[] exponentBytes = bytes.next(exponentLength);

		if(!bytes.check(0x90, 0x00))
			throw new IllegalArgumentException("Expecting 0x90 0x00");

		RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(hexString(modulusBytes), 16), new BigInteger(hexString(exponentBytes), 16));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");

		return keyFactory.generatePublic(spec);
	}

	/**
	 * Parses status-bytes given from the SmartCard. Codes taken from <a href=http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4_5_basic_organizations.aspx">CardWerk</a>
	 * @param sw1
	 * @param sw2
	 * @return
	 */
	public static String message(int sw1, int sw2) {
		String output = "";

		switch(sw1){
		case 0x90: output = "OK"; break;
		case 0x61: output = "OK, " + sw2 + " bytes still availiable"; break;
		case 0x62: 
			output = "WARNING: State of non-volatile memory unchanged, ";
			switch(sw2){
			case 0x00: break;
			case 0x81: output += "Part of returned data may be corrupted"; break;
			case 0x82: output += "End of file/record reached before reading Le bytes"; break;
			case 0x83: output += "Selected file invalidated"; break;
			case 0x84: output += "FCI not formatted according to 1.1.5"; break;
			default: output += "?"; break;
			}
			break;
		case 0x63:
			output = "WARNING: State of non-volatile memory changed, ";
			switch(sw2) {
			case 0x00: break;
			case 0x81: output += "File filled up by the last write"; break;
			default: output += "?"; break;
			}
			break;
		case 0x65: 
			if(sw2 == 0x00) 
				output = "WARNING: State of non-volatile memory changed";
			else if(sw2 == 0x81)
				output = "WARNING: State of non-volatile memory changed, Memory failure";
			else 
				output = "WARNING: State of non-volatile memory changed, ?";
			break;
		case 0x68: 
			output = "Functions in CLA not supported";
			if(sw2 == 0x00)
				output += ", no further information given";
			else if (sw2 == 0x81)
				output += ", Logical channel not supported";
			else if(sw2 == 0x82)
				output += ", Secure messaging not supported";
			break;
		case 0x69: output = "Command not allowed, ";
		
		switch(sw2) {
		case 0x00: break;
		case 0x81: output += "Command incompatible with file structure"; break;
		case 0x82: output += "Security status not satisfied"; break;
		case 0x83: output += "Authentication method blocked"; break;
		case 0x84: output += "Referenced data invalidated"; break;
		case 0x85: output += "Conditions of use not satisfied"; break;
		case 0x86: output += "Command not allowed (no current EF)"; break;
		case 0x87: output += "Expected SM data objects missing"; break;
		case 0x88: output += "SM data objects incorrect"; break;
		default: output += "?"; break;
		}
		break;
		case 0x6a: output = "Wrong parameter(s)"; 
		switch(sw2) {
		case 0x00: output += ", No other information given"; break;
		case 0x80: output += ", Incorrect parameters in the data field";break;
		case 0x81: output += ", Function not supported"; break;
		case 0x82: output += ", File not found"; break;
		case 0x83: output += ", Record not found"; break;
		case 0x84: output += ", Not enough memory space in the file"; break;
		case 0x85: output += ", Lc inconsistent with TLV structure"; break;
		case 0x86: output += ", Incorrect parameters P1-P2"; break;
		case 0x87: output += ", Lc inconsistent with P1-P2"; break;
		case 0x88: output += ", Referenced data not found"; break;
		}
		break;
		case 0x6b: output = "Wrong parameters(s) P1 P2";
		break;
		case 0x6c: output = "Wrong length of Le, the correct should be: " + sw2; 
		break;
		case 0x6d: output = "Instruction code not supported or invalid"; 
		break;
		case 0x6e: output = "Class not supported"; 
		break;
		case 0x6f: output = "No precise diagnosis"; 
		break;
		default: output = "?"; break;
		}

		return output;
	}

	private static String hexString(byte[] bytes) {
		StringBuilder output = new StringBuilder();
		for(int i=0;i<bytes.length; i++){
			String asHex = Integer.toHexString(bytes[i] & 0xff);
			if(asHex.length() == 1){
				asHex = "0" + asHex;
			}
			output.append(asHex);	
		}
		return output.toString();
	}

	private static int readLength(OffsetBytes bytes) {
		int result;
		switch(bytes.next()){
		case (byte) 0x81: result = bytes.next() & 0xff; break;
		case (byte) 0x82: result = (bytes.next() & 0xff)*256 + (bytes.next() & 0xff); break;
		default: throw new IllegalArgumentException("Expecting 0x81 or 0x82");
		}
		return result;
		//		return when(bytes.next()) {
		//			0x81.toByte() -> bytes.next().toInt() and 0xff
		//			0x82.toByte() -> (bytes.next().toInt() and 0xff) * 256 + (bytes.next().toInt() and 0xff)
		//			else -> throw IllegalArgumentException("Expecting 0x81 or 0x82")
		//		}
	}
}