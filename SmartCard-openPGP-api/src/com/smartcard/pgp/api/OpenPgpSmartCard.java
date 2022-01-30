package com.smartcard.pgp.api;


import java.io.ByteArrayOutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import com.smartcard.pgp.api.iso.APDU;
import com.smartcard.pgp.api.iso.ResponseParser;

public class OpenPgpSmartCard {

	private Card card;
	private CardChannel cardChannel;

	public OpenPgpSmartCard(Card card){
		this.card = card;
		cardChannel = card.getBasicChannel();
	}

	/**
	 * Tries to open the first terminal, if that fails, a IllegalArgumentException will be thrown 
	 * @return
	 * @throws CardException
	 */
	public static OpenPgpSmartCard getDefault() throws CardException {
		TerminalFactory terminalFactory = TerminalFactory.getDefault();
		List<CardTerminal> terminals = terminalFactory.terminals().list();
		//		CardTerminal terminal = terminals.firstOrNull() ?: throw new IllegalArgumentException("Terminal not found");
		if(terminals.isEmpty())
			throw new IllegalArgumentException("No terminal found");

		CardTerminal terminal = terminals.get(0);

		System.out.println("Connecting to " + terminal);  //TODO remove
		Card card = terminal.connect("T=1");

		return new OpenPgpSmartCard(card);
	}

	/**
	 * Tries to open a connection to a YubiKey. If no YubiKey is found, a IllegalArgumentException will be thrown 
	 * @return
	 * @throws CardException
	 */
	public static OpenPgpSmartCard getYubiKey() throws CardException, IllegalArgumentException {
		TerminalFactory terminalFactory = TerminalFactory.getDefault();
		List<CardTerminal> terminals = terminalFactory.terminals().list();
		CardTerminal terminal =null;
		for(int i=0; i<terminals.size(); i++){
			if(terminals.get(i).getName().toLowerCase().contains("yubico")){
				terminal = terminals.get(i);
				break;
			}
		}
		if(terminal == null)
			throw new IllegalArgumentException("Terminal not found");

		Card card = terminal.connect("T=1");

		return new OpenPgpSmartCard(card);
	}


	/**
	 * Selects the OpenPGP applet on the Card
	 * @throws CardException
	 */
	public void selectApplet() throws CardException {
		ResponseAPDU response = cardChannel.transmit(APDU.selectApplet());
		interpretResponse(response);
	}

	/**
	 * Verifies the pin-code on the Smart Card
	 * @param pinValue
	 * @throws CardException
	 */
	public void verify(String pinValue) throws CardException {
		ResponseAPDU response = cardChannel.transmit(APDU.verify(pinValue));
		try{
			interpretResponse(response);
		} catch (RuntimeException ex){
			throw new IllegalArgumentException("Password verification failed");
		}
	}

	/**
	 * Returns the Public Key from the Smart Card
	 * @return 
	 * @throws CardException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public PublicKey getPublicKey() throws CardException, NoSuchAlgorithmException, InvalidKeySpecException {
		ResponseAPDU response = cardChannel.transmit(APDU.getPublicKey());
		interpretResponse(response);

		return ResponseParser.parsePublicKey(response.getBytes());
	}


	/**
	 * The original implementation of decipher (from <a href=https://github.com/atok/smartcard-encrypt"> atok/smartcard-encrypt </a>
	 * @param encrypted
	 * @return
	 * @throws CardException
	 */
	public byte[] decipher(byte[] encrypted) throws CardException {
		if(encrypted.length != 256) 
			throw new IllegalArgumentException("Sorry, size has to be = 256");

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write(0);
		outputStream.write(encrypted, 0, 201);
		byte[] part1 = outputStream.toByteArray();

		ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream( );
		outputStream2.write(encrypted, 201, encrypted.length - 201);
		byte[] part2 = outputStream2.toByteArray();

		ResponseAPDU response1 = cardChannel.transmit(APDU.decipher(part1, true));
		interpretResponse(response1);

		ResponseAPDU response2 = cardChannel.transmit(APDU.decipher(part2));
		interpretResponse(response2);

		return response2.getData();
	}

	public void sign(byte[] bytes) throws CardException {
		ResponseAPDU signAnswer = cardChannel.transmit(APDU.sign(bytes));
		interpretResponse(signAnswer);
		System.out.println("Sign data $signAnswer");
	}

	public void disconnect() throws CardException {
		card.disconnect(true);
	}

	private void interpretResponse(ResponseAPDU response) {
		int sw1 = response.getSW1();
		int sw2 = response.getSW2();

		if(sw1 == 0x61){
			System.out.println("There is still " + sw2 + " bytes left to get");
		}
		if(sw1 == 0x90 || sw1 == 0x61) //0x90 =OK, 0x61 = more info
			return; //OK
		String msg = ResponseParser.message(sw1, sw2);

		throw new RuntimeException(response + "\n" + msg);
	}

	public byte[] getData(int tag1, int tag2) throws CardException{
		ResponseAPDU response = cardChannel.transmit(APDU.getData(tag1, tag2));
		interpretResponse(response);
		return response.getData();
	}

}