package com.java.smartcard.acr122u;

import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import org.apache.log4j.Logger;

import com.java.smartcard.acr122u.exception.CardDataException;
import com.java.smartcard.acr122u.util.ACR122Util;

/**
 * 
 * @author Sujith Ramanathan
 * <br><br>
 * 
 * <li>ACR122U Reader Helper Utility is used to read,write,encrypt and decrypt Mifare Classic 1k Cards only.</li>
 */

public class ACR122UReaderHelper {

	/** ACR122UReaderHelper Instance **/
	private static ACR122UReaderHelper instance;
	
	/** ACR122UReaderHelper Logger **/
	private Logger logger = Logger.getLogger(ACR122UReaderHelper.class);
	
	private final ACR122Util util = ACR122Util.getInstance();
 	
 	/** Card Terminal **/
 	private CardTerminal terminal;
 	
 	/** Card which is placed on the card reader **/
 	private Card card;
 	
 	/** ACR122UReaderHelper constructor **/
	private ACR122UReaderHelper(){}
	
	public static ACR122UReaderHelper getInstance(){
		if(null==instance){
			instance = new ACR122UReaderHelper();
		}
		return instance;
	}

	/**	 
	 * @return boolean
	 * 
	 * <li>This method will return true, If it is connected to ACR122U Reader.</li>
	 */
	public boolean connectReader()throws CardException{ 
		final List<CardTerminal> cardTerminal = getReaderList();
		if(null!=cardTerminal && cardTerminal.size()>0){
			try{
				for(CardTerminal cTerminal : cardTerminal){
					if(cTerminal.getName().contains("ACR122"));
						terminal = cTerminal;
				}
			}catch(Exception e){
				logger.error("Common Exception occurred while reading card ",e);
				return false;
			}
			return null!=terminal ? true : false;
		}
		return false;
	}
	
	/**
	 * @param connectionProtocol
	 * @throws CardException
	 * 
	 * <li>This method is used connect card terminal.</li>
	 */
	public void connectCard(String connectionProtocol)throws CardException{
		if(null!=terminal && terminal.isCardPresent()){
			if(null==connectionProtocol || "".equals(connectionProtocol)){
				connectionProtocol="*";
			}
			card = terminal.connect(connectionProtocol);
		}else{
			throw new CardDataException("Please run connectReader() method first or please connect ACR122U reader properly");
		}
	}

	/**
	 * @param blockNo
	 * @return byte[]
	 * 
	 * This method is used to read the card block using default key which is an unique key to Mifare Classic 1K Cards
	 */
	public byte[] readCardUsingDefaultKey(int blockNo){
		sendCommand(util.getDefaultAuthenticationKey());
		byte []authCmdForkeyA = util.getAuthCmdForkeyA();
		byte []readBlockCmd = util.getReadBlockCmd();
		authCmdForkeyA[7]=(byte)blockNo;
		sendCommand(authCmdForkeyA);
		readBlockCmd[3]=(byte)blockNo;
		return sendCommand(readBlockCmd);
	}
	
	/**
	 * @param authKeyData
	 * @param authKeyCmd
	 * @param blockNo
	 * @return byte []
	 * 
	 * <li>This method has 3 parameters, user defined authentication key, Authentication command for Key A or Key B, card block to read and return byte Array.</li>
	 */
	public byte[] readCardBlock(byte []authKeyData,byte []authKeyCmd,int blockNo){
		if(null==authKeyData || authKeyData.length!=6)
			throw new CardDataException("Insufficient authKeyData length. Length should be 6 in size");
		doAuthentication(authKeyData,authKeyCmd,blockNo);
		byte []readBlockCmd = util.getReadBlockCmd();
		readBlockCmd[3]=(byte)blockNo;
		return sendCommand(readBlockCmd);
	}
	
	/**
	 * @param authKeyData
	 * @param authKeyCmd
	 * @param blockNo
	 * @param data
	 * @return byte[]
	 * 
	 * <li>This method has 4 parameters, user defined authentication key, Authentication command for Key A or Key B, card block to write, byte data of 16 bytes to write in the card.</li>
	 */
	public byte[] writeDataIntoCard(byte []authKeyData,byte []authKeyCmd,int blockNo,byte []data){
		if(null==authKeyData || authKeyData.length!=6)
			throw new CardDataException("Insufficient authKeyData Param length. Length should be 6 in size");
		if(null==data || data.length!=16)
			throw new CardDataException("Insufficient data Param length. Length should be 16 in size");
		byte []byteDataArr = new byte[21];
		int arrCount=5;
		byte []writeCardCmd = util.getWriteCardCmd();
		for(int i=0;i<data.length;i++){
			if(i<5)
				byteDataArr[i]=writeCardCmd[i];
			byteDataArr[arrCount]=data[i];
			arrCount++;
		}
		byteDataArr[3]=(byte)blockNo;
		
		// We have to authenticate every block before writing or reading.
		doAuthentication(authKeyData,authKeyCmd, blockNo);
		
		byte []apduResponse = sendCommand(byteDataArr);
		return apduResponse;
	}

	/**
	 * @param authKey
	 * @param trailerBlockNo
	 * @return byte[]
	 * 
	 * <li>This method is used to encrypt card using default key. Once the card is encrypted the key will be stored on Key B side.</li> 
	 * <li>We have used access bits to grant read and write access internally to the reader. At the same time if we try to read this block the output will be 0.</li>
	 */
	public byte[] encryptCardUsingDefaultKey(byte []existingAuthKey, byte[] authCmdToAccess,byte []newAuthKey,int trailerBlockNo){
		
		if(null==existingAuthKey || existingAuthKey.length!=6)
			throw new CardDataException("Insufficient existingAuthKey Param length. Length should be 6 in size");
		
		if(null==newAuthKey || newAuthKey.length!=6)
			throw new CardDataException("Insufficient authKeyData Param length. Length should be 6 in size");
		int tBlock = 0;
		byte []trailerBlock = util.getTrailerBlock();
		byte []createManualAuthenticationKey = util.createManualAuthenticationKeyCmd();
		try{
			tBlock = (int)trailerBlock[trailerBlockNo/4];
			if(tBlock!=trailerBlockNo)
				throw new CardDataException("Invalid Trailor Block ".concat(String.valueOf(trailerBlockNo)));
		}catch(ArrayIndexOutOfBoundsException aiobe){
			logger.error("Error while reading trailerBlock Array ",aiobe);
			throw new CardDataException("Invalid Trailor Block ".concat(String.valueOf(trailerBlockNo)));
		}
		
		byte []authKeyData = new byte[createManualAuthenticationKey.length+existingAuthKey.length];
		
		for(int i=0,j=5;i<existingAuthKey.length;i++,j++){
			if(i<5)
				authKeyData[i]=createManualAuthenticationKey[i];
			authKeyData[j]=existingAuthKey[i];
		}
		
		byte []updateSecKey = new byte[21];
		int finalKeyCount=0;
		byte []writeOnKeyBAndInheritAs0Cmd = util.getCmdToWriteOnKeyBAndInheritAs0();
		for(int i=0;i<21;i++){
			if(i<15)
				updateSecKey[i]=writeOnKeyBAndInheritAs0Cmd[i];
			else{
				updateSecKey[i]=newAuthKey[finalKeyCount];
				finalKeyCount++;
			}
		}
		
//		Load Key into device
		byte []response=null;
		response = sendCommand(authKeyData);
		
		updateSecKey[3]=(byte)tBlock;
		authCmdToAccess[7]=(byte)tBlock;
		
//		Authenticate Trailor Block
		response = sendCommand(authCmdToAccess);
		
//		Update Security Key
		response = sendCommand(updateSecKey);

		return response;
	}
	
	/**
	 * @param authKeyData
	 * @param authKeyCmd
	 * @param trailerBlockNo
	 * @return byte[]
	 * 
	 * <li>This method has 3 parameters, user defined authentication key, Authentication command for key A or key B, trailer block number where the authentication key is stored.</li>
	 * <li>This method will override the current authentication key with default key(i.e., The key was provided by the manufacturer)</li>
	 */
	public byte[] resetCardWithDefaultKey(byte []authKeyData,byte []authKeyCmd,int trailerBlockNo){
		if(null == authKeyData || authKeyData.length!=6)
			throw new CardDataException("Insufficient authKeyData Param length. Length should be 6 in size");
		int tBlock = 0;
		byte []trailerBlock = util.getTrailerBlock();
		byte []formatCard = util.getFormatCard();
		try{
			tBlock = (int)trailerBlock[trailerBlockNo/4];
			if(tBlock!=trailerBlockNo)
				throw new CardDataException("Invalid Trailor Block ".concat(String.valueOf(trailerBlockNo)));
		}catch(ArrayIndexOutOfBoundsException aiobe){
			logger.error("Error while reading trailerBlock Array ",aiobe);
			throw new CardDataException("Invalid Trailor Block ".concat(String.valueOf(trailerBlockNo)));
		}
		
		doAuthentication(authKeyData, authKeyCmd, trailerBlockNo);
		
		formatCard[3] = (byte)tBlock;
		
		return sendCommand(formatCard);
	}

	/**
	 * This method will stop the card reading process.
	 */
	public void stop()throws CardException{
		if(null!=terminal && !terminal.isCardPresent()){
			card.disconnect(true);
		}
	}
	
	/**
	 * @param apduCmd
	 * @return byte Array
	 * 
	 * <li>This method will read card code from manufacturer block and returns the same.</li>
	 */
	public byte[] getUID(){
		return sendCommand(util.getReadUIDCmd());
	}
	
	/**
	 * @param apduCmd
	 * @return byte[]
	 */
	private byte[] sendCommand(byte[] apduCmd){
		if(null==card)
			throw new CardDataException("Place card on the reader");
		CardChannel cardChannel = card.getBasicChannel();
		CommandAPDU apduCommand = new CommandAPDU(apduCmd);
		ResponseAPDU responseApdu=null;
		try {
			responseApdu = cardChannel.transmit(apduCommand);
		} catch (CardException ce) {
			logger.error("Error occurred while transmitting command to card ",ce);
		}
		return responseApdu.getBytes();
	}
	
	/**
	 * @param apduCmd
	 * @return ResponseApdu
	 * 
	 * <li>This method is used to send Apdu command directly and will return ResponseAPDU.</li>
	 */
	public ResponseAPDU sendApduCommand(byte[] apduCmd){
		if(null==card)
			throw new CardDataException("Place card on the reader");
		CardChannel cardChannel = card.getBasicChannel();
		CommandAPDU apduCommand = new CommandAPDU(apduCmd);
		ResponseAPDU responseApdu=null;
		try {
			responseApdu = cardChannel.transmit(apduCommand);
		} catch (CardException ce) {
			logger.error("Error occurred while transmitting command to card ",ce);
		}
		return responseApdu;
	}
	
	/**
	 * @param interval
	 * @throws CardException
	 * 
	 * <li>This method will make the application wait for card to be present on the reader.</li>
	 */
	public void waitForCardPresent(int interval)throws CardException{
		terminal.waitForCardPresent(interval);
	}
	
	public void waitForCardAbsent(int interval)throws CardException{
		terminal.waitForCardAbsent(interval);
	}
	
	public boolean isCardPresent()throws CardException{
		return terminal.isCardPresent();
	}
	
	/**
	 * @return cardTerminalList
	 */
	private List<CardTerminal> getReaderList()throws CardException{
		CardTerminals cardTerminals = TerminalFactory.getDefault().terminals();
		return cardTerminals !=null ? cardTerminals.list() : null; 
	}
	
	/**
	 * @param authKeyData
	 * @param authKeyCmd
	 * @param blockNo
	 * @return byte[]
	 * 
	 * This method is used for internal authentication purpose.
	 */
	private byte[] doAuthentication(byte []authKeyData,byte []authKeyCmd,int blockNo){
		byte []createManualAuthenticationKey = util.createManualAuthenticationKeyCmd();
		byte []encryptedKey = new byte[createManualAuthenticationKey.length+authKeyData.length];
		for(int i=0,j=5;i<authKeyData.length;i++,j++){
			if(i<5)
				encryptedKey[i]=createManualAuthenticationKey[i];
			encryptedKey[j]=authKeyData[i];
		}
		
		// Load key in smart card reader
		sendCommand(encryptedKey);
		
		byte []encryptedAuthentication = authKeyCmd; 
		
		//Update block to authenticate
		encryptedAuthentication[7] = (byte)blockNo;
		
		//Do Authentication
		byte []apduResponse = sendCommand(encryptedAuthentication);
		
		return apduResponse;
	}
}