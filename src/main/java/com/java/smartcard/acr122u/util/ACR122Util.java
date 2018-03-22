package com.java.smartcard.acr122u.util;

/**
 * 
 * @author Sujith Ramanathan
 *
 */

public class ACR122Util {
	
	/** ACR122Util instance **/
	private static ACR122Util instance;
	
	/** This is the Default Authentication key which was stored in MiFare Classic 1K Cards on Key A. **/
	private final byte[] defaultAuthenticationKey = new byte[] {(byte)0xFF,(byte)0x82,(byte)0x00,(byte)0x00,(byte)0x06,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
	
	/** This command is same like above but we have to concat the data(i.e., 6 bytes of authentication key ) in the last **/
	private final byte[] createManualAuthenticationKeyCmd = new byte[] {(byte)0xFF,(byte)0x82,(byte)0x00,(byte)0x00,(byte)0x06};
	
	/** This command is used to authenticate the card using key A **/
 	private final byte[] authCmdForkeyA = new byte[] {(byte) 0xFF, (byte) 0x86, (byte) 0x00, (byte) 0x00, (byte) 0x05, (byte) 0x01,(byte) 0x00,(byte) 0x03,(byte) 0x60,(byte) 0x00};
 	
 	/** This command is used to authenticate the card using key B **/
 	private final byte[] authCmdForkeyB = new byte[] {(byte) 0xFF, (byte) 0x86, (byte) 0x00, (byte) 0x00, (byte) 0x05, (byte) 0x01,(byte) 0x00,(byte) 0x03,(byte) 0x61,(byte) 0x00};
 	
 	/** This command is used to read UID (i.e., Card code from manufacturer block) **/
 	private final byte[] readUIDCmd = new byte[]{(byte) 0xFF,(byte) 0xCA,(byte) 0x00,(byte) 0x00,(byte) 0x00};
 	
 	/** This command is used to read particular block of the card**/
 	private final byte[] readBlockCmd = new byte[]{(byte)0xFF,(byte)0xB0,(byte)0x00,(byte)0x01,(byte)0x10};
 	
 	/** Trailer Block array, Which has the list of all trailer blocks **/
 	private final byte[] trailerBlock = new byte[]{(byte)0x03,(byte)0x07,(byte)0x0B,(byte)0x0F,(byte)0x13,(byte)0x17,(byte)0x1B,(byte)0x1F,(byte)0x23,(byte)0x27,(byte)0x2B,(byte)0x2F,(byte)0x33,(byte)0x37,(byte)0x3B,(byte)0x3F};
 	
 	/** This command is used write the authentication key on Key B and provide read only access to key B, Key B inherits 0. **/
 	private final byte[] writeOnKeyBAndInheritAs0Cmd = new byte[]{(byte)0xFF,(byte)0xD6,(byte)0x00,(byte)0x03,(byte)0x10,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x08,(byte)0x77,(byte)0x8F,(byte)0x69};
 	
 	/** This command is used to write card into card **/
 	private final byte[] writeCardCmd = new byte[]{(byte)0xFF,(byte)0xD6,(byte)0x00,(byte)0x01,(byte)0x10};
 	
 	/** This command is used to reset trailer block with default key which was provided by the manufacturer **/
 	private final byte[] formatCard = new byte[]{(byte)0xFF,(byte)0xD6,(byte)0x00,(byte)0x03,(byte)0x10,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x07,(byte)0x80,(byte)0x69,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
	
	/** Private Constructor **/
	private ACR122Util(){}
	
	/** This method will return ACR122U instance **/
	public static ACR122Util getInstance(){
		if(null==instance){
			synchronized (ACR122Util.class) {
				if(null==instance)
					instance=new ACR122Util();
			}
		}
		return instance;
	}
	
    /**
	 * @param response
	 * @return String[]
	 * 
	 * <li>The result method will convert byte[] to String[] (hexa string).</li>
	 */
	public String[] convertByteArrayToStringArray(byte[] response) {
		String []resonseString = new String[response.length];
		for (int i = 0; i < response.length; i++) {
			resonseString[i]=String.format("%02X", response[i]);
		}
		return resonseString;
	}

	/**
	 * @return byte[]
	 * 
	 * <li>This method will return default authentication key for Mifare classic 1K card</li>
	 */
	public byte[] getDefaultAuthenticationKey() {
		return defaultAuthenticationKey;
	}

	/**
	 * @return byte[]
	 * 
	 * <li>This method will return basic command for user authentication key, Where user have to concatenate the 6 bytes of key in suffix.</li>
	 */
	public byte[] createManualAuthenticationKeyCmd() {
		return createManualAuthenticationKeyCmd;
	}

	/**
	 * @return byte[]
	 * 
	 * <li>This method will return Authentication command for key A</li>
	 */
	public byte[] getAuthCmdForkeyA() {
		return authCmdForkeyA;
	}

	/**
	 * @return byte[]
	 * 
	 * <li>This method will return Authentication command for key B</li>
	 */
	public byte[] getAuthCmdForkeyB() {
		return authCmdForkeyB;
	}

	/**
	 * @return byte[]
	 * 
	 * <li>This method will return UID of the Card from manufacturer block (i.e., block 0)</li>
	 */
	public byte[] getReadUIDCmd() {
		return readUIDCmd;
	}

	/**
	 * @return byte[]
	 * 
	 * <li>This method will the command which is used to read the card block</li>
	 */	
	public byte[] getReadBlockCmd() {
		return readBlockCmd;
	}

	/**
	 * @return byte[]
	 * 
	 * <li>This method will return all the trailer blocks of Mifare classic 1K card</li>
	 */
	public byte[] getTrailerBlock() {
		return trailerBlock;
	}

	/**
	 * @return byte[]
	 * 
	 * <li>This method will return the command which is used hide authentication key and show as 0 while reading the trailer block</li>
	 */
	public byte[] getCmdToWriteOnKeyBAndInheritAs0() {
		return writeOnKeyBAndInheritAs0Cmd;
	}
	
	/**
	 * @return byte[]
	 * 
	 * <li>This method will return command which is used to write data on card.</li>
	 */
	public byte[] getWriteCardCmd() {
		return writeCardCmd;
	}

	/**
	 * @return byte[]
	 * 
	 * <li>This method will return command which has default key and default access bits.</li>
	 */
	public byte[] getFormatCard() {
		return formatCard;
	}
}
