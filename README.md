# ACR122U

This is a simple java library which is used to read or write Mifare classic 1k cards only.

### Features
 * Read or Write Mifare Classic 1k cards
 * Supports ACR122U only
 * JRE 7.0 or later
 
### Build
 * mvn clean install

### Example
 	public static void main(String []args) throws CardException {
   	ACR122UReaderHelper reader = ACR122UReaderHelper.getInstance();
	ACR122Util readerUtil = ACR122Util.getInstance();

	byte []authKeyData = new byte[]{(byte)0x01,(byte)0x02,(byte)0x03,(byte)0x04,(byte)0x05,(byte)0x06};
	byte []data = new byte[]{(byte)0x09,(byte)0x09,(byte)0x09,(byte)0x09,(byte)0x09,(byte)0x09,(byte)0x09,(byte)0x09,(byte)0x09,   (byte)0x09,(byte)0x09,(byte)0x09,(byte)0x09,(byte)0x09,(byte)0x09,(byte)0x09};

	reader.connectReader();

	reader.connectCard(null);
	reader.getUID(); // Returns UID of the card which is placed on the readert.
	reader.readCardUsingDefaultKey(1); // Returns 16 bytes of array for success, Returns 2 bytes of array(63,00) for failure
	reader.readCardBlock(authKeyData, readerUtil.getAuthCmdForkeyA(), 1); // Returns 16 bytes of array for success, Returns 2 bytes of array(63,00) for failure
	reader.writeDataIntoCard(authKeyData, readerUtil.getAuthCmdForkeyA(), 1, data); // Returns 2 bytes of array(90,00) for success, Returns 2 bytes of array(63,00) for failure
	}

### About the ACR122U reader/writer

![ACR122U NFC reader/writer](res/reader.png?raw=true)


### Device features

  * PC-linked contactless smart card ([NFC](http://en.wikipedia.org/wiki/Near_field_communication)) reader/writer
  * Contactless operating frequency: 13.56 MHz
  * Supports: [ISO14443](http://en.wikipedia.org/wiki/ISO/IEC_14443) Type A & B, [MIFARE®](http://en.wikipedia.org/wiki/MIFARE), FeliCa, 4 types of NFC (ISO/IEC18092) tags
  * Interface: USB
  * Operating Distance: Up to 50 mm (depends on the tag type)
  * Operating Voltage: DC 5.0V
  * Operating Frequency: 13.56 MHz
  * Compliance/Certifications: ISO 14443, PC/SC, CCID
  * Size: 98 mm x 65 mm x 12.8 mm
  * Weight: 70 g


