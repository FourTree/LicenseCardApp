package com.icfcc.license;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

import com.icfcc.license.Constants;


public class VerifyApp extends Applet {
	private RSAPublicKey mpubkey ;
	private KeyPair keypair ;
	
	private Cipher cipherDecPkcs;
	private MessageDigest mSHA;
	private RandomData mrand;
	
	byte[] TMPATA;
	byte[] SHADATA;
	byte[] SRCDATA;

	VerifyApp() {
		cipherDecPkcs = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		mSHA = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);// 建立hash对象
		mrand = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		
		SHADATA = JCSystem.makeTransientByteArray(mSHA.getLength(),
				JCSystem.CLEAR_ON_RESET);
		TMPATA = JCSystem.makeTransientByteArray(mSHA.getLength(),
				JCSystem.CLEAR_ON_RESET);
		SRCDATA = new byte[Constants.randomdatalength];
		GenerateEmptyRSAKeyPair(Constants.keyLength);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new VerifyApp()
				.register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		short rlen = (short) 0;
		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) 0xA0:
			apdu.setIncomingAndReceive();
			if ((short) buf[ISO7816.OFFSET_P1] == (short) 0x0001) {
				mpubkey.setExponent(buf, (short) ISO7816.OFFSET_CDATA,
						(short) (0x00FF & buf[ISO7816.OFFSET_LC]));
			} else if ((short) buf[ISO7816.OFFSET_P1] == (short) 0x0002) {
				mpubkey.setModulus(buf, (short) ISO7816.OFFSET_CDATA,
						(short) (short) (0x00FF & buf[ISO7816.OFFSET_LC]));
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				break;
			}
			break;
			
		case (byte) 0xA1://取随机数
			mrand.generateData(SRCDATA, (short)0, Constants.randomdatalength);
			rlen = Util.arrayCopy(SRCDATA,(short)0, buf, (short)0, Constants.randomdatalength);
			apdu.setOutgoingAndSend((short)0, rlen);
			break;

		case (byte) 0xA2:
			apdu.setIncomingAndReceive();
			try {
				cipherDecPkcs.init(mpubkey, Cipher.MODE_DECRYPT);
				rlen = cipherDecPkcs.doFinal(buf, ISO7816.OFFSET_CDATA,
						(short) (0x00FF & buf[ISO7816.OFFSET_LC]), TMPATA,
						(short) 0);
				mSHA.doFinal(SRCDATA, (short) 0, (short) Constants.randomdatalength, SHADATA, (short) 0);
			} catch (Exception e) {
				ISOException.throwIt((short) 0x6300);
			}
			if (rlen != mSHA.getLength())
				ISOException.throwIt((short) 0x6300);

			if ((short) Util.arrayCompare(TMPATA, (short) 0, SHADATA,
					(short) 0, (short) SHADATA.length) == (short) 0) {
				ISOException.throwIt(ISO7816.SW_NO_ERROR);
			} else {
				ISOException.throwIt((short) 0x6300);
			}
			break;
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	/**
	 * 创建长度为 rsalen的空密钥对
	 * @param rsalen
	 */
	public void GenerateEmptyRSAKeyPair(short rsalen) {
		// 重复生成公私钥对时 ，回收内存
		if (keypair != null) {
			mpubkey.clearKey();
			keypair = null;
			/**
			 * 内存回收 发出垃圾回收请求，等接收到下一条指令前清除
			 */
			if (JCSystem.isObjectDeletionSupported()) {
				JCSystem.requestObjectDeletion();
			}
			// JCSystem.requestObjectDeletion();
		}

		keypair = new KeyPair(KeyPair.ALG_RSA_CRT, rsalen);// 创建公私钥对对象
		keypair.genKeyPair();
		mpubkey = (RSAPublicKey) keypair.getPublic();
	}
}
