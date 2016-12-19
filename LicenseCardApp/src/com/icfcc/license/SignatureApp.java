package com.icfcc.license;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.TransactionException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import com.icfcc.license.Constants;

/**
 * 该 Applet实现签名功能
 * 
 * @author daor
 * 
 */
public class SignatureApp extends Applet {

	private RSAPrivateCrtKey mpricrtkey;
	private RSAPublicKey mpubkey;
	private KeyPair keypair;

	Cipher cipherEncPkcs;
	MessageDigest mSHA;
	byte[] SHADATA;
	private byte[] counter;

	/**
	 * 公钥，设置次数时解密使用
	 */
	private RSAPublicKey vpubkey;
	private KeyPair vkeypair;
	private Cipher vcipherDecPkcs;
	static final byte[] vrsaExponent = new byte[] { (byte) 0x01, (byte) 0x00,
			(byte) 0x01 };
	static final byte[] vrsaModulus = new byte[] { (byte) 0xCA, (byte) 0x75,
			(byte) 0x4D, (byte) 0x81, (byte) 0x60, (byte) 0xD1, (byte) 0x13,
			(byte) 0x5D, (byte) 0x7A, (byte) 0xB5, (byte) 0x58, (byte) 0x6C,
			(byte) 0xB3, (byte) 0x06, (byte) 0xD1, (byte) 0xA2, (byte) 0x9D,
			(byte) 0x3D, (byte) 0xB3, (byte) 0xCB, (byte) 0xB0, (byte) 0x5D,
			(byte) 0xF9, (byte) 0xC2, (byte) 0x70, (byte) 0x48, (byte) 0xAB,
			(byte) 0x0F, (byte) 0x5F, (byte) 0xE1, (byte) 0xD9, (byte) 0xE5,
			(byte) 0xC7, (byte) 0x6D, (byte) 0xA2, (byte) 0x4C, (byte) 0xBD,
			(byte) 0xD9, (byte) 0xAA, (byte) 0x61, (byte) 0xFF, (byte) 0xC7,
			(byte) 0xBB, (byte) 0xAE, (byte) 0x8B, (byte) 0xB9, (byte) 0x2D,
			(byte) 0xFE, (byte) 0x0C, (byte) 0x50, (byte) 0x95, (byte) 0x54,
			(byte) 0x59, (byte) 0x86, (byte) 0xA0, (byte) 0x49, (byte) 0xB1,
			(byte) 0x27, (byte) 0x26, (byte) 0xCF, (byte) 0x90, (byte) 0xD1,
			(byte) 0x5C, (byte) 0xBE, (byte) 0x96, (byte) 0x4C, (byte) 0xDF,
			(byte) 0x42, (byte) 0x2E, (byte) 0xED, (byte) 0x05, (byte) 0x27,
			(byte) 0x80, (byte) 0x30, (byte) 0x23, (byte) 0xBB, (byte) 0x92,
			(byte) 0x92, (byte) 0x4B, (byte) 0x77, (byte) 0x85, (byte) 0x47,
			(byte) 0x01, (byte) 0x47, (byte) 0xEC, (byte) 0x36, (byte) 0x48,
			(byte) 0xBA, (byte) 0xDC, (byte) 0xA5, (byte) 0xDC, (byte) 0x1D,
			(byte) 0xBB, (byte) 0x01, (byte) 0x54, (byte) 0xD1, (byte) 0x34,
			(byte) 0xF2, (byte) 0xE6, (byte) 0x07, (byte) 0x6A, (byte) 0xE3,
			(byte) 0x26, (byte) 0x24, (byte) 0xE8, (byte) 0x82, (byte) 0x08,
			(byte) 0xC1, (byte) 0x30, (byte) 0x8C, (byte) 0xF2, (byte) 0x27,
			(byte) 0x44, (byte) 0x5A, (byte) 0xB7, (byte) 0x86, (byte) 0xD5,
			(byte) 0x58, (byte) 0x13, (byte) 0x92, (byte) 0xCC, (byte) 0x6C,
			(byte) 0xD9, (byte) 0xCE, (byte) 0xC7, (byte) 0x6C, (byte) 0x1E,
			(byte) 0x8B };
	private RandomData mrand;
	private byte[] randomdata;

	SignatureApp() {
		mrand = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

		cipherEncPkcs = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);

		mSHA = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);// 建立hash对象
		SHADATA = JCSystem.makeTransientByteArray((short) 20,
				JCSystem.CLEAR_ON_RESET);
		// randomdata = JCSystem.makeTransientByteArray(randomdatalength,
		// JCSystem.CLEAR_ON_RESET);
		randomdata = new byte[Constants.randomdatalength];// 测试用
		counter = new byte[Constants.counterlength];
		GenerateRSAKeyPair(Constants.keyLength);

		/* 验签相关数据个人化 */
		vcipherDecPkcs = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		vkeypair = new KeyPair(KeyPair.ALG_RSA_CRT, Constants.keyLength);// 创建公私钥对对象
		vkeypair.genKeyPair();
		vpubkey = (RSAPublicKey) vkeypair.getPublic();
		vpubkey.setExponent(vrsaExponent, (short) 0,
				(short) vrsaExponent.length);
		vpubkey.setModulus(vrsaModulus, (short) 0x0000,
				(short) vrsaModulus.length);

	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new SignatureApp().register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		short rlen = 0;
		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) 0xB1:// 签名
			apdu.setIncomingAndReceive();
			if (!Decrease(counter, (short) 0, Constants.counterlength,
					(byte) 0x01)) {
				ISOException.throwIt((short) 0x6A81);// 次数不够
				break;
			}
			cipherEncPkcs.init(mpricrtkey, Cipher.MODE_ENCRYPT);
			mSHA.doFinal(buf, ISO7816.OFFSET_CDATA,
					(short) (0x00FF & buf[ISO7816.OFFSET_LC]), SHADATA,
					(short) 0);
			rlen = cipherEncPkcs.doFinal(SHADATA, (short) 0,
					(short) SHADATA.length, buf, (short) 0);
			apdu.setOutgoingAndSend((short) 0, rlen);
			break;
		case (byte) 0xB2:// 查看剩余次数
			Util.arrayCopy(counter, (short) 0, buf, (short) 0,
					Constants.counterlength);
			apdu.setOutgoingAndSend((short) 0, Constants.counterlength);
			break;

		case (byte) 0xA1:// 读取公钥
			if ((short) buf[ISO7816.OFFSET_P1] == (short) 0x0001) {
				rlen = mpubkey.getExponent(buf, (short) 0);
			} else if ((short) buf[ISO7816.OFFSET_P1] == (short) 0x0002) {
				rlen = mpubkey.getModulus(buf, (short) 0);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				break;
			}
			apdu.setOutgoingAndSend((short) 0, rlen);
			break;
		case (byte) 0xA2:// 取随机数
			mrand.generateData(randomdata, (short) 0,
					Constants.randomdatalength);
			rlen = Util.arrayCopy(randomdata, (short) 0, buf, (short) 0,
					Constants.randomdatalength);
			apdu.setOutgoingAndSend((short) 0, rlen);
			break;
		case (byte) 0xA3:// 设置次数
			apdu.setIncomingAndReceive();
			vcipherDecPkcs.init(vpubkey, Cipher.MODE_DECRYPT);
			rlen = vcipherDecPkcs.doFinal(buf, ISO7816.OFFSET_CDATA,
					(short) (0x00FF & buf[ISO7816.OFFSET_LC]), buf, (short) 0);

			if (((byte) 0x00 != Util.arrayCompare(buf, (short) 0, randomdata,
					(short) 0, Constants.randomdatalength))
					|| (buf[Constants.randomdatalength
							+ Constants.counterlength] != Constants.counterSetFlag)) {
				ISOException.throwIt((short) 0x6A80);
			} else {
				Util.arrayCopy(buf, Constants.randomdatalength, counter,
						(short) 0, Constants.counterlength);
			}
			break;
		case (byte) 0xA4:// 增加次数
			apdu.setIncomingAndReceive();
			vcipherDecPkcs.init(vpubkey, Cipher.MODE_DECRYPT);
			rlen = vcipherDecPkcs.doFinal(buf, ISO7816.OFFSET_CDATA,
					(short) (0x00FF & buf[ISO7816.OFFSET_LC]), buf, (short) 0);
			if (((byte) 0x00 != Util.arrayCompare(buf, (short) 0, randomdata,
					(short) 0, Constants.randomdatalength))
					|| (buf[Constants.randomdatalength
							+ Constants.counterlength] != Constants.counterSetFlag)) {
				ISOException.throwIt((short) 0x6A80);
			} else {
				arrayHexcAdd(buf, Constants.randomdatalength, counter,
						(short) 0, counter, (short) 0, Constants.counterlength);// 增加次数
			}
			break;

		case (byte) 0x93:// 设置次数
			Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, counter, (short) 0,
					Constants.counterlength);
			break;
		case (byte) 0x94:// 增加次数
			arrayHexcAdd(buf, ISO7816.OFFSET_CDATA, counter, (short) 0,
					counter, (short) 0, Constants.counterlength);// 增加次数
			break;
		case (byte) 0x99:// 次数递减测试
			if (!Decrease(counter, (short) 0, Constants.counterlength,
					(byte) 0x01)) {
				ISOException.throwIt((short) 0x6A81);
				break;
			}
			Util.arrayCopy(counter, (short) 0, buf, (short) 0,
					Constants.counterlength);
			apdu.setOutgoingAndSend((short) 0, Constants.counterlength);
			break;
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	/**
	 * 创建长度为 rsalen的空密钥对
	 * 
	 * @param rsalen
	 */
	public void GenerateRSAKeyPair(short rsalen) {
		// 重复生成公私钥对时 ，回收内存
		if (keypair != null) {
			mpricrtkey.clearKey();
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
		keypair.genKeyPair();// 生成公私钥
		mpricrtkey = (RSAPrivateCrtKey) keypair.getPrivate();
		mpubkey = (RSAPublicKey) keypair.getPublic();
	}

	/**
	 * 
	 * @param mdata
	 * @param mOff
	 * @param mlength
	 * @return
	 */
	public static boolean Decrease(byte[] mdata, short mOff,
			final short mlength, byte mstep) {
		boolean c = false;// 是否借位成功
		final short step = (short) mstep;

		if ((short) (0x00FF & mdata[mlength - 1]) >= step) {// 不需要借位
			mdata[(short) (mlength - 1)] = (byte) ((short) mdata[(short) (mlength - 1)] - step);
			return true;
		}

		for (short i = (short) (mlength - 2); i >= 0; i--) {
			if ((short) (0x00FF & mdata[i]) > (short) 0) {
				mdata[i]--;// 借位成功
				c = true;
				for (short j = (short) (i + 1); j <= (short) (mlength - 2); j++) {
					mdata[j] = (byte) 0xFF;
				}
				break;
			} else {
				continue;
			}
		}
		if (c) {
			mdata[mlength - 1] = (byte) ((short) (0x00FF & mdata[mlength - 1])
					+ (short) 0x100 - step);
			return true;
		} else
			return false;
	}

	/**
	 * array unsigned byte dec add with carry.
	 * 
	 * @param augend
	 * @param augOff
	 * @param addend
	 * @param addOff
	 * @param out
	 *            out byte array.
	 * @param oOff
	 *            offset of out byte array.
	 * @param olength
	 *            length of augend/addend/out byte array.
	 */
	public static void arrayHexcAdd(byte[] augend, short augOff, byte[] addend,
			short addOff, byte[] out, short oOff, short olength) {

		short sf, st;
		byte c;

		c = (byte) 0;

		for (byte i = (byte) (olength - 1); i >= 0; i--) {

			sf = (short) (0x00FF & augend[augOff + i]);

			st = (short) (((short) (0x00FF & addend[addOff + i])) + c);

			c = (byte) 0;

			st += sf;

			if (st > 255) {

				st -= 256;
				c = (byte) 1;
			}

			out[(short) (oOff + i)] = (byte) st;
		}
	}
}
