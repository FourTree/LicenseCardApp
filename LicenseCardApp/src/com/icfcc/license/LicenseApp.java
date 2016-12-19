package com.icfcc.license;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

import com.icfcc.license.Constants;

/**
 * 该 Applet实现License授权次数
 * 
 * @author daor
 * 
 */
public class LicenseApp extends Applet {

	private RSAPrivateCrtKey mpricrtkey;
	private RSAPublicKey mpubkey;
	private KeyPair keypair;
	Cipher cipherEncPkcs;

	LicenseApp() {
		cipherEncPkcs = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		GenerateRSAKeyPair(Constants.keyLength);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new LicenseApp().register(bArray, (short) (bOffset + 1),
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
		case (byte) 0xA2:// 获取授权次数密文，设置
			apdu.setIncomingAndReceive();
			if (buf[ISO7816.OFFSET_LC] != (Constants.randomdatalength + Constants.counterlength)) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				break;
			}
			cipherEncPkcs.init(mpricrtkey, Cipher.MODE_ENCRYPT);
			rlen = (short) (buf[ISO7816.OFFSET_LC] + 1);
			buf[buf[ISO7816.OFFSET_LC] + 5] = Constants.counterSetFlag;
			rlen = cipherEncPkcs.doFinal(buf, (short) ISO7816.OFFSET_CDATA,
					rlen, buf, (short) 0);
			apdu.setOutgoingAndSend((short) 0, rlen);
			break;
		case (byte) 0xA3:// 获取授权次数密文，增加
			apdu.setIncomingAndReceive();
			if (buf[ISO7816.OFFSET_LC] != (Constants.randomdatalength + Constants.counterlength)) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				break;
			}
			cipherEncPkcs.init(mpricrtkey, Cipher.MODE_ENCRYPT);
			rlen = (short) (buf[ISO7816.OFFSET_LC] + 1);
			buf[ISO7816.OFFSET_CDATA + 5] = Constants.counterAddFlag;
			rlen = cipherEncPkcs.doFinal(buf, (short) ISO7816.OFFSET_CDATA,
					rlen, buf, (short) 0);
			apdu.setOutgoingAndSend((short) 0, rlen);
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
}
