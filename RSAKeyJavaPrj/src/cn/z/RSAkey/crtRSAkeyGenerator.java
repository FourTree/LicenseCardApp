package cn.z.RSAkey;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

public class crtRSAkeyGenerator {

	public static void main(String args[]){
		KeyPairGenerator kpg = null;
		try{
			kpg =KeyPairGenerator.getInstance("RSA");
		}catch(NoSuchAlgorithmException e){
			System.out.println("ERR…………");
				e.printStackTrace();
		}
		kpg.initialize(1024);
		KeyPair kp = kpg.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) kp.getPrivate();
		System.out.println(ByteUtils.byteArrayToHexString(publicKey.getEncoded()));
		System.out.println(ByteUtils.byteArrayToHexString(privateKey.getEncoded())); 
		
		System.out.println(ByteUtils.byteArrayToHexString(privateKey.getModulus().toByteArray())); 
		System.out.println(ByteUtils.byteArrayToHexString(privateKey.getPublicExponent().toByteArray())); 

		System.out.println("00B1000040"+ByteUtils.byteArrayToHexString(privateKey.getPrimeP().toByteArray()).toUpperCase()); 
		System.out.println("00B2000040"+ByteUtils.byteArrayToHexString(privateKey.getPrimeQ().toByteArray()).toUpperCase()); 
		System.out.println("00B3000040"+ByteUtils.byteArrayToHexString(privateKey.getPrimeExponentP().toByteArray()).toUpperCase()); 
		System.out.println("00B4000040"+ByteUtils.byteArrayToHexString(privateKey.getPrimeExponentQ().toByteArray()).toUpperCase()); 
		System.out.println("00B5000040"+ByteUtils.byteArrayToHexString(privateKey.getCrtCoefficient().toByteArray()).toUpperCase()); 

	}
	
}
