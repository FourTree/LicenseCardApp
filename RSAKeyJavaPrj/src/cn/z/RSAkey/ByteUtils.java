package cn.z.RSAkey;
import java.io.UnsupportedEncodingException;


public final class ByteUtils {
	private ByteUtils() {
	}

	// 数组的对比
	public static boolean comparebyte(byte[] srcdata, byte[] disdata) {
		for (int n = 0; n < srcdata.length; n++) {
			if (srcdata[n] != disdata[n]) {
				return false;
			}
		}
		return true;
	}

	public static String formatNo(int length, long source) {
		String const1 = "0000000000000000";
		String s1 = String.valueOf(source);

		if (s1.length() < length) {
			s1 = const1.substring(0, length - s1.length()) + s1;
		} else {
			s1 = s1.substring(0, 6);
		}

		return s1;
	}

	public static String formatStr(int length, String source) {
		String const1 = "00000000000000000000";
		String s1 = source;

		if (s1.length() < length) {
			s1 = const1.substring(0, length - s1.length()) + s1;
		} else {
			s1 = s1.substring(0, 6);
		}

		return s1;
	}

	public static String byteArrayToHexString(byte[] data) {
		if (data == null) {
			return "";
		}
		StringBuffer sb = new StringBuffer();
		int tmp;
		for (int i = 0; i < data.length; i++) {
			tmp = data[i] >= 0 ? data[i] : 256 + data[i];
			if (tmp < 16) {
				sb.append('0');
			}
			sb.append(Integer.toHexString(tmp));
		}
		return sb.toString().toUpperCase();
	}

	public static byte[] hexStringToByteArray(String data) {
		if (data == null || data.length() == 0 || (data.length() % 2) != 0) {
			return null;
		}
		int len = data.length() / 2;
		byte[] result = new byte[len];
		String tmp;
		for (int i = 0; i < len; i++) {
			tmp = data.substring(i * 2, (i + 1) * 2);
			try {
				result[i] = (byte) Integer.parseInt(tmp, 16);
			} catch (Exception e) {

				result[i] = 0x00;
			}
		}
		return result;
	}

	public static int bytes2Integer(byte[] byteVal) {
		int result = 0;
		for (int i = 0; i < byteVal.length; i++) {
			int tmpVal = (byteVal[i] << (8 * (3 - i)));
			switch (i) {
			case 0:
				tmpVal = tmpVal & 0xFF000000;
				break;
			case 1:
				tmpVal = tmpVal & 0x00FF0000;
				break;
			case 2:
				tmpVal = tmpVal & 0x0000FF00;
				break;
			case 3:
				tmpVal = tmpVal & 0x000000FF;
				break;
			default:
				break;
			}
			result = result | tmpVal;
		}
		return result;
	}
	
	public static byte[] int2Bytes(int intVal) {
		byte[] b = new byte[4];
		for (int i=0; i<4; i++) {
			int offset = (b.length -1 -i) * 8;
			b[i] = (byte) ((intVal >>> offset) & 0xFF);
		}
		return b;
	}
	
	public	static	void	intToBytes(int value, byte[] b, int off, int len)
	throws	Exception {
	//len -> %0*d
	byte[]	bt = String.valueOf(value).getBytes();
	if (len<bt.length) {
		throw new Exception("Buffer Overflow");
	}
	for (int i=0;i<len-bt.length; i++) {
		b[off+i] = '0';
	}
	System.arraycopy(bt, 0, b, off+len-bt.length, bt.length);
	return;
}
	
	/**
	 * @param byteVal 长度为2的字节数组
	 * @return 
	 */
	public static int bytes2Short(byte[] byteVal) {
		return ((byteVal[0]<<8) + (byteVal[1]&0xff));
	}
	
	public static byte[] short2Bytes(short shortVal) {
		byte[] shortBuf = new byte[2];
		for (int i=0; i<2; i++) {
			int offset = (shortBuf.length-1-i) * 8;
			shortBuf[i] = (byte) ((shortVal>>>offset) & 0xff);
		}
		return shortBuf;
	}
	
	public	static	int	bytesToInt(byte[] b, int off, int len) {
		return	Integer.parseInt(new String(b, off, len));
	}	
	/**
	 * 完整截取字节，考虑汉字的情况
	 * @param b
	 * @param len
	 * @return
	 * @throws UnsupportedEncodingException 
	 */
	public static byte[] intactInterceptBytes(byte[] b,int bytelen,String encoder) throws UnsupportedEncodingException{
	if (b.length<=bytelen){
		return b;
	}else{
		byte[] dest_b=new byte[bytelen+1];
		System.arraycopy(b, 0, dest_b, 0, bytelen+1);
		String str=new String(dest_b,encoder);
		str=str.substring(0, str.length()-1);		
		return str.getBytes(encoder);	
	}
	}
	
	/**
	 * 给定字符串 ，根据传入字符串 ，截取的字节长度，进行截取操作，考虑汉字的情况
	 * @param  传入原字符串
	 * @param len
	 * @return
	 * @throws UnsupportedEncodingException 
	 */
	public static String intactInterceptBytes(String srcstr,int bytelen,String encoder) throws UnsupportedEncodingException{
		byte[] b=srcstr.getBytes(encoder); 
		if (b.length<=bytelen){
		return srcstr;
	}else{
		byte[] dest_b=new byte[bytelen+1];
		System.arraycopy(b, 0, dest_b, 0, bytelen+1);
		String str=new String(dest_b,encoder);
		str=str.substring(0, str.length()-1);		
		return str;	
	}
		
	}
	/**
	 * 截取字节
	 * @param b
	 * @param len
	 * @return
	 */
	public static byte[] interceptBytes(byte[] b,int len ){
	if (b.length<=len){
		return b;
	}else{
		byte[] dest_b=new byte[len];
		System.arraycopy(b, 0, dest_b, 0, len); 
		return dest_b; 
	}
	}
	/**
	 * 从原字符串中拷贝 制定长度数据
	 * @param srcBytes
	 * @param offset
	 * @param len
	 * @return
	 */
	public static byte[] selfCopy(byte[]srcBytes,int offset,int len){
		int realLen = getRealLen( srcBytes,   offset,   len);
		byte[]outArr =null;
		if(realLen>0){
			outArr =new byte[realLen];
			try {
				System.arraycopy(srcBytes, offset, outArr, 0, realLen);
				return outArr;
			} catch (Exception e) {
				outArr=null;
			}
		}
		return outArr;
	}
	 
	
	public static int getRealLen(byte[] srcBytes, int offset, int len) {
		int realLen = len>0?len:0;
		if (len > 0 && srcBytes != null && srcBytes.length > offset
				&& offset >= 0) {
			if ((offset + len) > srcBytes.length) {
				realLen = srcBytes.length - offset;
			}
		}
		return realLen;
	} 
	/**
	 * 追加字节
	 * @param srcBytes
	 * @param addBytes
	 * @return
	 */
	public static byte[] add(byte[] srcBytes,byte[] addBytes){
		byte[] newbytes=new byte[srcBytes.length+addBytes.length];
		System.arraycopy(srcBytes, 0, newbytes, 0, srcBytes.length);
		System.arraycopy(addBytes, 0, newbytes,  srcBytes.length, addBytes.length);
		return newbytes;
	}
	 /**
	  * 填充固定长度的数据
	  * @param srcBytes 原字节数组
	  * @param filllen   填充的数据长度
	  * @param fillbyte  填充的字节
	  * @param isLast    是否是后面追加，TRUE 在后面追加，false 前面追加
	  * @return
	  */
	public static byte[] fillFixByte(byte[] srcBytes,int filllen ,byte fillbyte,boolean isLast){
		byte[] fillbytes=new byte[filllen];
		for (int i=0;i<filllen;i++){
			fillbytes[i]=fillbyte;
		}
		if (isLast){
			return add(srcBytes,fillbytes);
		}else{
			return add(fillbytes,srcBytes);
		}
	 
		
	}
	
	public static void main(String[] arg){
		String a="1涂ss长东111东";
		try {
			for (int i=1;i<15;i++){
			System.out.println(i+":"+ByteUtils.intactInterceptBytes(a,i, "GBK"));
			}
		} catch (UnsupportedEncodingException e) { 
			e.printStackTrace();
		}
		
	}
}
