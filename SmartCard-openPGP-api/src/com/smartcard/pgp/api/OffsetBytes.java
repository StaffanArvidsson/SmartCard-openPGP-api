package com.smartcard.pgp.api;

import java.util.ArrayList;

public class OffsetBytes {
	
	private byte[] bytes;
	private int offset;
	
	public OffsetBytes(byte[] bytes, int offset){
		this.bytes = bytes;
		this.offset = offset;
	}
	
    public byte next() {
        return bytes[offset++];
    }

    public byte[] next(int cnt) {
//        val ret = bytes.sliceArray((offset..offset+cnt-1))
    	byte[] ret = new byte[cnt];
    	for(int i=0; i<cnt; i++){
    		ret[i] = bytes[offset + i];
    	}
    	
        offset += cnt;
        return ret;
    }

    public int nextAsInt() {
        return (int) bytes[offset++]; //.toInt() and 0xff
    }

    public boolean check(byte[] checked) {
        byte[] has = next(checked.length);
//        for(i in 0..checked.size-1) {
        for(int i=0; i<checked.length; i++){
            if(checked[i] != has[i]) 
            	return false;
        }
        return true;
    }

    public boolean check(int checked) {
        return check(new byte[]{(byte) checked});// byteArrayOf(checked.toByte()));
    }

    public boolean check(int... checked) {
    	byte[]toCheck= new byte[checked.length];
    	for(int i=0;i<checked.length;i++){
    		toCheck[i]=(byte) checked[i];
    	}
        return check(toCheck);
    }

    public byte get(int i) {
        return bytes[i];
    }

    public String toString() {
//    	String[] bytesAsHex = new String[bytes.length];
    	StringBuilder output = new StringBuilder();
    	for(int i=0;i<offset; i++){
    		output.append(Integer.toHexString(bytes[i] & 0xff) + " ");
//    		bytesAsHex[i] = Integer.toHexString(bytes[i]);	
    	}
//        val printed = bytes.map {
//            val v = it.toInt() and 0xff
//            Integer.toHexString(v)
//        }
    	output.append("||");
    	for(int i=offset; i<bytes.length;i++){
    		output.append(" " + Integer.toHexString(bytes[i]));
    	}
    	return output.toString();
//        return printed.take(offset).joinToString(" ") + " || " + printed.takeLast(printed.size - offset).joinToString(" ");
    }
}
