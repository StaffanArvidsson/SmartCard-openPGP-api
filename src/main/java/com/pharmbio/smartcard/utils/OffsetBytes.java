package com.pharmbio.smartcard.utils;

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
    	byte[] ret = new byte[cnt];
    	for(int i=0; i<cnt; i++){
    		ret[i] = bytes[offset + i];
    	}
    	
        offset += cnt;
        return ret;
    }

    public int nextAsInt() {
        return (int) bytes[offset++];
    }

    public boolean check(byte[] checked) {
        byte[] has = next(checked.length);
        for(int i=0; i<checked.length; i++){
            if(checked[i] != has[i]) 
            	return false;
        }
        return true;
    }

    public boolean check(int checked) {
        return check(new byte[]{(byte) checked});
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
    	StringBuilder output = new StringBuilder();
    	for(int i=0;i<offset; i++){
    		output.append(Integer.toHexString(bytes[i] & 0xff)).append(' ');
    	}
    	output.append("||");
    	for(int i=offset; i<bytes.length;i++){
    		output.append(' ').append(Integer.toHexString(bytes[i]));
    	}
    	return output.toString();
    }
}
