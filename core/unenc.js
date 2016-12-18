var unenc_gcm = function(passwd, t){
 	var split = t.split("/"); //get the parameters
	var c = sjcl.codec.hex.toBits(split[0]);//...
	var s = sjcl.codec.hex.toBits(split[1]);//...
	var a = sjcl.codec.hex.toBits(split[2]);//...
	var i = sjcl.codec.hex.toBits(split[3]);//up to there

	var key = derivation(s, passwd); //we need the key to decrypt the ct

	var enc = new sjcl.cipher.aes(key);
	var plt = sjcl.mode.gcm.decrypt(enc, c, i, a, 128); //decrypt it!
	var plt = sjcl.codec.utf8String.fromBits(plt); //turn the bytes array into a utf8 string

	return plt; //return the string (plaintext)
}
