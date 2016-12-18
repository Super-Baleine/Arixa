var unenc_gcm = function(passwd, t){
 	var split = t.split(":");
	var c = sjcl.codec.hex.toBits(split[0]);
	var s = sjcl.codec.hex.toBits(split[1]);
	var a = sjcl.codec.hex.toBits(split[2]);
	var i = sjcl.codec.hex.toBits(split[3]);

	var key = derivation(s, passwd);

	var enc = new sjcl.cipher.aes(key);
	var plt = sjcl.mode.gcm.decrypt(enc, c, i, a, 128);
	var plt = sjcl.codec.utf8String.fromBits(plt);

	return plt;
}
