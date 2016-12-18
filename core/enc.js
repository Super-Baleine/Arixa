var gcm = function(pass, plt){
	var sALT = sjcl.random.randomWords(2);

	var key = derivation(sALT, pass);
	var plt = str(plt);

	var initvector = sjcl.random.randomWords(4);

	var a = sjcl.random.randomWords(1);

	var enc = new sjcl.cipher.aes(key);
	var ciphered = sjcl.mode.gcm.encrypt(enc, plt, initvector, a, 128)

	return packet(ciphered, sALT, a, initvector);
}

var packet = function(c, s, a, i){
	var c = sjcl.codec.base64.fromBits(c);
	var s = sjcl.codec.base64.fromBits(s);
	var a = sjcl.codec.base64.fromBits(a);
	var i = sjcl.codec.base64.fromBits(i);
	var packaged = c+s+a+i;
	return packaged;
}


var derivation = function(sALT, passwd){
	var key = sjcl.misc.pbkdf2(passwd, sALT, 2000, 256);
	return key;
}

var str = function(str){
	var str = sjcl.codec.utf8String.toBits(str);
	return str;
}
