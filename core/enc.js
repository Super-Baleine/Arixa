var enc_gcm = function(pass, plt){
	var sALT = sjcl.random.randomWords(2);

	var key = derivation(sALT, pass);
	var plt = str(plt);

	var initvector = sjcl.random.randomWords(4);
	console.log(initvector);

	var a = sjcl.random.randomWords(1);
	console.log(a)

	var enc = new sjcl.cipher.aes(key);
	var ciphered = sjcl.mode.gcm.encrypt(enc, plt, initvector, a, 128)

	return packet(ciphered, sALT, a, initvector);
}

var packet = function(c, s, a, i){
	var c = sjcl.codec.hex.fromBits(c); //ciphered text
	var s = sjcl.codec.hex.fromBits(s); //salt
	var a = sjcl.codec.hex.fromBits(a); //authentification data
	var i = sjcl.codec.hex.fromBits(i); //initialization vector
	var packaged = c+":"+s+":"+a+":"+i;
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
