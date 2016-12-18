var enc_gcm = function(pass, plt){
	var sALT = sjcl.random.randomWords(2); //2*4=16 bytes

	var key = derivation(sALT, pass); //key derivation process
	var plt = str(plt); //turn the string into a bytes array

	var initvector = sjcl.random.randomWords(4); //4*4=16 bytes

	var a = sjcl.random.randomWords(1); //authentification data 4 bytes

	var enc = new sjcl.cipher.aes(key);
	var ciphered = sjcl.mode.gcm.encrypt(enc, plt, initvector, a, 128) //encrypt it!

	return packet(ciphered, sALT, a, initvector); //return a packet with the ct and its parameters
}

var packet = function(c, s, a, i){
	var c = sjcl.codec.hex.fromBits(c); //ciphered text
	var s = sjcl.codec.hex.fromBits(s); //salt
	var a = sjcl.codec.hex.fromBits(a); //authentification data
	var i = sjcl.codec.hex.fromBits(i); //initialization vector
	var packaged = c+"/"+s+"/"+a+"/"+i; //join it
	return packaged;
}


var derivation = function(sALT, passwd){
	var key = sjcl.misc.pbkdf2(passwd, sALT, 2000, 256); //2000: iteration for strengthen by factor
	return key; //bytes array
}

var str = function(str){
	var str = sjcl.codec.utf8String.toBits(str); //we need to turn it into a bytes array
	return str;
}
