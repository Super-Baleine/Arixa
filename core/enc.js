var mode = {};
mode.gcm = {};
mode.ccm = {};
mode.ocb2 = {};

mode.gcm.encrypt = function(pass, plt){
	var sALT = sjcl.random.randomWords(2); //2*4=8 bytes

	var key = derivation(sALT, pass); //key derivation process
	var plt = str(plt); //turn the string into a bytes array

	var initvector = sjcl.random.randomWords(4); //4*4=16 bytes

	var a = sjcl.random.randomWords(1); //authentification data 4 bytes

	var enc = new sjcl.cipher.aes(key);
	var ciphered = sjcl.mode.gcm.encrypt(enc, plt, initvector, a, 128) //encrypt it!

	return packet(ciphered, sALT, a, initvector); //return a packet with the ct and its parameters
}

mode.ccm.encrypt = function(pass, plt){
	var sALT = sjcl.random.randomWords(2); //2*4=8 bytes

	var key = derivation(sALT, pass); //key derivation process
	var plt = str(plt); //turn the string into a bytes array

	var initvector = sjcl.random.randomWords(4); //4*4=16 bytes

	var a = sjcl.random.randomWords(1); //authentification data 4 bytes

	var enc = new sjcl.cipher.aes(key);
	var ciphered = sjcl.mode.ccm.encrypt(enc, plt, initvector, a, 128) //encrypt it!

	return packet(ciphered, sALT, a, initvector); //return a packet with the ct and its parameters
}

mode.ocb2.encrypt = function(pass, plt){
	var sALT = sjcl.random.randomWords(2); //2*4=8 bytes

	var key = derivation(sALT, pass); //key derivation process
	var plt = str(plt); //turn the string into a bytes array

	var initvector = sjcl.random.randomWords(4); //4*4=16 bytes

	var a = sjcl.random.randomWords(1); //authentification data 4 bytes

	var enc = new sjcl.cipher.aes(key);
	var ciphered = sjcl.mode.ocb2.encrypt(enc, plt, initvector, a, 128) //encrypt it!

	return packet(ciphered, sALT, a, initvector); //return a packet with the ct and its parameters
}



mode.gcm.decrypt = function(passwd, t){
	var split = t.split(":"); //get the parameters
	var c = sjcl.codec.base64.toBits(split[0]);//...
	var s = sjcl.codec.base64.toBits(split[1]);//...
	var a = sjcl.codec.base64.toBits(split[2]);//...
	var i = sjcl.codec.base64.toBits(split[3]);//up to there

	var key = derivation(s, passwd); //we need the key to decrypt the ct

	var enc = new sjcl.cipher.aes(key);
	var plt = sjcl.mode.gcm.decrypt(enc, c, i, a, 128); //decrypt it!
	var plt = sjcl.codec.utf8String.fromBits(plt); //turn the bytes array into a utf8 string

	return plt; //return the string (plaintext)
}

mode.ccm.decrypt = function(passwd, t){
	var split = t.split(":"); //get the parameters
	var c = sjcl.codec.base64.toBits(split[0]);//...
	var s = sjcl.codec.base64.toBits(split[1]);//...
	var a = sjcl.codec.base64.toBits(split[2]);//...
	var i = sjcl.codec.base64.toBits(split[3]);//up to there

	var key = derivation(s, passwd); //we need the key to decrypt the ct

	var enc = new sjcl.cipher.aes(key);
	var plt = sjcl.mode.ccm.decrypt(enc, c, i, a, 128); //decrypt it!
	var plt = sjcl.codec.utf8String.fromBits(plt); //turn the bytes array into a utf8 string

	return plt; //return the string (plaintext)
}

mode.ocb2.decrypt = function(passwd, t){
	var split = t.split(":"); //get the parameters
	var c = sjcl.codec.base64.toBits(split[0]);//...
	var s = sjcl.codec.base64.toBits(split[1]);//...
	var a = sjcl.codec.base64.toBits(split[2]);//...
	var i = sjcl.codec.base64.toBits(split[3]);//up to there

	var key = derivation(s, passwd); //we need the key to decrypt the ct

	var enc = new sjcl.cipher.aes(key);
	var plt = sjcl.mode.ocb2.decrypt(enc, c, i, a, 128); //decrypt it!
	var plt = sjcl.codec.utf8String.fromBits(plt); //turn the bytes array into a utf8 string

	return plt; //return the string (plaintext)
}


var packet = function(c, s, a, i){
	var c = sjcl.codec.base64.fromBits(c); //ciphered text
	var s = sjcl.codec.base64.fromBits(s); //salt
	var a = sjcl.codec.base64.fromBits(a); //authentification data
	var i = sjcl.codec.base64.fromBits(i); //initialization vector
	var packaged = c+":"+s+":"+a+":"+i; //join it
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
