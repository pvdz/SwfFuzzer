var SwfFuzzer = function(options){
	this.options = options || {};
};
SwfFuzzer.pack = function(n, len){
//	n >>>= 0;
	if (len == 4) return String.fromCharCode(n&0xff, n>>8&0xff, n>>16&0xff, n>>24&0xff)
	if (len == 3) return String.fromCharCode(n&0xff, n>>8&0xff, n>>16&0xff)
	if (len == 2) return String.fromCharCode(n&0xff, n>>8&0xff)
	return String.fromCharCode(n&0xff)
};
SwfFuzzer.convertToBin = function(n, len){
	var bin = n.toString(2);
	while (bin.length < len) bin = '0'+bin;
	return bin;
};
SwfFuzzer.randomNumberUpTo = function(limit){
	return SwfFuzzer.randomNumberBetween(0, limit);
};
SwfFuzzer.randomNumberBetween = function(start, stop) {
	return start + Math.floor(Math.random() * (stop-start));
};
SwfFuzzer.zeroPadBinaryRight = function(bin, count){
	var rest = count - (bin.length % count);
	if (rest < count) while (rest--) bin += '0'; // bit padding
	return bin;
},
SwfFuzzer.binToBytes = function(bin){
	bin = SwfFuzzer.zeroPadBinaryRight(bin, 8);
	var bytes = bin.split(/(?=(?:.{8})+$)/).map(function(n){ return parseInt(n,2); });
	return bytes;
},
SwfFuzzer.prototype = {
	getSwf: function(){
		var body = this.getSwfBody();
		var header = this.getHeader(body.length);

		return header+body;
	},
	getSwfBody: function(){
		var count = this.getTagCount();
		var tags = this.generateRandomTags(count);
		tags.push(this.getEndTag());
		
		return tags.join('');
	},
	getTagCount: function(){
		if (typeof this.options.tagCount == 'number') return this.options.tagCount;
		return this.getRandomTagCount();
	},
	getRandomTagCount: function(bodyLen){
		return SwfFuzzer.randomNumberBetween(1, 20);
	},
	getHeader: function(bodyLen){
		var pre = this.getPreHeader();
		var post = this.getPostHeader();
		
		return this.combineHeaderPartsWithLen(pre, post, bodyLen);
	},
	combineHeaderPartsWithLen: function(pre, post, bodyLen){
		var len = this.getLenPacked(pre.length + post.length + bodyLen);
		
		return pre+len+post;
	},
	getPreHeader: function(){
		return this.getSignature()+this.getVersionPacked();
	},
	getPostHeader: function(){
		return this.getRect()+this.getFpsPacked()+this.getFramesPacked();
	},
	getSignature: function(){
		return 'FWS';
	},
	getVersionPacked: function(){
		return SwfFuzzer.pack(this.createVersionNumber(), 1);
	},
	createVersionNumber: function(){
		if (typeof this.options.version == 'number') return this.options.version;
		return this.createRandomVersionNumber();
	},
	createRandomVersionNumber: function() {
		return SwfFuzzer.randomNumberUpTo(0xff);
	},
	getLenPacked: function(realLen){
		return SwfFuzzer.pack(this.createLenNumber(realLen), 4);
	},
	createLenNumber: function(realLen){
		if (typeof this.options.len == 'number') return this.options.len;
		if (this.options.randomHeaderLen) return this.createRandomLanNumber();
		return realLen + 4;
	},
	createRandomLanNumber: function(){
		return SwfFuzzer.randomNumberUpTo(0xffffffff);
	},
	getRect: function(){
		// a rect consists of a 5 bit field-bit-length field
		// then four fields of that number of bits
		var bits = this.createRectFieldLengthNumber();
		var x1 = this.createRectCoordinateNumber('x1', bits);
		var y1 = this.createRectCoordinateNumber('y1', bits);
		var x2 = this.createRectCoordinateNumber('x2', bits);
		var y2 = this.createRectCoordinateNumber('y2', bits);
		
		return this.createRectString(bits, x1, y1, x2, y2);
	},
	createRectString: function(bits, x1, y1, x2, y2){
		var bin = this.constructBinaryRect(bits, x1, y1, x2, y2);
		var bytes = SwfFuzzer.binToBytes(bin);
		var string = String.fromCharCode.apply(String, bytes);
		
		return string;
	},
	constructBinaryRect: function(bits, x1, y1, x2, y2){
		return SwfFuzzer.convertToBin(bits, 5)+SwfFuzzer.convertToBin(x1, bits)+SwfFuzzer.convertToBin(y1, bits)+SwfFuzzer.convertToBin(x2, bits)+SwfFuzzer.convertToBin(y2, bits);
	},
	createRectFieldLengthNumber: function(){
		if (typeof this.options.rectFieldSize == 'number') return this.options.rectFieldSize;
		return this.createRandomRectFieldLengthNumber();
	},
	createRandomRectFieldLengthNumber: function(){
		return SwfFuzzer.randomNumberUpTo(Math.pow(2, 5));
	},
	createRectCoordinateNumber: function(target, maxBits){
		var result = null;
		switch (target) {
			case 'x1':
				result = this.options.rectX1;
				break;
			case 'y1':
				result = this.options.rectY1;
				break;
			case 'x2':
				result = this.options.rectX2;
				break;
			case 'y2':
				result = this.options.rectY2;
				break;
		}

		if (typeof result != 'number') result = this.createRandomRectCoordinateNumber(maxBits);
		
		return result;
	},
	createRandomRectCoordinateNumber: function(maxBits){
		if (typeof maxBits == 'number') var max = Math.pow(2, maxBits);
		else var max = Math.pow(2, 5);
		return SwfFuzzer.randomNumberUpTo(max);
	},
	getFpsPacked: function(){
		return '\x00'+SwfFuzzer.pack(this.createFpsNumber(),1);
	},
	createFpsNumber: function(){
		if (typeof this.options.fps == 'number') return this.options.fps;
		return this.createRandomFpsNumber();
	},
	createRandomFpsNumber: function(){
		return SwfFuzzer.randomNumberUpTo(0xff);
	},
	getFramesPacked: function(){
		return SwfFuzzer.pack(this.createFramesNumber(), 2);
	},
	createFramesNumber: function(){
		return this.options.frames;
	},
	createRandomFramesNumber: function(){
		return SwfFuzzer.randomNumberUpTo(0xffff);
	},
	getCompleteTag: function(){
		var type = this.createTagType();
		var len = this.createTagLen();
		return this.combineAndPackTagTypeAndLen(type, len)+this.getTagBody(len);
	},
	createTagType: function(){
		if (typeof this.options.tagType == 'number') return this.options.tagType;
		return this.createRandomTagType();
	},
	createRandomTagType: function(){
		return SwfFuzzer.randomNumberBetween(1, 256);
	},
	createTagLen: function(){
		if (typeof this.options.tagLen == 'number') return this.options.tagLen;
		return this.createRandomTagLen();
	},
	createRandomTagLen: function(){
		if (Math.random() < 0.5) return this.createSmallRandomTagLen();
		else return this.createBigRandomTagLen();
	},
	createSmallRandomTagLen: function(){
		return SwfFuzzer.randomNumberUpTo(63);
	},
	createBigRandomTagLen: function(){
		return SwfFuzzer.randomNumberUpTo(0x1000);
	},
	combineAndPackTagTypeAndLen: function(type, len){
		var str = this.packTagTypeAndLen(this.combineTagTypeAndLen(type, len));
		if (len >= 63) str += SwfFuzzer.pack(len, 4);
		return str;
	},
	combineTagTypeAndLen: function(type, len){
		// 1023 = 10 bits, 63 = 6 bits
		return ((type&1023)<<6)|(len>63?63:len);
	},
	packTagTypeAndLen: function(typeLen){
		return SwfFuzzer.pack(typeLen,2);
	},
	getTagBody: function(len){
		if (this.options.tagBody != null) return this.options.tagBody;
		return this.createRandomTagBody(len);
	},
	createRandomTagBody: function(len){
		var arr = [];
		while (len--) arr.push(Math.floor(Math.random() * 256));
		return String.fromCharCode.apply(String, arr);
	},
	generateRandomTags: function(count){
		var tags = [];
		while (count--) {
			tags.push(this.getCompleteTag());
		}
		return tags;
	},
	getEndTag: function(){
		return '\x00';
	},
};

if (typeof window == 'undefined') module.exports = SwfFuzzer;
