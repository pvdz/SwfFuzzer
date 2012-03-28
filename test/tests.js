if (typeof window == 'undefined') var SwfFuzzer = require('../src/swffuzzer.js');

var tests = [
	function getEmptySwfWithSpecificHeadersFromFuzzer(){
		var fuzzer = new SwfFuzzer({version: 3, len: 0x4f, fps: 0xc, frames: 1, rectFieldSize:15, rectX1:0, rectY1:11000, rectX2:0, rectY2:8000, tagCount:0});
		var swf = fuzzer.getSwf();
		// rect: 011110000000000000000101010111110000000000000000000011111010000000000000
		// 01111 = 15, 4x15=60, 60+5/8=<8:1> (=9)
		// x1=000000000000000=0
		// y1=010101011111000=11000
		// x2=000000000000000=0
		// y2=001111101000000=8000
		// pad=0000000

		             // fws v   len(4)          rect (9)                            fps(2)  frames  end-tag
		return swf === 'FWS\x03\x4f\x00\x00\x00\x78\x00\x05\x5f\x00\x00\x0f\xa0\x00\x00\x0c\x01\x00\x00';
	},
	function generateRandomSwfs(){
		for (var i=0; i<100; ++i) {
			new SwfFuzzer().getSwf();
		}
		// just dont crash. :)
		return true;
	},
	function generateEmptySwf(){
		var fuzzer = new SwfFuzzer({tagCount: 0});
		var swf = fuzzer.getSwfBody();

		return swf.length == 1;
	},
	function tagBodyLenShouldBeValidWhenRequested(){
		var fuzzer = new SwfFuzzer({randomHeaderLen: false});
		
		var pre = fuzzer.getPreHeader();
		var post = fuzzer.getPostHeader();
		var body = fuzzer.getSwfBody();
		var len = fuzzer.createLenNumber(pre.length + post.length + body.length);

		return len == pre.length + 4 + post.length + body.length;
	},
	function tagBodyLenShouldBeValidWhenRequested(){
		var fuzzer = new SwfFuzzer({randomHeaderLen: false});
		
		var pre = fuzzer.getPreHeader();
		var post = fuzzer.getPostHeader();
		var body = fuzzer.getSwfBody();
		var len = fuzzer.createLenNumber(pre.length + post.length + body.length);

		return len == pre.length + 4 + post.length + body.length;
	},
	function moreThoroughHeaderLenCheck(){
		var good = true;
		for (var i=0; i<100; ++i) {
			var fuzzer = new SwfFuzzer({randomHeaderLen: false});
			
			var pre = fuzzer.getPreHeader();
			var post = fuzzer.getPostHeader();
			var body = fuzzer.getSwfBody();
	
			var header = fuzzer.combineHeaderPartsWithLen(pre, post, body.length);
			// now extract the length...
			// swf file header starts with signature (3 bytes) and version (1 byte).
			// so size field (4 bytes) starts at 5th byte, will be in little endian.
			var len = header.charCodeAt(4);
			len |= (header.charCodeAt(5) << 8);
			len |= (header.charCodeAt(6) << 16);
			len |= (header.charCodeAt(7) << 24);
			
			good = len === pre.length+4+post.length+body.length;
		}
		
		return good;
	},
	function headerShouldCombineWithLenProperly(){
		var fuzzer = new SwfFuzzer({len: 1});
		var swf = fuzzer.combineHeaderPartsWithLen('a', 'b', 5);

		return swf === 'a\x01\x00\x00\x00b';
	},
	function tagCountShouldBeUsed(){
		var fuzzer = new SwfFuzzer({tagCount: 5, tagLen: 1});
		var swf = fuzzer.getSwfBody();

		return swf.length == 16; // per tag, 2 bytes header and 1 byte body. 5x3=15. one byte for endTag => 16.
	},
	function getHeaderFromFuzzer(){
		var fuzzer = new SwfFuzzer({version: 3, len: 0x4f, fps: 0xc, frames: 1, rectFieldSize:15, rectX1:0, rectY1:11000, rectX2:0, rectY2:8000});
		var header = fuzzer.getHeader();
		
		return header === 'FWS\x03\x4f\x00\x00\x00\x78\x00\x05\x5f\x00\x00\x0f\xa0\x00\x00\x0c\x01\x00';
	},
	function getSignatureFromFuzzer(){
		var fuzzer = new SwfFuzzer();
		var sig = fuzzer.getSignature();
		
		return sig === 'FWS';
	},
	function versionParameterShouldBeUsed(){
		var fuzzer = new SwfFuzzer({version:3});
		var version = fuzzer.createVersionNumber();
		
		return version === 3;
	},
	function versionParameterZeroShouldBeUsed(){
		var fuzzer = new SwfFuzzer({version:0});
		var version = fuzzer.createVersionNumber();
		
		return version === 0;
	},
	function noVersionShouldReturnFuzzyVersion(){
		// return value is fuzzy. Sample it a few times.
		var good = true;
		for (var i=0; i<10 && good; ++i) {
			var fuzzer = new SwfFuzzer();
			var version = fuzzer.createRandomVersionNumber();
			good = (typeof version == 'number' && version >= 0 && version < 0x100);
		}
		
		return good;
	},
	function versionFieldIsOneByte(){
		var fuzzer = new SwfFuzzer({version:4});
		var version = fuzzer.getVersionPacked();
		
		return version === '\x04';
	},
	function lenParameterShouldBeUsed(){
		var fuzzer = new SwfFuzzer({len:0x4f});
		var len = fuzzer.createLenNumber();

		return len === 0x4f;
	},
	function lenParameterZeroShouldBeUsed(){
		var fuzzer = new SwfFuzzer({len:0});
		var len = fuzzer.createLenNumber();

		return len === 0;
	},
	function noLenShouldReturnFuzzyLen(){
		var good = true;
		for (var i=0; i<10 && good; ++i) {
			var fuzzer = new SwfFuzzer();
			var len = fuzzer.createRandomLanNumber();

			good = typeof len == 'number' && len >= 0 && len < 0x100000000;
		}
		
		return good;
	},
	function lenFieldIsFourBytes(){
		var fuzzer = new SwfFuzzer({len: 0x500});
		var len = fuzzer.getLenPacked();
		
		return len === '\x00\x05\x00\x00';
	},
	function eightBitsShouldReturnOneByte(){
		var bytes = SwfFuzzer.binToBytes('11101001');
		
		return bytes.length == 1;
	},
	function sixteenBitsShouldReturnTwoBytes(){
		var bytes = SwfFuzzer.binToBytes('1101001001001010');
		
		return bytes.length == 2;
	},
	function tenBitsShouldApplyPadding(){
		var bytes = SwfFuzzer.binToBytes('1001001001');
		
		return bytes.length == 2;
	},
	function applyNoPadding8(){
		var str = SwfFuzzer.zeroPadBinaryRight('10102343', 8);
		
		return str.length === 8;
	},
	function applyNoPadding16(){
		var str = SwfFuzzer.zeroPadBinaryRight('1010234345774587', 8);
		
		return str.length === 16;
	},
	function applyPadding17(){
		var str = SwfFuzzer.zeroPadBinaryRight('10102343457745871', 8);
		
		return str.length === 24;
	},
	function manyBitsShouldApplyPadding(){
		var bytes = SwfFuzzer.binToBytes('01111'+'000000000000000'+'010101011111000'+'000000000000000'+'001111101000000');
		
		return bytes.join(' ') === '120 0 5 95 0 0 15 160 0';
	},
	function bitCountDeterminesBinLength(){
		var fuzzer = new SwfFuzzer();
		var bin = fuzzer.constructBinaryRect(10,0,0,0,0);
		
		return bin.length === 5+10+10+10+10;
	},
	function paramsShouldBeConvertedToBinaryString(){
		var fuzzer = new SwfFuzzer();
		var bin = fuzzer.constructBinaryRect(10,1,2,3,4);
		
		return bin === '01010'+'0000000001'+'0000000010'+'0000000011'+'0000000100';
	},
	function bigParamsShouldBeConvertedToBinaryString(){
		var fuzzer = new SwfFuzzer();
		var bin = fuzzer.constructBinaryRect(15,0,11000,0,8000);
		
		return bin === '01111'+'000000000000000'+'010101011111000'+'000000000000000'+'001111101000000';
	},
	function rectFieldSizeArgumentShouldBeUsed(){
		var fuzzer = new SwfFuzzer({rectFieldSize: 19});
		var bits = fuzzer.createRectFieldLengthNumber();
		
		return bits === 19;
	},
	function noRectFieldShouldAlwaysReturnNumber(){
		var fuzzer = new SwfFuzzer();
		var bits = fuzzer.createRectFieldLengthNumber();
		
		return typeof bits == 'number';
	},
	function noRectFieldSizeArgumentShouldReturnFuzzy(){
		var maxNumberOfBits = Math.pow(2, 5);
		var good = true;
		for (var i=0; i<10 && good; ++i) {
			var fuzzer = new SwfFuzzer({rectFieldSize: 19});
			var bits = fuzzer.createRandomRectFieldLengthNumber();
			
			good = typeof bits == 'number' && bits >= 0 && bits < maxNumberOfBits;
		}
		
		return good;
	},
	function rectCoordinateX1ShouldBeUsed(){
		var fuzzer = new SwfFuzzer({rectX1: 10});
		var x1 = fuzzer.createRectCoordinateNumber('x1', 15);
		
		return x1 === 10;
	},
	function rectCoordinateY1ShouldBeUsed(){
		var fuzzer = new SwfFuzzer({rectY1: 20});
		var y1 = fuzzer.createRectCoordinateNumber('y1', 15);
		
		return y1 === 20;
	},
	function rectCoordinateX2ShouldBeUsed(){
		var fuzzer = new SwfFuzzer({rectX2: 30});
		var x2 = fuzzer.createRectCoordinateNumber('x2', 15);
		
		return x2 === 30;
	},
	function rectCoordinateY2ShouldBeUsed(){
		var fuzzer = new SwfFuzzer({rectY2: 40});
		var y2 = fuzzer.createRectCoordinateNumber('y2', 15);
		
		return y2 === 40;
	},
	function randomCoordGeneratorShouldNotExceedBits(){
		var good = true;
		for (var i=0; i<10 && good; ++i) {
			var fuzzer = new SwfFuzzer();
			var coord = fuzzer.createRandomRectCoordinateNumber(5);
			
			good = (typeof coord == 'number' && coord >= 0 && coord < Math.pow(2, 5));
		}
		
		return good;
	},
	function rectCoordinateWithMaxbitsShouldGenerateNumber(){
		var fuzzer = new SwfFuzzer();
		var coord = fuzzer.createRectCoordinateNumber(null, 5);
	
		return typeof coord == 'number' && !isNaN(coord);		
	},
	function randomRectCoordinateWithMaxbitsShouldGenerateNumber(){
		var fuzzer = new SwfFuzzer({rectMaxBits: 5});
		var coord = fuzzer.createRandomRectCoordinateNumber();
	
		return typeof coord == 'number' && !isNaN(coord);		
	},
	function noRectCoordinateArgumentWithMaxbitsShouldReturnBoundFuzzy(){
		var fieldBits = 4;
		var maxFieldSize = Math.pow(2, fieldBits);
		var good = true;
		for (var i=0; i<10 && good; ++i) {
			var fuzzer = new SwfFuzzer();
			var coord = fuzzer.createRectCoordinateNumber(null, fieldBits);

			good = (typeof coord == 'number' && coord >= 0 && coord < maxFieldSize);
		}
		
		return good;
	},
	function noRectCoordinateArgumentShouldReturnUnboundFuzzy(){ // still bound to 15 bits :)
		// you can parse up to 5 bits which make up the bit width of the other fields
		var maxFieldBitSize = Math.pow(2, 5)-1;
		var maxFieldValue = Math.pow(2, maxFieldBitSize);
		
		var good = true;
		for (var i=0; i<10 && good; ++i) {
			var fuzzer = new SwfFuzzer();
			var coord = fuzzer.createRectCoordinateNumber(null, maxFieldBitSize);

			good = (typeof coord == 'number' && coord >= 0 && coord < maxFieldValue);
		}
		
		return good;
	},
	function getRectStringFromParams(){
		var fuzzer = new SwfFuzzer();
		var string = fuzzer.createRectString(15, 0, 11000, 0, 8000);
		
//		console.log(string.split('').map(function(s){ return 'x'+s.charCodeAt(0).toString(2); }).join(' '))
//		console.log('\x78\x00\x05\x5f\x00\x00\x0f\xa0\x00'.split('').map(function(s){ return 'x'+s.charCodeAt(0).toString(2); }).join(' '))

		return string === '\x78\x00\x05\x5f\x00\x00\x0f\xa0\x00';
	},
	function getRectFromFuzzer(){
		var fuzzer = new SwfFuzzer({rectFieldSize:15, rectX1:0, rectY1:11000, rectX2:0, rectY2:8000});
		var rect = fuzzer.getRect();

		return rect == '\x78\x00\x05\x5f\x00\x00\x0f\xa0\x00';
	},
	function fpsParameterShouldBeUsed(){
		var fuzzer = new SwfFuzzer({fps:0x15});
		var fps = fuzzer.createFpsNumber();
		
		return fps == 0x15;
	},
	function fpsParameterZeroShouldBeUsed(){
		var fuzzer = new SwfFuzzer({fps:0});
		var fps = fuzzer.createFpsNumber();

		return fps == 0;
	},
	function noFpsShouldReturnFuzzyFps(){
		var good = true;
		for (var i=0; i<10 && good; ++i) {
			var fuzzer = new SwfFuzzer();
			var fps = fuzzer.createRandomFpsNumber();
			
			good = (typeof fps == 'number' && fps >= 0 && fps < 0x100);
		}
		
		return good;
	},
	function fpsFieldIsTwoBytes(){
		var fuzzer = new SwfFuzzer({fps:0x0c});
		var fps = fuzzer.getFpsPacked();
		
		return fps == '\x00\x0c';
	},
	function framesParameterShouldBeUsed(){
		var fuzzer = new SwfFuzzer({frames:1});
		var frames = fuzzer.createFramesNumber();
		
		return frames === 1;
	},
	function noFramesShouldReturnFuzzyFrames(){
		var good = true;
		for (var i=0; i<10 && good; ++i) {
			var fuzzer = new SwfFuzzer();
			var frames = fuzzer.createRandomFramesNumber();
			
			good = (typeof frames == 'number' && frames >= 0 && frames < 0x10000);
		}
		
		return good;
	},
	function framesFieldIsTwoBytes(){
		var fuzzer = new SwfFuzzer({frames:1});
		var frames = fuzzer.getFramesPacked();
		
		return frames == '\x01\x00';
	},
	function getEndTagFromFuzzer(){
		var fuzzer = new SwfFuzzer();
		var tag = fuzzer.getEndTag();
		
		return tag == '\x00';
	},
	function convert0ToOneCharBinaryLE(){
		var bin = SwfFuzzer.pack(0, 1);
		
		return bin == '\x00';
	},
	function convert2ToOneCharBinaryLE(){
		var bin = SwfFuzzer.pack(2, 1);
		
		return bin == '\x02';
	},
	function convert255ToOneCharBinaryLE(){
		var bin = SwfFuzzer.pack(255, 1);
		
		return bin == '\xff';
	},
	function convert0ToTwoCharBinaryLE(){
		var bin = SwfFuzzer.pack(0, 2);
		
		return bin == '\x00\x00';
	},
	function convert2ToTwoCharBinaryLE(){
		var bin = SwfFuzzer.pack(2, 2);
		
		return bin == '\x02\x00';
	},
	function convertxffffToTwoCharBinaryLE(){
		var bin = SwfFuzzer.pack(0xffff, 2);
		
		return bin == '\xff\xff';
	},
	function convert0ToThreeCharBinaryLE(){
		var bin = SwfFuzzer.pack(0, 3);
		
		return bin == '\x00\x00\x00';
	},
	function convert2ToThreeCharBinaryLE(){
		var bin = SwfFuzzer.pack(2, 3);
		
		return bin == '\x02\x00\x00';
	},
	function convertxffffffToThreeCharBinaryLE(){
		var bin = SwfFuzzer.pack(0xffffff, 3);
		
		return bin == '\xff\xff\xff';
	},
	function convert0ToFourCharBinaryLE(){
		var bin = SwfFuzzer.pack(0, 4);
		
		return bin == '\x00\x00\x00\x00';
	},
	function convert2ToFourCharBinaryLE(){
		var bin = SwfFuzzer.pack(2, 4);
		
		return bin == '\x02\x00\x00\x00';
	},
	function convertx47ToFourCharBinaryLE(){
		var bin = SwfFuzzer.pack(0x74, 4);
		
		return bin == '\x74\x00\x00\x00';
	},
	function convertxffffffffToFourCharBinaryLE(){
		var bin = SwfFuzzer.pack(0xffffffff, 4);
		
		return bin == '\xff\xff\xff\xff';
	},
	function optionsShouldBeOptional(){
		new SwfFuzzer();
		
		return true; // if not crash, then ok
	},
	function shouldSaveOptions(){
		var options = {};
		var fuzzer = new SwfFuzzer(options);
		
		return fuzzer.options == options;
	},
	function convert5To10CharBin(){
		var bin = SwfFuzzer.convertToBin(5, 10);

		return bin === '0000000101';
	},
	function convert645To20CharBin(){
		var bin = SwfFuzzer.convertToBin(645, 20);

		return bin === '00000000001010000101';
	},
	function getCompleteTagFromFuzzer(){
		var fuzzer = new SwfFuzzer({tagType:9, tagLen:3, tagBody: '\xff\xff\xff'});
		var tag = fuzzer.getCompleteTag();
		
		return tag === '\x43\x02\xff\xff\xff';
	},
	function getTagTypeFromFuzzer(){
		var good = true;
		for (var i=0; i<100 && good; ++i) {
			var fuzzer = new SwfFuzzer();
			var tag = fuzzer.createTagType();
			
			good = (typeof tag == 'number' && tag > 0 && tag < 256);
		}
		
		return good;
	},
	function getTagLenFromFuzzer(){
		var good = true;
		for (var i=0; i<100 && good; ++i) {
			var fuzzer = new SwfFuzzer();
			var tag = fuzzer.createTagLen();
			
			good = (typeof tag == 'number' && tag >= 0 && tag < 0x100000000);
		}
		
		return good;
	},
	function tagLenShouldBeUsed(){
		var fuzzer = new SwfFuzzer({tagLen: 10});
		var len = fuzzer.createTagLen();

		return len == 10;
	},
	function smallTagLenHasSmallHeader(){
		var fuzzer = new SwfFuzzer();
		var str = fuzzer.combineAndPackTagTypeAndLen(15, 60);

		return str === '\xfc\x03';
	},
	function bigTagLenIsFourBytesBigger(){
		var fuzzer = new SwfFuzzer();
		var str = fuzzer.combineAndPackTagTypeAndLen(15, 300);

		return str === '\xff\x03\x2c\x01\x00\x00';
	},
	function startOfBigTagHeaderLenShouldAlwaysBeEqual(){
		var fuzzer = new SwfFuzzer();
		
		return fuzzer.combineAndPackTagTypeAndLen(15, 63).substring(0,2) === fuzzer.combineAndPackTagTypeAndLen(15, 300).substring(0,2);
	},
	function tagTypeShouldBeUsed(){
		var fuzzer = new SwfFuzzer({tagType: 20});
		var len = fuzzer.createTagType();

		return len == 20;
	},
	function combineTagAndTypeAndPackThem(){
		var fuzzer=  new SwfFuzzer();
		var string = fuzzer.combineAndPackTagTypeAndLen(9, 3);

		return string === '\x43\x02';
	},
	function tagTypeAndLenShouldBeOneNumber(){
		var fuzzer = new SwfFuzzer();
		var num = fuzzer.combineTagTypeAndLen(10,20);
		
		return num === 660;
	},
	function packTagTypeAndLen(){
		// 660: (type<<6)|(len&63) with type=10, len=20
		var fuzzer = new SwfFuzzer();
		var str = fuzzer.packTagTypeAndLen(660);
		
		return str === '\x94\x02';
	},
	function tagBodyShouldBeUsed(){
		var fuzzer = new SwfFuzzer({tagBody:'abcd'});
		var str = fuzzer.getTagBody();
		
		return str === 'abcd';
	},
	function ifNoTagBodyShouldReturnFuzzBody(){
		var good = true;
		for (var i=0; i<100 && good; ++i) {
			var fuzzer = new SwfFuzzer();
			var str = fuzzer.getTagBody(10);
			
			good = (typeof str == 'string' && str.length == 10);
		}
		
		return good;
	},
	function randomTagsShouldHaveProperLength(){
		var good = true;
		for (var i=0; i<100 && good; ++i) {
			var fuzzer = new SwfFuzzer();
			var tag = fuzzer.getCompleteTag();
	
			// extract length
			var len = tag.charCodeAt(0) & 63;
			if (len == 63) {
				len = tag.charCodeAt(2);
				len |= tag.charCodeAt(3) << 8;
				len |= tag.charCodeAt(4) << 16;
				len |= tag.charCodeAt(5) << 24;
				len >>>= 0;
				
				// big tags have 2 bytes tag and type + 4 bytes extra length
				return tag.length == 6+len;
			}
			
			good = tag.length == 2+len;
		}
		
		return good;
	},
	function countShouldCauseThatManyTagsToBeGenerated(){
		// hard to validate anything here. but at least this shouldnt crash :)
		var fuzzer = new SwfFuzzer();
		var tags = fuzzer.generateRandomTags(10);
		
		return tags.length == 10;
	},
];


var good = 0;
var bad = 0;
var crash = 0;
for (var i=0; i<tests.length; ++i) {
	try {
		if (tests[i]()) ++good;
		else {
			++bad;
			console.warn('bad',tests[i].toString())
		}
	} catch(e){
		++crash;
		console.error('crash',tests[i].toString())
	}
}

if (typeof window != 'undefined') {
	document.body.style.backgroundColor = (crash||bad?'red':'green');
	document.body.style.color = 'white';
	document.body.innerHTML = 'Tests: '+good+' good, '+bad+' bad, '+crash+' crashed';
} else {
	console.log('Test results: '+good+' good, '+bad+' bad, '+crash+' crashed');
}
