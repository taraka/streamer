var program = require('commander');
var pcapp = require('pcap-parser');
var IpParser = require('./parsers/ip');
var util = require('util');

var Streamer = function() {
	program.version('0.0.0')
		.option('-f, --file <file>', 'Input file')
		.parse(process.argv);

	this.ipParser = new IpParser();
	this.streams = [];
}

Streamer.prototype.start = function() {

	if (!program.file) {
		console.error('Error input file not supplied');
		program.help();
		process.exit(127);
	}

	console.log('Starting packet analysis on file ' + program.file);
	var parser = pcapp.parse(program.file);
	parser.on('packet', this.processPacket.bind(this));
	parser.on('end', this.fileComplete.bind(this));
};

Streamer.prototype.processPacket = function(packet) {

	packet = this.ipParser.parse(packet.data.slice(14));

	var stream = this.findStream(packet);
	stream.packets.push(packet);

	stream.packets.inspect = function() {return this.length.toString();};


	/*for(var i=0; i<64; i++) {
		if (typeof data[i] != 'undefined') {
			var str = data[i].toString(2);
			var pad = Array(9 - str.length).join('0');
			process.stdout.write(pad + str + ' ');
			if (!((i+1) % 4)) {
				process.stdout.write("\n");
			}
		}
	}*/

};

Streamer.prototype.fileComplete = function() {

	/*for (var i=0; i<this.streams.length; i++) {
		var stream = this.streams[i];
		console.log(this.streams.length);
		for (var j=0; j<stream.packets.length; j++) {
			stream.data += stream.packets[j].data.toString();
		}
	}*/
	console.log(util.inspect(this.streams, 1, 5, 1));
};

Streamer.prototype.findStream = function(packet) {

	var stream = {};
	var newStream = (function() {
		stream = {
			srcAddr: packet.ip.srcAddr,
			srcPort: packet.tcp.srcPort,
			destAddr: packet.ip.destAddr,
			destPort: packet.tcp.destPort,
			data: '',
			packets: []
		};
		this.streams.push(stream);
	}).bind(this);

	if (packet.tcp.flags.SYN && !packet.tcp.flags.ACK) {
		newStream(); 
		return stream;
	}

	for (var i=this.streams.length-1; i>=0; i--) {
		var testStream = this.streams[i];
		if ((testStream.srcAddr == packet.ip.srcAddr && testStream.srcPort == packet.tcp.srcPort &&
			testStream.destAddr == packet.ip.destAddr && testStream.destPort == packet.tcp.destPort) || 
			(testStream.destAddr == packet.ip.srcAddr && testStream.destPort == packet.tcp.srcPort &&
			testStream.srcAddr == packet.ip.destAddr && testStream.srcPort == packet.tcp.destPort)) {

			return testStream;
		}
	}

	//Stream not found
	newStream(); 
	console.error('Partial stream %j', stream);
	return stream;

};

var app = new Streamer();
app.start();

