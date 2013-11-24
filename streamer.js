var program = require('commander');
var pcapp = require('pcap-parser');
var IpParser = require('./parsers/ip');

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
};

Streamer.prototype.processPacket = function(packet) {

	packet = this.ipParser.parse(packet.data.slice(14));

	var stream = this.findStream(packet);
	stream.packets.push(packet);


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

	console.dir(this.streams);

};

Streamer.prototype.findStream = function(packet) {

	var stream = {};
	var newStream = function() {
		stream = {
			srcAddr: packet.ip.srcAddr,
			srcPort: packet.ip.srcPort,
			destAddr: packet.ip.destAddr,
			destPort: packet.ip.destPort,
			packets: []
		};

		this.streams[this.streams.length] = stream;
	};

	if (packet.tcp.flags.SYN && !packet.tcp.flags.ACK) {
		newStream(); 
		return stream;
	}

	for (var i=this.streams.length-1; i>=0; i--) {
		var testStream = this.stream[i];
		if ((testStream.srcAddr == packet.ip.srcAddr && testStream.srcPort == packet.ip.srcPort &&
			testStream.destAddr == packet.ip.destAddr && testStream.destPort == packet.ip.destPort) || 
			(testStream.destAddr == packet.ip.srcAddr && testStream.destPort == packet.ip.srcPort &&
			testStream.srcAddr == packet.ip.destAddr && testStream.srcPort == packet.ip.destPort)) {

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

