var program = require('commander');
var pcapp = require('pcap-parser');
var IpParser = require('./parsers/ip');

var Streamer = function() {
	program.version('0.0.0')
		.option('-f, --file <file>', 'Input file')
		.parse(process.argv);

	this.ipParser = new IpParser();
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


	console.dir(packet);


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

	console.log("\n\n\n");

};

var app = new Streamer();
app.start();

