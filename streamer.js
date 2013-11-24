var program = require('commander');
var pcapp = require('pcap-parser');
var EthernetParser = require('./parsers/ethernet');
var util = require('util');
var express = require('express');
var cons = require('consolidate');
var _ = require('lodash');
var htmlencode = require('htmlencode');

var Streamer = function() {
	program.version('0.0.0')
		.option('-f, --file <file>', 'Input file')
		.parse(process.argv);

	this.ethParser = new EthernetParser();
	this.streams = [];
	this.packets = [];
	this.createServer();
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

	this.server.listen(8002);
};

Streamer.prototype.processPacket = function(frame) {

	var packet = _.omit(frame, 'data');

	var timeString = (new Date((packet.header.timestampSeconds * 1000))).toISOString();

	timeString = timeString.replace(/([0-9])+Z$/ ,packet.header.timestampMicroseconds + 'Z');

	packet.header.time = timeString;
	this.ethParser.parse(packet, frame.data);

	var stream = this.findStream(packet);
	stream.packets.push(packet);

	//stream.packets.inspect = function() {return this.length.toString();};


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

Streamer.prototype.createServer = function() {

	var self = this;
	this.server = express();

	var tmpl = {
	    compile: function (source, options) {
	        if (typeof source == 'string') {
	            return function(options) {
	                options.locals = options.locals || {};
	                options.partials = options.partials || {};
	                if (options.body) // for express.js > v1.0
	                    locals.body = options.body;
	                return mustache.to_html(
	                    source, options.locals, options.partials);
	            };
	        } else {
	            return source;
	        }
	    },
	    render: function (template, options) {
	        template = this.compile(template, options);
	        return template(options);
	    }
	};

	this.server.engine('html', cons.mustache);
	this.server.set('views', __dirname + '/views');

    this.server.use(express.errorHandler({
        dumpExceptions:true, 
        showStack:true
    }));

	this.server.get('/', function(req, res) {
		res.render('index.html', {streams: self.streams});
	});
};

Streamer.prototype.fileComplete = function() {

	for (var i=0; i<this.streams.length; i++) {
		var stream = this.streams[i];

		var currentHost;
		
		for (var j=0; j<stream.packets.length; j++) {
			var packet = stream.packets[j];
			var packetData = stream.packets[j].data.toString();

			if (packetData) {
				if (currentHost != packet.ip.srcAddr + ':' + packet.tcp.srcPort){
					if (currentHost){
						stream.data += '</pre></div>'
					}
					currentHost = packet.ip.srcAddr + ':' + packet.tcp.srcPort;
					stream.data += '<div class="';
					stream.data += (currentHost == stream.srcAddr + ':' + stream.srcPort ? 'client-data' : 'server-data');
				}	stream.data += '"><pre>';
				stream.data += htmlencode.htmlEncode(packetData);
			}
		}
		if (stream.data) {
			stream.data += '</pre></div>'
		}
	}
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

