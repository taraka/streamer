var pcapp = require('pcap-parser');

var parser = pcapp.parse('capture.pcap');

parser.on('packet', function(packet) {
	var data = packet.data.slice(14);
	var packet = {
		ip:{}
	};

	var headerLength = data.readUInt8(0) & 7;
	console.log('headerLength ' + headerLength);
	console.log('Found packet: ' + data.readUInt16BE(4));
	packet.ip.len = data.readUInt16BE(2);
	packet.ip.ident = data.readUInt16BE(4);
	packet.ip.ttl = data.readUInt8(8);

	packet.ip.protocol = getProtocolName(data.readUInt8(9));
	packet.ip.srcAddr = data.readUInt8(12) + '.' + data.readUInt8(13) + '.' + data.readUInt8(14) + '.' + data.readUInt8(15);
	packet.ip.destAddr = data.readUInt8(16) + '.' + data.readUInt8(17) + '.' + data.readUInt8(18) + '.' + data.readUInt8(19);

	switch(packet.ip.protocol) {
		case 'tcp':
			addTcpData(packet, data.slice(headerLength * 4));
			break;
	}

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
})

function getProtocolName(protocol) {
	switch(protocol) {
		case 6:
			return 'tcp';
			break;
		case 1:
			return 'icmp';
			break;
		case 17:
			return 'udp';
			break;
		default: 
			return 'unknown';

	}
}

function addTcpData(packet, data) {
	packet.tcp = {}

	packet.tcp.srcPort = data.readUInt16BE(0);
	packet.tcp.destPort = data.readUInt16BE(2);
	packet.tcp.seqNum = data.readUInt32BE(4);
	packet.tcp.ackNum = data.readUInt32BE(8);

	var headerLength = (data.readUInt8(12) & 240) >> 4;

	packet.tcp.flags = getTcpFlags(data.readUInt8(13));
	packet.tcp.ackNum = data.readUInt32BE(8);

	//packet.data = data.slice(headerLength * 4).toString();
}

function getTcpFlags(input) {
	var flags = {};

	if (input & 1) {
		flags.FIN = true;
	}

	if (input & 2) {
		flags.SYN = true;
	}

	if (input & 4) {
		flags.RST = true;
	}

	if (input & 8) {
		flags.PSH = true;
	}

	if (input & 16) {
		flags.ACK = true;
	}

	if (input & 32) {
		flags.URG = true;
	}

	if (input & 64) {
		flags.ECE = true;
	}

	if (input & 128) {
		flags.CWR = true;
	}

	return flags;
}