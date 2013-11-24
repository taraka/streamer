
var _ = require('lodash');

var Tcp = function() {};

Tcp.prototype.parse = function(packet, data) {
	packet.tcp = {}

	packet.tcp.srcPort = data.readUInt16BE(0);
	packet.tcp.destPort = data.readUInt16BE(2);
	packet.tcp.seqNum = data.readUInt32BE(4);
	packet.tcp.ackNum = data.readUInt32BE(8);

	var headerLength = (data.readUInt8(12) & 240) >> 4;

	packet.tcp.flags = this.getTcpFlags(data.readUInt8(13));

	packet.tcp.flagsString = (_.keys(packet.tcp.flags)).join(' ');
	packet.tcp.ackNum = data.readUInt32BE(8);

	packet.data = data.slice(headerLength * 4);
}

Tcp.prototype.getTcpFlags = function(input) {
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

module.exports = Tcp;