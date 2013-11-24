
var TcpParser = require('./tcp');

var Ip = function() {
	this.tcpParser = new TcpParser();
};

Ip.prototype.parse = function(packet, data) {

	packet.ip = {};

	var headerLength = data.readUInt8(0) & 7;

	packet.ip.len = data.readUInt16BE(2);
	packet.ip.ident = data.readUInt16BE(4);
	packet.ip.ttl = data.readUInt8(8);

	packet.ip.protocol = this.getProtocolName(data.readUInt8(9));
	packet.ip.srcAddr = data.readUInt8(12) + '.' + data.readUInt8(13) + '.' + data.readUInt8(14) + '.' + data.readUInt8(15);
	packet.ip.destAddr = data.readUInt8(16) + '.' + data.readUInt8(17) + '.' + data.readUInt8(18) + '.' + data.readUInt8(19);

	var dataParser = null;

	switch(packet.ip.protocol) {
		case 'tcp':
			dataParser = this.tcpParser;
			break;
	}

	if (dataParser) {
		dataParser.parse(packet, data.slice(headerLength * 4));
	};
}

Ip.prototype.getProtocolName = function(protocol) {
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

module.exports = Ip;