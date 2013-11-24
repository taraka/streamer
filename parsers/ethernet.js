
var IpParser = require('./ip');
var _ = require('lodash');

var EthernetParser = function() {
	this.ipParser = new IpParser();
};

EthernetParser.prototype.parse = function(packet, data) {

	packet.ethernet = {};

	var headerLength = 12;

	packet.ethernet.destMAC = this.parseMAC(data.slice(0, 6));
	packet.ethernet.srcMAC = this.parseMAC(data.slice(6, 12));

	data = data.slice(12);

	if (data.readUInt16BE(0) == 0x8100) {
		packet.ethernet.vlan = data.readUInt16BE(0) & 4095;
		data = data.slice(4);
	}

	this.ipParser.parse(packet, data.slice(2));
}

EthernetParser.prototype.parseMAC = function(stream) {
	return (_.map(stream, function(item) {
		return item.toString(16);
	})).join(':');
}

module.exports = EthernetParser;