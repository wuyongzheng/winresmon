# generate network log with following syntax
# send/recv tcp/udp pid time-pre time-post file-discriptor address:port size
# example
# send tcp 1334 14187092095622 14187106119394 0x81b27028 74.125.15.31:80 355
# note: only the skype process is selected.

function getaddr (fd) {
	if (fd in dstaddr)
		return dstaddr[fd];
	if (fd in assocfd && assocfd[fd] in dstaddr)
		return dstaddr[assocfd[fd]];
	print fd " not associated with an address" > "/dev/stderr";
	next;
}

BEGIN {
	FS = "\t";
	OFS = "\t";
}

#$9 ~ /^tdi_/ && $8 == "STATUS_SUCCESS" {
$9 ~ /^tdi_/ && $8 == "STATUS_SUCCESS" && $6 ~ /[Ss]kype.exe$/ {
	# use $11 to get an associative array
	split($11, params1, ", ");
	for (k in params1) {
		split(params1[k], arr, "=");
		params2[arr[1]] = arr[2];
	}

	if ($9 == "tdi_connect") {
		dstaddr[params2["f"]] = params2["reqaddr"];
	} else if ($9 == "tdi_event_connect") {
		# no sample log to verify
		dstaddr[params2["f"]] = params2["addr"];
	} else if ($9 == "tdi_associate_address") {
		assocfd[params2["f2"]] = params2["f"];
	} else if ($9 == "tdi_receive") {
		print "recv", "tcp", $4, $2, $3, params2["f"], getaddr(params2["f"]), params2["len"];
	} else if ($9 == "tdi_receive_datagram") {
		# no sample log to verify
		print "recv", "udp", $4, $2, $3, params2["f"], params2["reqaddr"], params2["len"];
	} else if ($9 == "tdi_send") {
		print "send", "tcp", $4, $2, $3, params2["f"], getaddr(params2["f"]), params2["len"];
	} else if ($9 == "tdi_send_datagram") {
		print "send", "udp", $4, $2, $3, params2["f"], params2["addr"], params2["len"];
	} else if ($9 == "tdi_event_receive" || $9 == "tdi_event_receive_expedited") {
		print "recv", "tcp", $4, $2, $3, params2["f"], getaddr(params2["f"]), params2["bt"];
	} else if ($9 == "tdi_event_chained_receive" || $9 == "tdi_event_chained_receive_expedited") {
		print "recv", "tcp", $4, $2, $3, params2["f"], getaddr(params2["f"]), params2["len"];
	} else if ($9 == "tdi_event_receive_datagram") {
		print "recv", "udp", $4, $2, $3, params2["f"], params2["addr"], params2["bt"];
	} else if ($9 == "tdi_event_chained_receive_datagram") {
		print "recv", "udp", $4, $2, $3, params2["f"], params2["addr"], params2["len"];
	}
}
