# filter log by process tree
# the root of the process tree is specified by -v root=<pid>
# gunzip -c ~/tmp/im-log/aim-install.log.gz | gawk -v root=1336 -f filter-by-parent.awk
# if more than one root, use "-v root=1336,1627,984"

BEGIN {
	FS = "\t";
	split(root, arr, ",");
	for (k in arr)
		pass[arr[k]] = 1;
	delete arr;
}

{
	pid = int($4);
	if ($9 == "proc_create") {
		cpid = int(gensub(/.*, pid=/, "", "g", $11));
		if (pid in pass)
			pass[cpid] = 1;
	}
	if (pid in pass)
		print;
	if ($9 == "proc_term") {
		delete pass[pid];
	}
}
