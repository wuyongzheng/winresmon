# filter log by process tree
# the root of the process tree is specified by -v root=<pid>
# gunzip -c ~/tmp/im-log/aim-install.log.gz | gawk -v root=1336 -f filter-by-parent.awk

BEGIN {
	FS = "\t";
	pass[root] = 1;
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
