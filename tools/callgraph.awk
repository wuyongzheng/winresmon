# generate call graph for a process.
# input need to be filtered by process and/or thread
# e.g. to see pid=452, tid=472
#   gunzip -c ~/tmp/im-log/aim-install.log.gz | grep $'\t452\t472\t' | gawk -f callgraph.aw

BEGIN {
	FS = "\t";
}

{
	split($12, stack, " ");
	prev = $9
	for (i = 1; ; i ++) {
		if (!(i in stack))
			break;
		edges[prev, "f" stack[i]] = 1;
		prev = "f" stack[i];
	}
}

END {
	print "digraph G {";
	print "size=\"7.27,10.69\";";
	for (x in edges) {
		split(x, ab, SUBSEP);
		print ab[2] "->" ab[1] ";";
	}
	print "}";
}
