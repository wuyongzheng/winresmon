# generate process tree graph
# the output is a dot file.
# e.g.
# gunzip -c aim.log.gz | gawk -f proch.awk > aim.dot
# dot -Tps aim.dot -o aim.ps
# ps2pdf -sPAPERSIZE=a4 aim.ps

# arr_pid2pn maps pid to unique pn
# arr_pn2pid maps unique pn to pid (this array only add, no modify existing)
# arr_pn2exe
# arr_cpn_ppn maps child pn to parent pn

BEGIN {
	FS = "\t";
}

{
	pid = int($4);
	exe = $6;

	if (!(pid in arr_pid2pn)) {
		arr_pid2pn[pid] = pid;
		arr_pn2pid[pid] = pid;
	}
	pn = arr_pid2pn[pid];
	arr_pn2exe[pn] = exe;

	if ($9 == "proc_create") {
		cpid = int(gensub(/.*, pid=/, "", "g", $11));
		for (cpn = cpid; ; cpn += 100000) {
			if (!(cpn in arr_pn2pid))
				break;
		}
		arr_pid2pn[cpid] = cpn;
		arr_pn2pid[cpn] = cpid;
		arr_cpn_ppn[cpn] = pn;
	}
}

END {
	print "digraph G {";
	print "size=\"7.27,10.69\";";
	print "rankdir=\"LR\";";
	for (cpn in arr_cpn_ppn) {
#		pexe = gensub(/\\/, "\\\\\\\\", "g", arr_pn2exe[arr_cpn_ppn[cpn]]);
#		cexe = gensub(/\\/, "\\\\\\\\", "g", arr_pn2exe[cpn]);
		pexe = gensub(/.*\\/, "", "g", arr_pn2exe[arr_cpn_ppn[cpn]]);
		cexe = gensub(/.*\\/, "", "g", arr_pn2exe[cpn]);
		print "\"" arr_cpn_ppn[cpn] " " pexe "\" -> \"" cpn " " cexe "\";";
	}
	print "}";
}
