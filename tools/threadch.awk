# generate thread tree graph
# the output is a dot file.
# e.g.
# gunzip -c aim.log.gz | gawk -f threadch.awk > aim.dot
# dot -Tps aim.dot -o aim.ps
# ps2pdf -sPAPERSIZE=a4 aim.ps

# arr_tid2tn maps tid to unique tn
# arr_tn2tid
# arr_pid2pn maps pid to unique pn
# arr_pn2pid
# arr_tn2pn
# arr_ctn_ptn maps child tn to parent tn
# arr_pn2exe

BEGIN {
	FS = "\t";
}

{
	pid = int($4);
	tid = int($5);
	exe = $6;

	if (!(tid in arr_tid2tn)) {
		arr_tid2tn[tid] = tid;
		arr_tn2tid[tid] = tid;
	}
	if (!(pid in arr_pid2pn)) {
		arr_pid2pn[pid] = pid;
		arr_pn2pid[pid] = pid;
	}
	tn = arr_tid2tn[tid];
	pn = arr_pid2pn[pid];
	arr_tn2pn[tn] = pn;
	arr_pn2exe[pn] = exe;

	if ($9 == "thread_create") {
		ctid = int(substr($11, 5));
		for (ctn = ctid; ; ctn += 100000) {
			if (!(ctn in arr_tn2tid))
				break;
		}
		arr_tid2tn[ctid] = ctn;
		arr_tn2tid[ctn] = ctid;
		arr_ctn_ptn[ctn] = tn;
	} else if ($9 == "proc_create") {
		cpid = int(gensub(/.*, pid=/, "", "g", $11));
		for (cpn = cpid; ; cpn += 100000) {
			if (!(cpn in arr_pn2pid))
				break;
		}
		arr_pid2pn[cpid] = cpn;
		arr_pn2pid[cpn] = cpid;
	}
}

END {
	print "digraph G {";
	print "size=\"7.27,10.69\";";
	print "rankdir=\"LR\";";
	for (tn in arr_ctn_ptn)
		print "t" arr_ctn_ptn[tn] "->t" tn ";";

	for (pn in arr_pn2exe) {
		print "subgraph \"cluster_p" pn "\" {";
		print "label=\"" gensub(/\\/, "\\\\\\\\", "g", arr_pn2exe[pn]) " p" pn "\";";
		for (tn in arr_tn2pn) {
			if (arr_tn2pn[tn] == pn)
				print "t" tn ";";
		}
		print "}";
	}
	print "}";
}
