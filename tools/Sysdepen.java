import java.io.*;
import java.util.*;

public class Sysdepen {

	public static String implode (Iterable<String> arr, String prefix, String suffix, String sep)
	{
		StringBuffer sb = new StringBuffer();
		for (String s : arr)
			sb.append(prefix).append(s).append(suffix).append(sep);
		return sb.substring(0, sb.length() - sep.length());
	}

	public static String get_dllset_struct (TreeSet<String> dllset, String struct_name)
	{
		StringBuffer sb = new StringBuffer();
		sb.append(struct_name);
		sb.append(" [shape=record,label=\"");
		TreeMap<String, TreeSet<String>> pattern2nameset = new TreeMap<String, TreeSet<String>>();
		for (String dll : dllset) {
			String dir = dll.replaceAll("/[^/]*$", "/");
			String name = dll.replaceAll("^.*/", "");
			String ext = name.substring(name.length() - 4);
			name = name.substring(0, name.length() - 4);
			String pattern = dir + "*" + ext;
			TreeSet<String> nameset = pattern2nameset.get(pattern);
			if (nameset == null)
				nameset = new TreeSet<String>();
			nameset.add(name);
			pattern2nameset.put(pattern, nameset);
		}
		int wrap = 50;
		for (String pattern : pattern2nameset.keySet()) {
			TreeSet<String> nameset = pattern2nameset.get(pattern);
			if (nameset.size() == 1) {
				if (pattern.startsWith("/windows/winsxs/")) {
					sb.append(pattern.substring(0, pattern.indexOf('_', 20)) + "_.../" + nameset.first() + ".dll");
				} else {
					sb.append(pattern.replace("*", nameset.first()));
				}
			} else {
				sb.append("[" + pattern + "]\\n");
				int count = 0;
				for (String name : nameset) {
					if (count >= wrap) {
						sb.append("\\n");
						count = 0;
					}
					sb.append(name).append(", ");
					count += name.length() + 1;
				}
				sb.setLength(sb.length() - 2);
			}
			sb.append("|");
		}
		sb.setLength(sb.length() - 1);
		sb.append("\"];");
		return sb.toString();
	}

	public static void main (String [] args) throws IOException
	{
		boolean split_program = false;
		boolean transitive_reduction = false;

		for (String arg : args) {
			if (arg.equals("-sp"))
				split_program = true;
			else if (arg.equals("-tr"))
				transitive_reduction = true;
		}

		Hashtable<Integer, String> pn2exe = new Hashtable<Integer, String>();
		Hashtable<Integer, Integer> pid2pn = new Hashtable<Integer, Integer>();
		Hashtable<Integer, Integer> pn2pid = new Hashtable<Integer, Integer>();
		Hashtable<Integer, Integer> cpn2ppn = new Hashtable<Integer, Integer>();
		HashSet<String> prgdll = new HashSet<String>();

		BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
		while (true) {
			String line = stdin.readLine();
			if (line == null)
				break;
			String [] fields = line.split("\t");
			int pid = Integer.parseInt(fields[3]);
			String exe = fields[5].replaceAll(".*\\\\", "").toLowerCase();

			if (!pid2pn.containsKey(pid)) {
				pid2pn.put(pid, pid);
				pn2pid.put(pid, pid);
			}
			int pn = pid2pn.get(pid);
			pn2exe.put(pn, exe);

			String prg = split_program ? pn + " " + exe : exe;

			if (fields[8].equals("proc_create")) {
				int cpid = Integer.parseInt(fields[10].replaceAll(".*, pid=", ""));
				int cpn = cpid;
				while (pn2pid.containsKey(cpn))
					cpn += 100000;
				pid2pn.put(cpid, cpn);
				pn2pid.put(cpn, cpid);
				cpn2ppn.put(cpn, pn);
			} else if (fields[8].equals("image")) {
				String dll = fields[9].toLowerCase().replaceAll("\\\\", "/").replaceAll("/device/harddiskvolume1/", "/").replaceAll("/systemroot/", "/windows/").replaceAll("/progra~1/", "/program files/");
				// we don't count the exe.
				if (dll.endsWith(exe))
					continue;
				prgdll.add(prg + "\t" + dll);
			}
		}

		System.out.println("digraph G {");
		System.out.println("size=\"7.27,10.69\";");
		System.out.println("rankdir=\"LR\";");
		System.out.println();

		// parent-child relationship
		if (split_program) {
			for (int cpn : cpn2ppn.keySet()) {
				System.out.println("\"" + cpn2ppn.get(cpn) + " " + pn2exe.get(cpn2ppn.get(cpn)) +
						"\" -> \"" +
						cpn + " " + pn2exe.get(cpn) + "\" [style=bold];");
			}
		} else {
			Hashtable<String, Integer> pprgcprg = new Hashtable<String, Integer>();
			for (int cpn : cpn2ppn.keySet()) {
				String key = pn2exe.get(cpn2ppn.get(cpn)) + "\" -> \"" + pn2exe.get(cpn);
				if (pprgcprg.containsKey(key))
					pprgcprg.put(key, pprgcprg.get(key) + 1);
				else
					pprgcprg.put(key, 1);
			}
			for (String key : pprgcprg.keySet())
				System.out.println("\"" + key + "\" [label=" + pprgcprg.get(key) + ",style=bold];");
		}

		// program dll relationship
		Hashtable<String, TreeSet<String>> dll2prgset = new Hashtable<String, TreeSet<String>>();
		for (String key : prgdll) {
			String [] arr = key.split("\t");
			if (dll2prgset.containsKey(arr[1])) {
				dll2prgset.get(arr[1]).add(arr[0]);
			} else {
				TreeSet<String> set = new TreeSet<String>();
				set.add(arr[0]);
				dll2prgset.put(arr[1], set);
			}
		}

		Hashtable<TreeSet<String>, TreeSet<String>> prgset2dllset = new Hashtable<TreeSet<String>, TreeSet<String>>();
		for (String dll : dll2prgset.keySet()) {
			TreeSet<String> dllset = prgset2dllset.get(dll2prgset.get(dll));
			if (dllset == null)
				dllset = new TreeSet<String>();
			dllset.add(dll);
			prgset2dllset.put(dll2prgset.get(dll), dllset);
		}

		if (transitive_reduction) {
			int max_dllset_size = 0;
			int struct_count = 1;
			Hashtable<TreeSet<String>, String> prgset2sname = new Hashtable<TreeSet<String>, String>();
			for (TreeSet<String> prgset : prgset2dllset.keySet()) {
				TreeSet<String> dllset = prgset2dllset.get(prgset);
				String struct_name = "struct" + (struct_count ++);
				System.out.println(get_dllset_struct(dllset, struct_name));
				System.out.println("// " + struct_name + " " + prgset);
				prgset2sname.put(prgset, struct_name);
				if (max_dllset_size < prgset.size())
					max_dllset_size = prgset.size();
			}
			// Put all prgset in a list. smaller one goes first.
			LinkedList<TreeSet<String>> prgsetlist = new LinkedList<TreeSet<String>>();
			for (int i = 1; i <= max_dllset_size; i ++) {
				for (TreeSet<String> prgset : prgset2dllset.keySet()) {
					if (prgset.size() != i)
						continue;
					// For each <prgset> about to add, visit each <earlier>
					// (added before X) set (later one is visited earlier).
					// print <earlier> if <earlier> is a subset of <prgset> and
					// <earlier> covers at least one uncovered elements.
					TreeSet<String> uncovered = new TreeSet<String>();
					uncovered.addAll(prgset);
					for (TreeSet<String> early : prgsetlist) {
						if (!prgset.containsAll(early))
							continue;
						// does <early> and <uncovered> intersect?
						boolean intersect = false;
						for (String prg : uncovered) {
							if (early.contains(prg)) {
								intersect = true;
								break;
							}
						}
						if (intersect) {
							uncovered.removeAll(early);
							System.out.println("\"" + prgset2sname.get(early) + "\" -> " + prgset2sname.get(prgset) + ";");
						}
					}
					// If all sets are searched, but still can't cover S, use the program themself.
					for (String prg : uncovered) {
						System.out.println("\"" + prg + "\" -> " + prgset2sname.get(prgset) + ";");
					}
					// finally prepend it to the list.
					prgsetlist.addFirst(prgset);
				}
			}
		} else {
			int struct_count = 1;
			for (TreeSet<String> prgset : prgset2dllset.keySet()) {
				TreeSet<String> dllset = prgset2dllset.get(prgset);
				String struct_name = "struct" + (struct_count ++);
				System.out.println(get_dllset_struct(dllset, struct_name));
				for (String prg : prgset)
					System.out.println("\"" + prg + "\" -> " + struct_name + ";");
			}
		}
		System.out.println("}");
	}
}
