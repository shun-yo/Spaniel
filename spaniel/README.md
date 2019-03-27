# PANDA plugin: spaniel

Summary
-------
Spaniel is a plugin for panda-re(https://github.com/panda-re/panda).

By specifying filename which are touched by attacker, spaiel can trace every instructions which handled or potentially handled by malware. These automated analysis are based on taint analysis.

I used `taint2`, `osi_linux`, `osi` which are plugins default-installed in PANDA for utilizing taint analysis and introspection functions.

Arguments
---------
These argument names are inspired from `file_taint` a default-installed plugins of panda-re(https://github.com/panda-re/panda)

* `filename`: string, filename we want to monitor and analysis read data using taint analysis.
* `file_taint`: boolean, Enable tainting data opend from file specified in "filename"

Dependencies
------------
I modified some codes in panda-re(https://github.com/panda-re/panda) for inserting some rr callbacking functions to handle packet received and/or send in e1000 network driver.


Use case
-------

We Analyzed file exfiltration, left one is attacker(Kali linux) , right one is victim(Debian on Qemu).

![Record file exfiltration by attacker](docs/images/exfiltration_cat.png)


We want to analyze malcious processing applied to 'passwd'


	$PANDA_PATH/i386-softmmu/qemu-system-i386 -m 128 -replay meterbind_cat_1211_4  -os linux-32 -panda osi\
    -panda osi_linux:kconf_group=debian-3.2.81-686-pae:32  -panda syscalls2:profile=linux_x86 \
    -panda spaniel:filename=passwd,file_taint,last_tainted_rr=3194324


And you will see this dot script in this plugin's(spaniel's) output.

    digraph taintgraph {
        "/etc/passwd"[shape=note];
        "Tainted Buffer"[shape=doubleoctagon];
        "[fd]1"[shape=folder];
        "[fd]4"[shape=folder];
        "[tcp]192.168.124.131:44261"[shape=folder][style=filled];
        "cat"[style=filled];
        "cmd:cat";
        "cmd:meterbind2.elf";
        "cmd:sh";
        "ld-2.13.so"[style=filled];
        "libc-2.13.so"[style=filled];
        "sys_read";
        "sys_sendto";
        "sys_write";
        "Tainted Buffer" -> "cat";
        "Tainted Buffer" -> "cmd:cat";
        "Tainted Buffer" -> "cmd:meterbind2.elf";
        "Tainted Buffer" -> "ld-2.13.so";
        "Tainted Buffer" -> "libc-2.13.so";
        "cmd:cat" -> "sys_read";
        "cmd:cat" -> "sys_write";
        "cmd:meterbind2.elf" -> "cmd:cat";
        "cmd:meterbind2.elf" -> "sys_sendto";
        "cmd:sh" -> "cmd:cat";
        "sys_read" -> "/etc/passwd";
        "sys_read" -> "Tainted Buffer";
        "sys_sendto" -> "[fd]4";
        "sys_sendto" -> "[tcp]192.168.124.131:44261";
        "sys_write" -> "[fd]1";
    }



Please named this dot script arbitrary name and type this command to convert to graph image.
I named this file "exfiltration.dot".

	> dot -T pdf exfiltration.dot -o exfiltration.pdf

You can see graph

	> open exfiltration.pdf

![Graph Visualization](docs/images/taint_graph.png)


Thanks
-------
Above graph was inspired from this paper. Thanks.

* Yin, Heng, et al. "Panorama: capturing system-wide information flow for malware detection and analysis." Proceedings of the 14th ACM conference on Computer and communications security. ACM, 2007.

