#define __STDC_FORMAT_MACROS
#include"spaniel_tools.h"
#include<iostream>
#include<string>
#include<cstdlib>
#include<vector>
#include<map>
#include<set>

csh cs_handle_32;
csh cs_handle_64;

std::string get_disas_pc(CPUState* cpu, target_ulong pc, target_ulong tb_pc, uint16_t tb_size) {
#if defined(TARGET_I386)
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_32) != CS_ERR_OK) return std::string("No disas");
	cs_option(cs_handle_32, CS_OPT_DETAIL, CS_OPT_ON);
    unsigned char *buf = (unsigned char *) malloc(tb_size);
    int err = panda_virtual_memory_rw(cpu, tb_pc, buf, tb_size, 0);
    if (err == -1){free(buf); return std::string("No disas"); }
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    csh handle = (env->hflags & HF_LMA_MASK) ? cs_handle_64 : cs_handle_32;
    cs_insn *insn;
	std::string disas_pc;
    size_t count = cs_disasm(handle, buf, tb_size, tb_pc, 0, &insn);
    if(count <= 0) goto done2;
    if(count>0){
        size_t j;
        for(j=0; j<count; j++){
                std::string mnem = insn[j].mnemonic;
                std::string op = insn[j].op_str;
                std::string space = " ";
                std::string instr = mnem + space + op;
				if(insn[j].address == pc){
					disas_pc = instr;
					break;
                    //std::cout << "disased: 0x" << std::hex << insn[j].address << instr << std::endl;
				}
        }
    }
    cs_free(insn, count);
	return disas_pc;
done2:
    free(buf);
	return std::string("No disas");
#endif
	return std::string("No disas");
}


void gen_graph_dot(std::vector<Edge> edges){
	std::string in_taint_icon_fmt = "\"%s\"[shape=note];";
	//std::string out_taint_icon_fmt = "\"%s\"[shape=folder];";
	std::string out_taint_icon_fmt = "\"%s\"[shape=cylinder];";
	std::string tainted_icon = "\"Tainted Buffer\"[shape=doubleoctagon];";

	std::string default_fmt = "\"%s\";";

	std::string mod_icon_fmt = "\"%s\"[style=filled];";
	//std::string mod_icon_fmt = "\"%s\"[shape=box;style=filled];";
	//std::string proc_icon_fmt = "\"%s\";";
	std::string proc_icon_fmt = "\"%s\"[shape=box][style=rounded];";
	std::string syscall_icon_fmt = "\"%s\";";
    std::string concat_fmt = "\"%s\" -> \"%s\";";
	std::string buf_icon_fmt = "\"%s\"[shape=doubleoctagon];";
	//std::string net_tx_icon_fmt = "\"%s\"[shape=folder][style=filled];";
	std::string net_tx_icon_fmt = "\"%s\"[shape=cylinder][style=filled];";


	std::map<node_type, std::string> fmt_dict;
	fmt_dict[TAINT_SRC] = in_taint_icon_fmt;
	fmt_dict[TAINT_DST] = out_taint_icon_fmt;
	fmt_dict[MODULE] = mod_icon_fmt;
	fmt_dict[PROC] = proc_icon_fmt;
	fmt_dict[SYSCALL] = syscall_icon_fmt;
	fmt_dict[BUF] = buf_icon_fmt;
	fmt_dict[CONCAT] = concat_fmt;
    fmt_dict[NET_TX] = net_tx_icon_fmt;

    fmt_dict[OS_OBJECT] = default_fmt;

	std::set<std::string> defined_nodes;
	std::set<std::string> concated_nodes;
	for(auto p : edges){
		char *s1 = new char[256];
		char *s2 = new char[256];
		char *concated = new char[256];
		snprintf(s1, 256, fmt_dict[p.first.first].c_str(), p.first.second.c_str());
		snprintf(s2, 256, fmt_dict[p.second.first].c_str(), p.second.second.c_str());
		defined_nodes.insert(s1);
		defined_nodes.insert(s2);
		snprintf(concated, 256, fmt_dict[CONCAT].c_str(), p.first.second.c_str(), p.second.second.c_str());
		concated_nodes.insert(concated);
	}
//    std::cout << std::endl;
    std::cout << "digraph taintgraph {" << std::endl;
	for(auto s : defined_nodes){
        std::cout << "\t";
		std::cout << s << std::endl;
	}
	for(auto s : concated_nodes){
        std::cout << "\t";
		std::cout << s << std::endl;
	}
	std::cout << "}" << std::endl;
}
