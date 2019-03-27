#include "panda/plugin.h"
#include <capstone/capstone.h>
#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#elif defined(TARGET_PPC)
#include <capstone/ppc.h>
#endif

#include<string>
#include<set>
#include<utility>
#include<vector>

std::string get_disas_pc(CPUState* cpu, target_ulong pc, target_ulong tb_pc, uint16_t tb_size);


///////
enum node_type{
	BUF,
	TAINT_SRC,
	TAINT_DST,
	MODULE,
	PROC,
	SYSCALL,
    OS_OBJECT,
	//
	CONCAT,
    NET_TX,
};
typedef std::pair<node_type, std::string> Node;
//typedef std::pair<tg_node, tg_node> dir_tg_node;
typedef std::pair<Node, Node> Edge;

//void gen_graph_dot(std::vector<dir_tg_node> node_pair);
void gen_graph_dot(std::vector<Edge> edges);
///////

