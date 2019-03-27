#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"
#include "osi_linux/osi_linux_ext.h"
#include "syscalls2/gen_syscalls_ext_typedefs.h"
#include "taint2/taint2.h"
#include "taint2/taint2_ext.h"

#include<iostream>
#include<vector>
#include<string>
#include<set>
#include<cstring>
#include<stack>

#define PANDA_NET_RX 0
#define PANDA_NET_TX 1


#define ISNULL "Isnull"

enum Sockcall{
	PADDING         = 0,
    SYS_SOCKET      = 1,
    SYS_BIND        = 2,
    SYS_CONNECT     = 3,
    SYS_LISTEN      = 4,
    SYS_ACCEPT      = 5,
    SYS_GETSOCKNAME = 6,
    SYS_GETPEERNAME = 7,
    SYS_SOCKETPAIR  = 8,
    SYS_SEND        = 9,
    SYS_RECV        = 10,
    SYS_SENDTO      = 11,
    SYS_RECVFROM    = 12,
    SYS_SHUTDOWN    = 13,
    SYS_SETSOCKOPT  = 14,
    SYS_GETSOCKOPT  = 15,
    SYS_SENDMSG     = 16,
    SYS_RECVMSG     = 17,
    SYS_ACCEPT4     = 18,
    SYS_RECVMMSG    = 19,
    SYS_SENDMMSG    = 20,
    FUNC_TOTAL      = 21,
};

std::string sys_sockcall_name[]{
	"padding",
    "sys_socket", 
    "sys_bind",
    "sys_connect"     ,
    "sys_listen"      ,
    "sys_accept"      ,
    "sys_getsockname" ,
    "sys_getpeername" ,
    "sys_socketpair " ,
    "sys_send" ,
    "sys_recv" ,
    "sys_sendto" ,
    "sys_recvfrom" ,
    "sys_shutdown" ,
    "sys_setsockopt" ,
    "sys_getsockopt " ,
    "sys_sendmsg" ,
    "sys_recvmsg" ,
    "sys_accept4" ,
    "sys_recvmmsg" ,
    "sys_sendmmsg" ,
};

enum cb_state{
	ENTER,
	RETURN,
};



bool current_tap_labeled = false;
std::string tx_last_tcp_conn;
std::string rx_last_tcp_conn;


/*
#define GEN_ENUM(ENUM) ENUM
#define GEN_FALSE(ENUM) false
#define FOREACH_TAP_ENUM(ACTION) \
    ACTION(TAP_SENDTO), \
    ACTION(TAP_WRITE), \
    ACTION(TAP_WRITEV)
enum tap_point{
    FOREACH_TAP_ENUM(GEN_ENUM)
};
bool is_tap_labeled[] = {
    FOREACH_TAP_ENUM(GEN_FALSE)
};
*/

//(CPUState* cpu, int32_t call, uint32_t args, int32_t state)
typedef void sockcall_func_t(CPUState* cpu, int32_t call, uint32_t args, uint32_t cb_state);

sockcall_func_t* sockcalls[FUNC_TOTAL];

void sys_connect(CPUState* cpu, int32_t call, uint32_t args, uint32_t cb_state);
void sys_send(CPUState* cpu, int32_t call, uint32_t args, uint32_t cb_state);
void sys_sendto(CPUState* cpu, int32_t call, uint32_t args, uint32_t cb_state);
void sys_recv(CPUState* cpu, int32_t call, uint32_t args, uint32_t cb_state);
void sys_recvmsg(CPUState* cpu, int32_t call, uint32_t args, uint32_t cb_state);

//For using string, include-maching
template<class T> bool contain(const std::string& s, const T& v);

void str_add(std::string& s, const std::string& v);
void update_procs_fdmap(CPUState *cpu, uint32_t fd);
std::string get_procs_fdmap(CPUState* cpu, uint32_t fd);

///for Structured data//
struct iovec32{
	union {uint8_t ar[4]; uint32_t val;}iov_base;
	union {uint8_t ar[4]; uint32_t val;}iov_len;
};

struct sockaddr_in32{
	uint8_t sin_len;
	uint8_t sin_family;
	union {uint8_t ar[2]; uint16_t val;}sin_port;
	union {uint8_t ar[4]; uint32_t val;}sin_addr;
};

template<typename T>
void cast_to_struct(T& result, std::vector<uint8_t> vec){
	std::copy(vec.begin(), vec.end(), reinterpret_cast<uint8_t*>(&result));
}

///
//#ifdef TARGET_I386

///For Introspection///
bool pid_ok(int pid);
bool check_proc_ok(OsiProc* proc);
uint32_t get_syscall_retval(CPUState* cpu);
std::string get_filename_from_fd(CPUState* cpu, uint32_t fd);
std::set<std::string> get_commands_from_pid(uint32_t pid);
std::string get_current_command(CPUState* cpu);
std::set<std::string> get_current_parent_command(CPUState* cpu);

//void get_current_mod(CPUState* cpu);
void get_current_mod(CPUState* cpu, target_ulong pc_addr);
bool is_in_watched_cmd(CPUState* cpu);
///

//For using strcpy and memcpy in C
std::string get_strncpy_buf(CPUState *cpu, target_ulong guest_addr, size_t max_len);


//Functions for doing little endian
uint32_t little_endian_vec(uint8_t *vec, int size);
uint32_t buf_virtaddr_little_endianed(CPUState *cpu, uint32_t addr, uint64_t len);

//for print debugging or something, use little-endian-function above
std::vector<uint8_t> get_buf_dump(CPUState *cpu, uint32_t addr, uint32_t len);
std::string hex2str(int dec);
std::string get_buf_printable(CPUState *cpu, uint32_t addr, uint32_t len, bool in_hex);

void buf_dump_panda_virtaddr(CPUState *cpu, uint32_t addr, uint64_t len, bool fmt_char);


typedef struct Info_resource{
    std::string resource_name;
    std::string cmd;
    std::set<std::string> parent_cmds;
    uint32_t size;
    uint64_t rr_count;
}Info_resource;

bool operator<(const Info_resource &lhs, const Info_resource &rhs){
    return lhs.resource_name < rhs.resource_name;
}

//syscall, and filename(read or written,etc.
//typedef std::map<std::string, std::set<Info_resource>> RESOURCE_MP;
typedef std::map<std::string, std::vector<Info_resource>> RESOURCE_MP;
RESOURCE_MP resource_touched;

//For debugging
//void monitor_resource_access(CPUState* cpu, std::string call_name, int fd);


///Taint Analysis///
typedef struct Info_taint_source{
	uint64_t rr_count;
	target_ulong pc;
	target_ulong asid;
    std::string resource; //file or file descriptor
	std::string cmd;
	std::set<std::string> parent_cmds; //in some cases, several commands share the same pid.
    std::string syscall;
    uint32_t propagate_count;
    Info_taint_source() : propagate_count(0){};
    uint32_t range_size;
	std::string candidate_src_host = "(no_tagged_host)";
    int fd;
}Info_t;

typedef struct Info_taint_output{
	std::set<uint32_t> ls;
	std::string cmd;
	std::string syscall;
	std::string resource;
	std::set<std::string> parent_cmds; //in some cases, several commands share the same pid.
	std::vector<uint8_t> buf;
	uint64_t rr_count;
    int fd;
}Info_out;

int app_getlabels(uint32_t el, void *stuff1);
//uint32_t is_virtaddr_labeled(CPUState* cpu, target_ulong virt_addr, std::set<uint32_t> &ls);
void check_virtaddr_labeled(CPUState* cpu, target_ulong virt_addr, std::set<uint32_t> &ls);
bool is_tapped_buf_labeled(CPUState* cpu, uint32_t addr, uint32_t len, int fd, std::string tapped_call);



struct Tainted_cmd{
    uint64_t rr_count;
    std::string cmd;
    std::set<std::string> parent_cmds;
    uint32_t asid;
	std::string disas_code;
    //std::set<uint32_t> labels;
    //target_ulong pc;
};

bool operator<(const Tainted_cmd &lhs, const Tainted_cmd &rhs){
    return (lhs.cmd < rhs.cmd);
}

std::set<Tainted_cmd> tainted_commands;




struct Tainted_instr{
    uint64_t rr_count;
    uint32_t asid;
    std::set<uint32_t> labels;
    target_ulong pc;
};
std::vector<Tainted_instr> tainted_instrs;



// label this virtual address.  might fail, so
// returns true if byte was labeled
bool label_byte(CPUState *cpu, target_ulong virt_addr, uint32_t label_num); 
//void ranged_label_byte(CPUState *cpu, target_ulong virt_addr, uint32_t size, int fd, std::string tap_call); 
//bool satisfy_read_taint(CPUState* cpu, uint32_t fd, uint32_t buf, uint32_t len);
////////////////////

std::stack<std::string> call_stack;

std::set<std::string> taint_funcs;
std::set<std::string> watched_cmd_funcs;

std::set<std::string> taint_funcs_rr_limited;


std::set< target_ulong > func_addrs;



