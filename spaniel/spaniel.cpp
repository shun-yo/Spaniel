// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "osi/osi_types.h"
#include "osi/osi_ext.h"
#include "osi_linux/osi_linux_ext.h"
#include "syscalls2/gen_syscalls_ext_typedefs.h"
#include "taint2/taint2.h"
#include "taint2/taint2_ext.h"
#include "panda/plugin.h"

#include "spaniel_helper.h"
#include "spaniel_syscalls.h"
#include "spaniel_tools.h"
//#include "entro.h"

#include<iostream>
#include<string>
#include<fstream>
#include<sstream>
#include<iomanip>
#include<map>
#include<vector>
#include<set>
#include<utility>
#include<algorithm>
#include<cstring>
#include<stack>

#define MAX_FILENAME 256

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

bool init_plugin(void *);
void uninit_plugin(void *);
}

//Plugin parameter's argument
panda_arg_list *args;
bool file_taint = false;
bool all_file_taint = false;
bool no_taint=false;
bool all_read_taint = false;
bool rx_taint = false;
bool no_positional_labels=false;
bool no_char = false;
bool debug = false;
const char *taint_filename = 0;
uint32_t watched_fd_num;
const char *watched_cmd = 0;
uint64_t last_tainted_rr = 0;
bool check_funcall = false;
uint64_t check_funcall_rr = 0;
//////////

std::vector< std::pair<int, target_ulong> > fd_watched;
std::map<target_ulong, OsiProc> running_procs;

// file-descriptor-name such as "SYSTEMCALL" or filename.
typedef std::map<uint32_t, std::string> FDMP;
std::map<target_ulong, FDMP> procs_fdmap;

//instruction's addr to module-name.
typedef std::map<uint32_t, std::string> MODMP;
std::map<target_ulong, MODMP> procs_mapped_modules;


typedef std::map<uint32_t, std::pair<std::string, std::string>> MOD_PC_MP;
std::map<target_ulong, MOD_PC_MP> procs_pc_module_mp;


//procs to its referenced module-name.
typedef std::set<std::string> MODS;
std::map<target_ulong, MODS> procs_refered_module;

typedef struct Info_taint_source Info_t;
std::map<uint32_t, Info_t> taint_label_info;

typedef struct Info_taint_output Info_out;
std::vector< Info_out > taint_outs;

//rr count to name of destination
std::map<uint64_t, std::string> transfered_data_info;

//packet data, expressed in std-string-format
std::string tx_packet_payload;
std::string rx_packet_payload;
std::map<uint32_t, std::string> label_network_rx_mp;

void cb_sys_tapped(CPUState* cpu, std::string tapped_syscall, int fd, uint32_t buf, uint32_t len, uint32_t cb_state);
void cb_taint(CPUState* cpu, std::string tapped_syscall, int fd, uint32_t buf, uint32_t count, uint32_t cb_state);

uint16_t cur_tb_size;
target_ulong cur_tb_pc;

target_ulong last_user_pc;
target_ulong rx_last_user_pc;
target_ulong tx_last_user_pc;



std::set<std::string> rx_remote_hosts;
std::set<std::string> tx_remote_hosts;


//asid,command-name to set(resource)
std::map<std::pair<target_ulong, std::string>, std::set<std::string>> cmd_resource_mp;



// I used running_procs map for saving OsiProc,
// but in before-exec-cb, that osiproc hold a not-enough
// length of name or information, so I hold osiproc
// in vmi_pgd_changed callback. this is for tainted-cmd-names
OsiProc *proc_at_pgd;

bool asid_just_changed = false;

uint32_t asid_at_pgd;

bool pid_ok(int pid){
    if(pid < 4){
        return false;
    }else{
        return true;
    }
}

bool check_proc_ok(OsiProc* proc){
    return (proc && pid_ok(proc->pid));
}


std::string hex2str(int dec){
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(2) << std::hex << dec;
    return std::string(oss.str());
}


//uint32_t little_endian_vec(uint8_t *vec, int size){
uint32_t endian_vec(uint8_t *vec, int size, int big){
	uint32_t endianed_val = 0;
	if(big == 1){
		for(int i = size-1; i>=0; i--)
			endianed_val |= vec[i] << ((i-1) * 8);
	}else{
		for(int i = 0; i<size; i++)
			endianed_val |= vec[i] << (i * 8);
	}
	return endianed_val;
}

template<class T> bool contain(const std::string& s, const T& v){
	return s.find(v) != std::string::npos;
}


void str_add(std::string& s, const std::string& v)
{
	if(!contain(s, v)){
		s += v;
	}
}

void update_procs_fdmap(CPUState *cpu, uint32_t fd){
	std::string filename = get_filename_from_fd(cpu, fd);
	uint32_t asid = panda_current_asid(cpu);
	procs_fdmap[asid][fd] = filename;
}

std::string get_procs_fdmap(CPUState* cpu, uint32_t fd){
	uint32_t asid = panda_current_asid(cpu);
	return procs_fdmap[asid][fd];
}


#ifdef TARGET_I386

void hex_dump(const uint8_t *buf, int size)
{
    int len, i, j, c;
    for(i=0;i<size;i+=16) {
        len = size - i;
        if (len > 16)
            len = 16;
        fprintf(stdout, "%08x ", i);
        for(j=0;j<16;j++) {
            if (j < len)
                fprintf(stdout, " %02x", buf[i+j]);
            else
                fprintf(stdout, "   ");
        }
        fprintf(stdout, " ");
        for(j=0;j<len;j++) {
            c = buf[i+j];
            if (c < ' ' || c > '~')
                c = '.';
            fprintf(stdout, "%c", c);
        }
        fprintf(stdout, "\n");
    }
}


uint32_t get_syscall_retval(CPUState* cpu){
	CPUArchState *env = (CPUArchState*)cpu->env_ptr;
	return env->regs[R_EAX]; 
}


std::string get_filename_from_fd(CPUState* cpu, uint32_t fd){
	std::string the_filename;
	uint32_t asid = panda_current_asid(cpu);
	OsiProc& proc = running_procs[asid];
	char *filename = osi_linux_fd_to_filename(cpu, &proc, fd);

	if(filename != NULL){
		the_filename = std::string(filename);
	}else{
		the_filename = "(" ISNULL " fd:" + std::to_string(fd) + ")";
	}
	return the_filename;
};

uint64_t get_pos_from_fd(CPUState* cpu, uint32_t fd){
	uint32_t asid = panda_current_asid(cpu);
	OsiProc& proc = running_procs[asid];
	uint64_t pos = osi_linux_fd_to_pos(cpu, &proc, fd);
    return pos;
};


std::string get_current_command(CPUState* cpu){
	uint32_t asid = panda_current_asid(cpu);
    char *comm = running_procs[asid].name;
	return (comm ? std::string(comm) : ISNULL);
}


std::set<std::string> get_commands_from_pid(uint32_t pid){
    std::set<std::string> cmds;
    for(auto x : running_procs){
        if(x.second.pid == pid){
            if(x.second.name){
                cmds.insert(std::string(x.second.name));
            }
        }
    }
    return cmds;
}

//get command-name of current's parent-process.
std::set<std::string> get_current_parent_command(CPUState* cpu){
    std::set<std::string> parent_cmds;
    uint32_t asid = panda_current_asid(cpu);
    OsiProc& current = running_procs[asid];
    parent_cmds = get_commands_from_pid(current.ppid);
    return parent_cmds;
}


void get_current_mod(CPUState* cpu, target_ulong pc_addr){
	uint32_t asid = panda_current_asid(cpu);
	uint32_t pc;
	if(pc_addr == 0){
		pc = panda_current_pc(cpu);
	}else{
		pc = pc_addr;
	}

	OsiProc *current = get_current_process(cpu);
    OsiModules *ms = get_libraries(cpu, current);
	OsiModule m;

	//Set blank string in current pc's if not defined yet.
    if(procs_mapped_modules[asid].count(pc) == 0){
        procs_mapped_modules[asid][pc] = ISNULL;
    }

	if(ms==NULL) return;

	for(int i=0; i < ms->num; i++){
		m = ms->module[i];
		for(auto x : procs_mapped_modules[asid]){
			if(x.second == ISNULL){
				if(x.first > m.base && x.first<(m.base+m.size)){
                    procs_mapped_modules[asid][x.first] = m.name;
                    //if m.file is NULL, name will be "[???]"

                    if(m.file){
                        procs_pc_module_mp[asid][x.first] = std::make_pair(get_current_command(cpu), m.name);
                        procs_refered_module[asid].insert(m.name);
                    }
				}
			}
		}
	}
	return;
}



bool is_in_watched_cmd(CPUState* cpu){
    if(contain(get_current_command(cpu), watched_cmd))
        return true;
    else
        return false;
}


void monitor_resource_access(CPUState* cpu, std::string call_name, int fd,uint32_t size){
	std::string filename = get_filename_from_fd(cpu, fd);
    Info_resource touched;
    touched.resource_name = filename;
    touched.cmd = get_current_command(cpu);
    touched.parent_cmds = get_current_parent_command(cpu);
    touched.size = size;
    touched.rr_count = rr_get_guest_instr_count();
    //resource_touched[call_name].insert(touched);
    resource_touched[call_name].push_back(touched);
}


int app_getlabels(uint32_t el, void *stuff1){
	if(el){
		((std::set<uint32_t> *)stuff1)->insert(el);
		return 0;
	}else{
		return 1;
	}
}

void check_virtaddr_labeled(CPUState* cpu, target_ulong virt_addr, std::set<uint32_t> &ls){
    hwaddr pa = panda_virt_to_phys(cpu, virt_addr);
	//for checking taint labels, id or something.
    if (pa != (hwaddr) -1) {
        taint2_labelset_ram_iter(pa, app_getlabels, &ls);
    }
}


bool is_tapped_buf_labeled(CPUState* cpu, uint32_t addr, uint32_t len, int fd, std::string tapped_call){ 
    if(!taint2_enabled()){return false;};

	Info_out t;
	t.cmd = get_current_command(cpu);
    t.parent_cmds = get_current_parent_command(cpu);
	t.resource = get_filename_from_fd(cpu,fd);
	t.syscall = tapped_call;
    t.buf = get_buf_dump(cpu, addr, len);
	t.rr_count = rr_get_guest_instr_count();
    t.fd = fd;

    for(int i=0; i<len; i++){
        check_virtaddr_labeled(cpu, addr+i, t.ls);
    } 

	if(t.ls.size() > 0){
        taint_outs.push_back(t);
        return true;
    }else{
        return false;
    }

}


// label this virtual address.  might fail, so
// returns true if byte was labeled
bool label_byte(CPUState *cpu, target_ulong virt_addr, uint32_t label_num) {
    if(!taint2_enabled()) return false;
	
    hwaddr pa = panda_virt_to_phys(cpu, virt_addr);
    if (pa == (hwaddr) -1) {
        printf ("label_byte: virtual addr " TARGET_FMT_lx " not available\n", virt_addr);
        return false;
    }

    taint2_label_ram(pa, label_num);
    
    return true;
}


void ranged_label_byte(CPUState *cpu, target_ulong pc, target_ulong virt_addr, uint32_t len, int fd, std::string tap_call) {
    if(!taint2_enabled()) return;

	if(len>0){
		static uint32_t label_num = 0;
        std::string buf_data = get_buf_printable(cpu, virt_addr, len, true);
		Info_t tap;
		tap.asid = panda_current_asid(cpu);
		tap.pc = pc;
		tap.syscall = tap_call;
		tap.resource = get_filename_from_fd(cpu,fd);
		tap.cmd = get_current_command(cpu);
		tap.parent_cmds = get_current_parent_command(cpu);
		tap.range_size = len;
		tap.rr_count = rr_get_guest_instr_count();
        tap.fd = fd; 

        if(!no_positional_labels){
            label_num += 1;
        }else{
            label_num = 1;
        }

		for(int i = 0; i < len; i++){
			label_byte(cpu, virt_addr+i, label_num);
        }

        // In the case of taint in, payload is possibly be splitted because of transported in TCP,
        // and these data is concatenated before read to buffer by sys_readv()
		// So check whether buf_data(bigger one) contains packet payload or not.
        // Constraint: resource's filename is null.
        if(contain(tap.resource, ISNULL)){
            if((buf_data.size()/2 <= 1460 and buf_data==rx_packet_payload) or \
            (buf_data.size()/2 > 1460 and contain(buf_data, rx_packet_payload))){
                tap.resource += " (Matched-net-incoming " + rx_last_tcp_conn + ")";
                tap.candidate_src_host = rx_last_tcp_conn;
                label_network_rx_mp[label_num] = rx_last_tcp_conn;
			}
		}
		taint_label_info[ label_num ] = tap;
	}
}

uint32_t buf_virtaddr_little_endianed(CPUState *cpu, uint32_t addr, uint64_t len){
	uint32_t little_endianed=0;
	uint8_t tmp = -1;
	for(int i = 0; i < len; i++){
		panda_virtual_memory_rw(cpu, addr+i, (uint8_t *)&tmp, sizeof(tmp), 0);
		little_endianed |= (uint32_t)tmp << (i*8);
	}
	return little_endianed;
};


std::vector<uint8_t> get_buf_dump(CPUState *cpu, uint32_t addr, uint32_t len){
	std::vector<uint8_t> dumped_buf;
	uint8_t cell = -1;
	for(int i = 0; i < len; i++){
		panda_virtual_memory_rw(cpu, addr+i, (uint8_t *)&cell, sizeof(cell), 0);
		dumped_buf.push_back(cell);
	}
	return dumped_buf;
}


std::string get_buf_printable(CPUState *cpu, uint32_t addr, uint32_t len, bool in_hex){
	std::string printable_str;
	std::vector<uint8_t> dumped_buf;
	dumped_buf = get_buf_dump(cpu, addr, len);
	for(uint8_t c : dumped_buf){
		if(in_hex){
			printable_str += hex2str(c);
		}else if(isprint(c)){
			printable_str += c;
		}else{
			printable_str += ".";
		}
	}
	return printable_str;
}


std::string get_strncpy_buf(CPUState *cpu, target_ulong guest_addr, size_t max_len){
	std::string str;
	char *buf = new char[max_len];
	int i;
    uint8_t c;
	for(i=0; i<max_len; i++){
		panda_virtual_memory_rw(cpu, guest_addr+i, &c, 1, 0);
		buf[i] = c;
		if(c == '\x00') break;
	}
	str = std::string(buf);
    delete[] buf;
    buf = NULL;
	return str;
}


void buf_dump_panda_virtaddr(CPUState *cpu, uint32_t addr, uint64_t len, bool fmt_char){
	int64_t ch = -1;
	for(int i = 0; i < len; i++){
		panda_virtual_memory_rw(cpu, addr+i, (uint8_t *)&ch, sizeof(ch), 0);
		if(fmt_char){
            if(isprint((char)ch))
                printf("%c", (char)ch);	
            else
                printf(".");	
		}else{
			printf("%02x ", (uint8_t)ch);	
		}
	}
	printf("\n");
};


//bool cb_satisfy_read_taint(CPUState* cpu, uint32_t fd, uint32_t buf, uint32_t len, uint32_t rx_cb_state){
bool cb_satisfy_read_taint(CPUState* cpu, uint32_t fd, uint32_t buf, uint32_t len){
    if(no_taint) return false;
//	//////////////////////////
//	//for handling incoming access
//	bool is_rx_taint = false;
//    if(rx_taint){
//        if(rx_cb_state == ENTER){
//            is_rx_taint = (rx_taint && is_in_watched_cmd(cpu));
//        }else if(rx_cb_state == RETURN){
//            bool is_rx_payload = false;
//            std::string buf_data;
//            buf_data = get_buf_printable(cpu, buf, len, true);
//            if(contain(buf_data, rx_packet_payload)){
//                is_rx_payload = true;
//            }
//            is_rx_taint = (rx_taint && is_in_watched_cmd(cpu) && is_rx_payload);
//        }
//    }
//	//////////////////////////

	std::string the_filename = get_filename_from_fd(cpu, fd);
	bool is_tainted_file = (file_taint && contain(the_filename, taint_filename));
	// Taint if fd is what I specified.
	// and check if in the process we watched.
	bool is_watched_fd = ((fd==watched_fd_num) && is_in_watched_cmd(cpu));
    bool is_all_taint = (all_read_taint && is_in_watched_cmd(cpu));
    bool is_all_file_taint = (all_file_taint && !contain(the_filename, ISNULL));

	//if(is_tainted_file || is_watched_fd  ||  is_all_taint || is_all_file_taint || is_rx_taint){
	if(is_tainted_file || is_watched_fd  ||  is_all_taint || is_all_file_taint){
        return true;
    }
    return false;
}


void cb_taint(CPUState* cpu, std::string read_call, int fd, uint32_t buf, uint32_t count, uint32_t cb_state){
    static std::map<std::string, target_ulong> sysenter_pc_mp;

    if(cb_state == ENTER){
        if(cb_satisfy_read_taint(cpu, fd, buf, count)){
            if(!taint2_enabled()){
				sysenter_pc_mp[read_call] = panda_current_pc(cpu);
                taint2_enable_taint();
            }
        } 
    }else if(cb_state == RETURN){
        if(count>0 && cb_satisfy_read_taint(cpu, fd, buf, count)){
            if(taint2_enabled()){

				get_current_mod(cpu, sysenter_pc_mp[read_call]);
				
				target_ulong pc = sysenter_pc_mp[read_call];

                ranged_label_byte(cpu, pc, buf, count, fd, read_call);
            }
        }
    }
}


void linux_sys_read(CPUState *cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count, uint32_t cb_state){
    if(cb_state == ENTER){

		//std::cout << "get_current_pc en: 0x" << std::hex << panda_current_pc(cpu) << std::endl;

        cb_taint(cpu, "sys_read", fd, buf, count, cb_state);
    }else if(cb_state == RETURN){

		//std::cout << "get_current_pc re: 0x" << std::hex << panda_current_pc(cpu) << std::endl;

        //update_procs_fdmap(cpu, fd);
        int read_byte = get_syscall_retval(cpu);
        if(read_byte>0){
            cb_taint(cpu, "sys_read", fd, buf, read_byte, cb_state);
        }
        monitor_resource_access(cpu, "sys_read", fd, read_byte);
    }
}


void linux_read_enter(CPUState *cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count) {
    linux_sys_read(cpu, pc, fd, buf, count, ENTER);
	return;
}

void linux_read_return(CPUState *cpu, target_ulong pc, uint32_t fd, uint32_t buf, uint32_t count) {
    linux_sys_read(cpu, pc, fd, buf, count, RETURN);
	return;
}

void linux_open_enter(CPUState *cpu, target_ulong pc, uint32_t filename, int32_t flags, int32_t mode) {
	return;
}

void linux_open_return(CPUState* cpu,target_ulong pc,uint32_t filename,int32_t flags,int32_t mode){
	std::string the_filename = get_strncpy_buf(cpu, filename, MAX_FILENAME);
	std::cout << "Fileopen : " << the_filename << std::endl;

    int the_fd = get_syscall_retval(cpu);
	target_ulong the_asid = panda_current_asid(cpu);
	std::string opened_filename =  the_filename;

	if(contain(opened_filename, taint_filename)){
		fd_watched.push_back( {the_fd, the_asid} );
	}

    return;
}

void linux_sys_readv(CPUState* cpu,target_ulong pc,uint32_t fd,uint32_t vec,uint32_t vlen, uint32_t cb_state){

    if(cb_state == ENTER){
        cb_taint(cpu, "sys_readv", fd, 0, 0, cb_state);
    }else if(cb_state == RETURN){
        //update_procs_fdmap(cpu, fd);

        //this retval uses for range of taint.
        int readv_byte = get_syscall_retval(cpu);
        std::vector<uint8_t> readv_buf = get_buf_dump(cpu, vec, vlen*(sizeof(struct iovec32)));

        struct iovec32 *iovec_info = new struct iovec32[vlen];
        cast_to_struct(*iovec_info, readv_buf);

        uint32_t addr;
        uint32_t len;
        for(int i = 0; i<vlen; i++){
            //castしたときに既にリトルエンディアン済み
            addr = iovec_info[i].iov_base.val;
            len = iovec_info[i].iov_len.val;
            if(len>0 && readv_byte>0){
                cb_taint(cpu, "sys_readv", fd, addr, readv_byte, cb_state);
            }
        }
        monitor_resource_access(cpu, "sys_read", fd, readv_byte);
    }
}

void linux_readv_enter(CPUState* cpu,target_ulong pc,uint32_t fd,uint32_t vec,uint32_t vlen){
    linux_sys_readv(cpu, pc, fd, vec, vlen, ENTER);
	return;
}

void linux_readv_return(CPUState* cpu,target_ulong pc,uint32_t fd,uint32_t vec,uint32_t vlen){
    linux_sys_readv(cpu, pc, fd, vec, vlen, RETURN);
	return;
}


void linux_sys_write(CPUState* cpu,target_ulong pc,uint32_t fd,uint32_t buf,uint32_t count, uint32_t cb_state){
	if(cb_state == ENTER){
		monitor_resource_access(cpu, "sys_write", fd, 0);
        cb_sys_tapped(cpu, "sys_write", fd, buf, count, cb_state);
        return;
	}else if(cb_state == RETURN){
        cb_sys_tapped(cpu, "sys_write", -1, 0, 0, cb_state);
		return;
	}
}

void linux_write_enter(CPUState* cpu,target_ulong pc,uint32_t fd,uint32_t buf,uint32_t count){
	linux_sys_write(cpu, pc, fd, buf, count, ENTER);
	return;
}

void linux_write_return(CPUState* cpu,target_ulong pc,uint32_t fd,uint32_t buf,uint32_t count){
	linux_sys_write(cpu, pc, fd, buf, count, RETURN);
	return;
}


void linux_sys_writev(CPUState* cpu,target_ulong pc,uint32_t fd,uint32_t vec,uint32_t vlen, uint32_t cb_state){
    struct iovec32 *iovec_info;
    uint32_t addr;
    uint32_t len;
	if(cb_state == ENTER){
        monitor_resource_access(cpu, "sys_writev", fd, 0);
        std::vector<uint8_t> writev_buf = get_buf_dump(cpu, vec, vlen*(sizeof(struct iovec32)));
        iovec_info = new struct iovec32[vlen];
        cast_to_struct(*iovec_info, writev_buf);
        for(int i = 0; i<vlen; i++){
            addr = iovec_info[i].iov_base.val;
            len = iovec_info[i].iov_len.val;
            cb_sys_tapped(cpu, "sys_writev", fd, addr, len, cb_state);
        }
		return;
	}else if(cb_state == RETURN){
        cb_sys_tapped(cpu, "sys_writev", -1, 0, 0, cb_state);
        return;
    }
}


void linux_writev_enter(CPUState* cpu,target_ulong pc,uint32_t fd,uint32_t vec,uint32_t vlen){
    linux_sys_writev(cpu, pc, fd, vec, vlen, ENTER);
	return;
}

void linux_writev_return(CPUState* cpu,target_ulong pc,uint32_t fd,uint32_t vec,uint32_t vlen){
	return;
}

void linux_stat64_enter(CPUState* cpu,target_ulong pc,uint32_t filename,uint32_t statbuf){
//	std::string the_filename = get_strncpy_buf(cpu, filename, MAX_FILENAME);
//	std::cout << "file-stat64: " << the_filename << std::endl;
	return;
}

void linux_stat64_return(CPUState* cpu,target_ulong pc,uint32_t filename,uint32_t statbuf){
//	std::string the_filename = get_strncpy_buf(cpu, filename, MAX_FILENAME);
//	std::cout << "file-stat64-return: " << the_filename << std::endl;
	return;
}

void linux_execve_enter(CPUState* cpu,target_ulong pc,uint32_t filename,uint32_t argv,uint32_t envp){
//	std::string the_filename = get_strncpy_buf(cpu, filename, MAX_FILENAME);
//	std::cout << "execve-enter: " << the_filename << std::endl;
	return;
}


void linux_execve_return(CPUState* cpu,target_ulong pc,uint32_t filename,uint32_t argv,uint32_t envp){
//	std::string the_filename = get_strncpy_buf(cpu, filename, MAX_FILENAME);
//	std::cout << "execve-return: " << the_filename << std::endl;
	return;
}


void linux_all_sys_enter(CPUState *cpu, target_ulong pc, target_ulong callno){
//	std::cout << "syscallname: " << syscall_name[callno] << std::endl;
	return;
}

void linux_all_sys_return(CPUState *cpu, target_ulong pc, target_ulong callno){
	return;
}

void sys_connect(CPUState* cpu, int32_t call, uint32_t args, uint32_t cb_state){
	if(cb_state == ENTER){
		uint32_t sys_buf;
		std::vector<uint8_t> sock_vec;
		struct sockaddr_in32 *sin_info;
//		uint32_t port;
		uint32_t ipaddr;
		struct in_addr inaddr;
		std::string ipaddr_str;

		sys_buf =   buf_virtaddr_little_endianed(cpu, args+4, 4);
		sock_vec = get_buf_dump(cpu, sys_buf, sizeof(struct sockaddr_in32));

		sin_info = new struct sockaddr_in32;
		cast_to_struct(*sin_info, sock_vec);
//		port = sin_info->sin_port.val;
		ipaddr = sin_info->sin_addr.val;
		inaddr.s_addr = ipaddr;
		ipaddr_str = std::string(inet_ntoa(inaddr));
//		std::cout << "sys_conn ip: " << std::string(inet_ntoa(inaddr)) << std::endl;
//		std::cout << "sys_conn port: " << ntohs(port) << std::endl;
	}
}

void sys_send(CPUState* cpu, int32_t call, uint32_t args, uint32_t cb_state){
//    std::cout << "sys_send " << std::endl;
	uint32_t sys_buf;
	sys_buf =   buf_virtaddr_little_endianed(cpu, args+4, 4);
//	std::cout << std::hex << sys_buf << std::endl;
//	std::cout << "sys_buf: ";
	buf_dump_panda_virtaddr(cpu, sys_buf, 30, false);
//	std::cout << std::endl;
}


void cb_sys_tapped(CPUState* cpu, std::string tapped_syscall, int fd, uint32_t buf, uint32_t len, uint32_t cb_state){

    static std::map<std::string, uint64_t> tapped_rr_count_mp;
    static std::map<std::string, std::vector<std::string>> tapped_bufvec_mp;

	if(cb_state == ENTER){
		bool labeled = is_tapped_buf_labeled(cpu, buf, len, fd, tapped_syscall);
        if(labeled){
            tapped_rr_count_mp[tapped_syscall] = rr_get_guest_instr_count();
            std::string buf_data = get_buf_printable(cpu, buf, len, true);
            tapped_bufvec_mp[tapped_syscall].push_back(buf_data);
        }
    }else if(cb_state == RETURN){
        uint64_t rr_count_at_tapped = tapped_rr_count_mp[tapped_syscall];
        for(std::string data : tapped_bufvec_mp[tapped_syscall]){
            //writevなどで複数に分けてパケットに書き込まれることもあると想定
			//checking if data matched or not.
            //mss is 1460
            if(((data.size())/2<=1460 and tx_packet_payload==data) or \
               ((data.size())/2 > 1460 and contain(data, tx_packet_payload))){
//                std::cout << "Matched data with new_cb exfiltration " << tapped_syscall << std::endl;
                transfered_data_info[rr_count_at_tapped] = tx_last_tcp_conn;
            }
        }
        //re-initialization
        rr_count_at_tapped = 0; 
        tapped_bufvec_mp[tapped_syscall].clear();
        tapped_bufvec_mp[tapped_syscall].shrink_to_fit();
    }
    return;
}


void sys_sendto(CPUState* cpu, int32_t call, uint32_t args, uint32_t cb_state){
	uint32_t sys_buf;
	uint32_t sys_len;
	uint32_t sys_fd;

    sys_fd =   buf_virtaddr_little_endianed(cpu, args, 4);
    sys_buf =   buf_virtaddr_little_endianed(cpu, args+4, 4);
    sys_len =   buf_virtaddr_little_endianed(cpu, args+8, 4);
    //update_procs_fdmap(cpu, sys_fd);

	if(cb_state == ENTER){

        monitor_resource_access(cpu, "sys_sendto", sys_fd, sys_len);

        cb_sys_tapped(cpu, "sys_sendto", sys_fd, sys_buf, sys_len, cb_state);
		return;
	}else if(cb_state == RETURN){
        cb_sys_tapped(cpu, "sys_sendto", -1, 0, 0, cb_state);
        return;
    }
}


void sys_recv(CPUState* cpu, int32_t call, uint32_t args, uint32_t cb_state){
	uint32_t sys_buf;
	uint32_t sys_len;
	if(cb_state == ENTER){
		sys_buf =   buf_virtaddr_little_endianed(cpu, args+4, 4);
		sys_len =   buf_virtaddr_little_endianed(cpu, args+8, 4);
//        std::cout << "recv_buf: ";
        buf_dump_panda_virtaddr(cpu, sys_buf, sys_len, false);
		return;
	}else if(cb_state == RETURN){
		return;
    }
}

void sys_recvmsg(CPUState* cpu, int32_t call, uint32_t args, uint32_t cb_state){
}

void linux_socketcall_enter(CPUState* cpu,target_ulong pc,int32_t call,uint32_t args){
//std::cout << "socketcall_func_enter: " << sys_sockcall_name[call] << std::endl;
	if(sockcalls[call] != NULL)
		sockcalls[call](cpu, call, args, ENTER);
}

void linux_socketcall_return(CPUState* cpu,target_ulong pc,int32_t call,uint32_t args){
//std::cout << "socketcall_func_return: " << sys_sockcall_name[call] << std::endl;
	if(sockcalls[call] != NULL)
		sockcalls[call](cpu, call, args, RETURN);
}


void linux_fork_enter(CPUState* cpu,target_ulong pc){
//    std::cout << "linux_fork_enter" << std::endl;
}

void linux_fork_return(CPUState* cpu,target_ulong pc){
//	uint32_t newpid = get_syscall_retval(cpu);
//	std::cout << "linux_fork pid: " << std::dec << newpid << " current-cmd:" << get_current_command(cpu) << std::endl;
}

void taint_change(Addr addr, uint64_t size){

	CPUState* cpu = first_cpu;
	if(panda_in_kernel(cpu)) return;
    Tainted_cmd command;
    command.cmd = get_current_command(cpu);
    command.parent_cmds = get_current_parent_command(cpu);
    command.asid = panda_current_asid(cpu);
    command.rr_count = rr_get_guest_instr_count();

	get_current_mod(cpu, 0);
    std::set<uint32_t> taint_changed_labels;
	taint2_labelset_addr_iter(addr, app_getlabels, &taint_changed_labels);
  
    tainted_commands.insert(command);

    Tainted_instr ti;
    ti.pc = panda_current_pc(cpu);
    ti.asid = panda_current_asid(cpu);
    ti.rr_count = rr_get_guest_instr_count();
	ti.labels = taint_changed_labels;
    tainted_instrs.push_back(ti);

    for(uint32_t x : taint_changed_labels){
        taint_label_info[x].propagate_count += 1;
    }

	///////////
	//function call checking!!
	uint64_t cur_rr_count = rr_get_guest_instr_count();
	if(check_funcall){
		// only if in 'userland' and in 'watched_cmd'
		//if(is_in_watched_cmd(cpu) and !panda_in_kernel(cpu)){
        //
        //but, std::set is not duplicable, and call_stack is userland-only stacked container, so, i think need not to care about ring0 or ring3...
		//if(is_in_watched_cmd(cpu)){
		if(is_in_watched_cmd(cpu) and !panda_in_kernel(cpu)){
			if(!call_stack.empty()){
				taint_funcs.insert( call_stack.top() );

				if(cur_rr_count > 0 and cur_rr_count <= check_funcall_rr){
					taint_funcs_rr_limited.insert( call_stack.top() );
				}

			}else{
				taint_funcs.insert( "<nofunc>" );
			}
		}
	}
	///////////


	return;
}

void linux_fchmodat_enter(CPUState* cpu,target_ulong pc,int32_t dfd,uint32_t filename,uint32_t mode){
	return;
}

void linux_fchmodat_return(CPUState* cpu,target_ulong pc,int32_t dfd,uint32_t filename,uint32_t mode){
	std::string the_filename = get_strncpy_buf(cpu, filename, MAX_FILENAME);
//	std::cout << "fchmodat_return: " << the_filename << " mode: " << std::oct << mode <<  " cmd:";
//    std::cout << std::dec;
	for(auto x : get_current_parent_command(cpu))
//		std::cout << x << " ";
//	std::cout << std::endl;
	return;
}

void linux_unlinkat_enter(CPUState* cpu,target_ulong pc,int32_t dfd,uint32_t pathname,int32_t flag){
	std::string the_filename = get_strncpy_buf(cpu, pathname, MAX_FILENAME);
//	std::cout << "unlinkat_enter: " << the_filename << " : flag: " << std::dec << flag << " cmd:" ;
	for(auto x : get_current_parent_command(cpu)){
//		std::cout << x << " ";
	}
//	std::cout << std::endl;
}




void linux_mkdir_enter(CPUState* cpu,target_ulong pc,uint32_t pathname,int32_t mode){
	std::string dirname = get_strncpy_buf(cpu, pathname, MAX_FILENAME);
//    std::cout << "mkdir_enter: " << dirname << std::endl;

    std::pair< target_ulong, std::string > os_cmd = std::make_pair( panda_current_asid(cpu), get_current_command(cpu) );
    
    cmd_resource_mp[os_cmd].insert(dirname);

}




int osi_process_introspection(CPUState *cpu, TranslationBlock *tb) {
    if(tb){
		cur_tb_size = tb->size;
		cur_tb_pc = tb->pc;
    }

//    std::string hoge = get_disas_pc(cpu, cur_tb_pc, cur_tb_pc, cur_tb_size);
//    std::cout << hoge << std::endl;
//		if(!panda_in_kernel(cpu)){
//			last_user_pc = panda_current_pc(cpu);
//		}

	if(panda_in_kernel(cpu)){
		OsiProc *p = get_current_process(cpu);
		target_ulong asid = panda_current_asid(cpu);
		//sanity check on what we think the current process is
		if(p->offset==0) return 0;
		//or the name
		if(p->name==0) return 0;
		if(((int) p->pid) == -1) return 0;
		uint32_t n = strnlen(p->name, 32);
		if(n<2) return 0;
		uint32_t np = 0;
		for(uint32_t i=0; i<n; i++){
			np += (isprint(p->name[i]) != 0);
		}
		if(np != n) return 0;
		/////////
        if(asid_just_changed && check_proc_ok(p)){
            running_procs[asid] = *p;
        }
        if(asid_just_changed && check_proc_ok(proc_at_pgd)){
            p = proc_at_pgd;
            asid = asid_at_pgd;
            asid_just_changed = false;
            running_procs[asid] = *p;
        }else if( check_proc_ok(p) ){
            running_procs[asid] = *p;
        }else{
            //if not check_proc_ok(p)
            return 0;
        }
        asid_just_changed = false;
		/////////
	}
	return 0;
}


int vmi_pgd_changed(CPUState *cpu, target_ulong old_pgd, target_ulong new_pgd) {
	proc_at_pgd = get_current_process(cpu);
    if(proc_at_pgd->asid == 0){
        return 0;
    }
    asid_just_changed = true;
    // old_pgd is same with panda_current_asid(cpu), 
    // and new_pgd is asid just now changed.
    // so, old_pgd is same with panda_current_process's asid.
    //この時のold_pgd(つまりpanda_current_asid)は、まさにそのOsiProcを指している
    asid_at_pgd = old_pgd;
    return osi_process_introspection(cpu, NULL);
}


int handle_packet(CPUState *cpu, uint8_t *buf, int size, uint8_t direction, uint64_t old_buf_addr){

    struct iphdr* pkt_iphdr;
    struct tcphdr* pkt_tcphdr;
    struct in_addr inaddr;
    std::string src_addr;
    std::string dst_addr;
    std::string src_port;
    std::string dst_port;

    pkt_iphdr = (struct iphdr*)(buf+sizeof(struct ether_header));
    inaddr.s_addr = pkt_iphdr->saddr;
    src_addr = std::string(inet_ntoa(inaddr));
    inaddr.s_addr = pkt_iphdr->daddr;
    dst_addr = std::string(inet_ntoa(inaddr));

    pkt_tcphdr = (struct tcphdr*)(buf+sizeof(struct ether_header)+sizeof(struct iphdr));
    src_port = std::to_string(ntohs(pkt_tcphdr->source));
    dst_port = std::to_string(ntohs(pkt_tcphdr->dest));

    uint8_t *data = buf+sizeof(struct ether_header)+sizeof(struct iphdr) + (pkt_tcphdr->doff)*4;
    int data_size = size-(sizeof(struct ether_header)+sizeof(struct iphdr)+(pkt_tcphdr->doff)*4);

    std::string payload;
    for(int i = 0; i<data_size; i++){
        payload += hex2str(data[i]);
    }

    if(direction == PANDA_NET_TX){
        tx_packet_payload = payload;
        tx_last_tcp_conn = dst_addr+":"+dst_port;
		tx_remote_hosts.insert(tx_last_tcp_conn);
    }

    if(direction == PANDA_NET_RX){
        rx_packet_payload = payload;
        rx_last_tcp_conn = src_addr+":"+src_port;
		rx_remote_hosts.insert(rx_last_tcp_conn);
    }

//	std::cout << "pktsize: " << std::dec << size << std::endl;
//    std::cout << "pkt_comm: " << get_current_command(cpu) << std::endl;
//    hex_dump(buf, size);

    return 0;
}

//int after_block_translate(CPUState *cpu, TranslationBlock *tb){
////    cur_tb_size = tb->size;
////	cur_tb_pc = tb->pc;
//    return 1;
//}


enum instr_type {
  INSTR_UNKNOWN = 0,
  INSTR_CALL,
  INSTR_RET,
  INSTR_SYSCALL,
  INSTR_SYSRET,
  INSTR_SYSENTER,
  INSTR_SYSEXIT,
  INSTR_INT,
  INSTR_IRET,
};

struct instr_detail{
	instr_type type;
	std::string opcode;
};

//std::map<target_ulong, instr_type> call_cache;
std::map<target_ulong, instr_detail> call_cache;
csh cs_handle_32_2;
csh cs_handle_64_2;
//procname and stacks
//instr_type disas_after_block_translate(CPUArchState* env, target_ulong pc, int size) {
instr_detail disas_after_block_translate(CPUArchState* env, target_ulong pc, int size) {
    unsigned char *buf = (unsigned char *) malloc(size);
    int err = panda_virtual_memory_rw(ENV_GET_CPU(env), pc, buf, size, 0);
    if (err == -1) printf("Couldn't read TB memory!\n");
    //instr_type res = INSTR_UNKNOWN;
    instr_detail res = {INSTR_UNKNOWN, ISNULL};
#if defined(TARGET_I386)
    csh handle = (env->hflags & HF_LMA_MASK) ? cs_handle_64_2 : cs_handle_32_2;
#elif defined(TARGET_ARM)
    csh handle = cs_handle_32_2;
    if (env->thumb){
        cs_option(handle, CS_OPT_MODE, CS_MODE_THUMB);
    }
    else {
        cs_option(handle, CS_OPT_MODE, CS_MODE_ARM);
    }
//#elif defined(TARGET_PPC)
//    csh handle = cs_handle_32_2;
#endif
    cs_insn *insn;
    cs_insn *end;
    size_t count = cs_disasm(handle, buf, size, pc, 0, &insn);
    if (count <= 0) goto done2;
    for (end = insn + count - 1; end >= insn; end--) {
        if (!cs_insn_group(handle, end, CS_GRP_INVALID)) {
            break;
        }
    }
    if (end < insn) goto done;
    if (cs_insn_group(handle, end, CS_GRP_CALL)) {
		std::string mnem = end->mnemonic;
		std::string op = end->op_str;
		std::string space = " ";
		std::string disas_instr = mnem + space + op;
        //res = INSTR_CALL;
        res = instr_detail{ INSTR_CALL, disas_instr};
    } else if (cs_insn_group(handle, end, CS_GRP_RET)) {
		std::string mnem = end->mnemonic;
		std::string op = end->op_str;
		std::string space = " ";
		std::string disas_instr = mnem + space + op;
//        res = INSTR_RET;
        res = instr_detail{ INSTR_RET, disas_instr};
    } else {
//        res = INSTR_UNKNOWN;
        res = instr_detail{ INSTR_UNKNOWN, ISNULL};
    }
done:
    cs_free(insn, count);
done2:
    free(buf);
    return res;
}

//std::map< std::string , std::stack<std::string> > call_stack;
//defined in "my_helper.h"
//std::stack<std::string> call_stack;
bool just_called_func = false;
int after_block_translate(CPUState *cpu, TranslationBlock *tb) {


	if(check_funcall){

        if(just_called_func and (is_in_watched_cmd(cpu) and !panda_in_kernel(cpu) )){
        //if(just_called_func and is_in_watched_cmd(cpu)){
            func_addrs.insert( tb->pc );
            just_called_func = false;
        }


		CPUArchState* env = (CPUArchState*)cpu->env_ptr;
		instr_detail insd = disas_after_block_translate(env, tb->pc, tb->size);
		std::string command = get_current_command(cpu);
		//if(is_in_watched_cmd(cpu)){
		// only if in 'userland' and in 'watched_cmd'
		if(is_in_watched_cmd(cpu) and !panda_in_kernel(cpu)){
			if(insd.type == INSTR_CALL){
				call_stack.push( insd.opcode );
				watched_cmd_funcs.insert( insd.opcode );

                // for getting address.
                just_called_func = true;

			}else if(insd.type == INSTR_RET){

                // for getting address.
                just_called_func = false;


				if(!call_stack.empty()){
					call_stack.pop();
				}
			}
		}
	}




    return 1;
}

/*
int after_block_exec(CPUState *env, TranslationBlock *tb){
    cur_tb_size = tb->size;
	cur_tb_pc = tb->pc;
	return 0;
}
*/


int cb_virt_mem_after_read(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf)
{
//    if(is_in_watched_cmd(cpu)){
////        std::cout << "cb_virtmem_read: ";
////        buf_dump_panda_virtaddr(cpu, addr, 32, true);
////        //std::cout << size << std::endl;
////        std::cout << "0x" << std::hex << buf << " 0x" << std::hex << addr << std::endl;
//    }
	return 0;
}


int cb_virt_mem_after_write(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf)
{
//    if(is_in_watched_cmd(cpu)){
////        std::cout << "cb_virtmem_write: ";
////        buf_dump_panda_virtaddr(cpu, addr, 32, true);
////        std::cout << "0x" << std::hex << buf << " 0x" << std::hex << addr << std::endl;
//    }
	return 0;
}


//std::set< std::pair<std::string, std::uint64_t> > recorded_stacks;
//// Check if the instruction is sysenter (0F 34)
//bool insn_translate(CPUState *cpu, target_ulong pc) {
////    std::cout << "insn_cur_func: " << get_current_command(cpu) << std::endl;;
//    std::string command = get_current_command(cpu) ;
//	CPUArchState *env = (CPUArchState*)cpu->env_ptr;
//	target_ulong ebp  = env->regs[R_EBP]; 
//    if(!panda_in_kernel(cpu)){
////    std::cout << "insn_cur: " << command << " " << std::hex << "ebp: 0x" << ebp << " :asid: " << panda_current_asid(cpu) << std::endl;
//    }
//
//    recorded_stacks.insert( std::make_pair(command, ebp) );
//
//    return true;
//}

#endif

bool init_plugin(void *self) {

#ifdef TARGET_I386

	panda_cb pcb;
	pcb.before_block_exec = osi_process_introspection;
	panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

	//pcb.after_block_exec = after_block_exec;
	//panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

//    pcb.virt_mem_after_read = cb_virt_mem_after_read;
//	panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);
//	pcb.virt_mem_after_write = cb_virt_mem_after_write; 
//	panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);
//    ///

    pcb.asid_changed = vmi_pgd_changed;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    pcb.replay_handle_packet = handle_packet;
    panda_register_callback(self, PANDA_CB_REPLAY_HANDLE_PACKET, pcb);

/////////
#if defined(TARGET_I386)
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_32_2) != CS_ERR_OK)
#if defined(TARGET_X86_64)
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle_64_2) != CS_ERR_OK)
#endif
#elif defined(TARGET_ARM)
    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cs_handle_32_2) != CS_ERR_OK)
#elif defined(TARGET_PPC)
    if (cs_open(CS_ARCH_PPC, CS_MODE_32, &cs_handle_32_2) != CS_ERR_OK)
#endif
        return false;

    // Need details in capstone to have instruction groupings
    cs_option(cs_handle_32_2, CS_OPT_DETAIL, CS_OPT_ON);
#if defined(TARGET_X86_64)
    cs_option(cs_handle_64_2, CS_OPT_DETAIL, CS_OPT_ON);
#endif

//	pcb.insn_translate = insn_translate;
//	panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
/////////


	//args = panda_get_args("my_network_exploit");
	args = panda_get_args("spaniel");
	debug = panda_parse_bool_opt(args, "debug", "Print debug message");
	no_taint = panda_parse_bool_opt(args, "notaint", "don't actually taint anything");
	file_taint = panda_parse_bool_opt(args, "file_taint", "Let's taint opened file.");
	all_file_taint = panda_parse_bool_opt(args, "all_file_taint", "taint every opened file");
	all_read_taint = panda_parse_bool_opt(args, "all_taint", "Taint every read data, buffer.");

	rx_taint = panda_parse_bool_opt(args, "rx_taint", "Taint watched_process's incoming traffic");

    no_positional_labels = panda_parse_bool_opt(args, "nonpos", "use positional labels");
    no_char = panda_parse_bool_opt(args, "nonchar", "don't use printable character for output, but use hex format");

	taint_filename = panda_parse_string_opt(args, "filename", "abc123", "filename to taint");
	watched_fd_num = panda_parse_ulong(args, "watched_fd", -1 );

	watched_cmd = panda_parse_string_opt(args, "watched_cmd", "abc123", "command name to inspect");


    //last_tainted_rr = panda_parse_uint64_opt(args, "last_tainted_rr", 0, "check tainted instructions until this instruction, just for debugging");
    last_tainted_rr = panda_parse_uint64_opt(args, "last_tainted_rr", 10000000, "check tainted instructions until this instruction, just for debugging");


	check_funcall = panda_parse_bool_opt(args, "check_funcall", "check and recorrd current Function-name.");
	//check_funcall_rr = panda_parse_bool_opt(args, "check_funcall_rr", "check_funcall based on last rr.");
    check_funcall_rr = panda_parse_uint64_opt(args, "check_funcall_rr", 0, "For check_funcall, rr_instr count.");


    init_syscall_mp();

	panda_require("taint2");
	assert(init_taint2_api());

	//before_block_exec requires precise_pc for panda_current_asid(note in: taint2.cpp
	panda_enable_precise_pc();

	if(!init_osi_api()) return false;
    if (panda_os_type == OST_LINUX) {
        panda_require("osi_linux");
        assert(init_osi_linux_api());

        PPP_REG_CB("syscalls2", on_sys_open_enter, linux_open_enter);
        PPP_REG_CB("syscalls2", on_sys_open_return, linux_open_return);

        PPP_REG_CB("syscalls2", on_sys_read_enter, linux_read_enter);
        PPP_REG_CB("syscalls2", on_sys_read_return, linux_read_return);
	
        PPP_REG_CB("syscalls2", on_sys_readv_enter, linux_readv_enter);
        PPP_REG_CB("syscalls2", on_sys_readv_return, linux_readv_return);

        PPP_REG_CB("syscalls2", on_sys_write_enter, linux_write_enter);
        PPP_REG_CB("syscalls2", on_sys_write_return, linux_write_return);

        PPP_REG_CB("syscalls2", on_sys_writev_enter, linux_writev_enter);
        PPP_REG_CB("syscalls2", on_sys_writev_return, linux_writev_return);

        PPP_REG_CB("syscalls2", on_all_sys_enter, linux_all_sys_enter);
        PPP_REG_CB("syscalls2", on_all_sys_return, linux_all_sys_return);

        PPP_REG_CB("syscalls2", on_sys_stat64_enter, linux_stat64_enter);
        PPP_REG_CB("syscalls2", on_sys_stat64_return, linux_stat64_return);

        PPP_REG_CB("syscalls2", on_sys_execve_enter, linux_execve_enter);
        PPP_REG_CB("syscalls2", on_sys_execve_return, linux_execve_return);

        PPP_REG_CB("syscalls2", on_sys_socketcall_enter, linux_socketcall_enter);
        PPP_REG_CB("syscalls2", on_sys_socketcall_return, linux_socketcall_return);

        PPP_REG_CB("syscalls2", on_sys_fork_enter, linux_fork_enter);
        PPP_REG_CB("syscalls2", on_sys_fork_return, linux_fork_return);

        PPP_REG_CB("syscalls2", on_sys_fchmodat_enter, linux_fchmodat_enter);
        PPP_REG_CB("syscalls2", on_sys_fchmodat_return, linux_fchmodat_return);

        //for detecting rm command
        PPP_REG_CB("syscalls2", on_sys_unlinkat_enter, linux_unlinkat_enter);

        //for detecting mkdir command
        PPP_REG_CB("syscalls2", on_sys_mkdir_enter, linux_mkdir_enter);

		std::memset(sockcalls, 0, sizeof(sockcalls));
		sockcalls[SYS_CONNECT] = sys_connect;
		sockcalls[SYS_SEND] = sys_send;
		sockcalls[SYS_SENDTO] = sys_sendto;
		sockcalls[SYS_RECV] = sys_recv;
		sockcalls[SYS_RECVMSG] = sys_recvmsg;

		//setting for taint analysis
		PPP_REG_CB("taint2", on_taint_change, taint_change);
		taint2_track_taint_state();
	}
#endif
    return true;
}

void uninit_plugin(void *self) { 

    std::vector<Edge> graph_edges;

	std::cout << "=============" << std::endl;
	std::cout << "taint_in:" << std::endl;
	for(auto x : taint_label_info){

        ////TaingGraph
        //nodes when tainting are started: src syscall, src resource, src command
        graph_edges.push_back(Edge(Node(SYSCALL, x.second.syscall), Node(BUF, "Tainted Buffer")));
        graph_edges.push_back(Edge(Node(SYSCALL, x.second.syscall), Node(TAINT_SRC, x.second.resource)));
        graph_edges.push_back(Edge(Node(PROC, "cmd:"+x.second.cmd), Node(SYSCALL, x.second.syscall)));

		std::cout << "\tlabel-" << std::dec << x.first << std::endl;
		std::cout << "\t\ttainted_resource: " << x.second.resource << std::endl;
		std::cout << "\t\tsyscall: " << x.second.syscall << std::endl;
		std::cout << "\t\t\trr_instr: " << std::dec << x.second.rr_count << std::endl;
		std::cout << "\t\t\tsize: " << std::dec << x.second.range_size << std::endl;
		std::cout << "\t\tcmd: " << x.second.cmd << std::endl;
        for(auto y : x.second.parent_cmds){
            std::cout << "\t\t\tparent_cmd: " << y << std::endl;

            ////TaingGraph
            //parent's
            graph_edges.push_back(Edge(Node(PROC, "cmd:"+y), Node(PROC, "cmd:"+x.second.cmd)));

		}

//		std::cout << std::endl;
	}

	std::cout << "=============" << std::endl;
	for(auto x : taint_outs){
		std::cout << "taint_out: " << std::endl;
        std::cout << "\tcmd: " << x.cmd << std::endl;
        for(auto y : x.parent_cmds) 
            std::cout << "\t\t\tparent_cmd: " << y << std::endl;

		std::cout << "\tsyscall: " << x.syscall << std::endl; 
		std::cout << "\t\trr_instr: " << std::dec << x.rr_count << std::endl; 
		std::cout << "\t\tresource: " << x.resource << std::endl; 
        if(transfered_data_info.count(x.rr_count) > 0){
			std::cout << "\t\t\tcandidate_dst_host: " << transfered_data_info[x.rr_count] << std::endl;
		}
        if(debug){
            std::cout << "\t\tbuf: size:" << x.buf.size() << " ";
            for(int data : x.buf){
                if(no_char){
                    printf("%02x ", data);
                }else{
                    if(isprint(data))
                        printf("%c", (char)data);
                    else
                        printf(".");
                }
            }
            std::cout << std::endl;
        }

        ////TaingGraph
        //nodes when tainted data are out: dst command, dst syscall, dst resource(file,ipaddress) are checked
        graph_edges.push_back(Edge(Node(BUF, "Tainted Buffer"), Node(PROC, "cmd:"+x.cmd)));
        graph_edges.push_back(Edge(Node(PROC, "cmd:"+x.cmd), Node(SYSCALL, x.syscall)));
        if(contain(x.resource, ISNULL)){
            graph_edges.push_back(Edge(Node(SYSCALL, x.syscall), Node(TAINT_DST, "[fd]"+std::to_string(x.fd))));
        }else{
            graph_edges.push_back(Edge(Node(SYSCALL, x.syscall), Node(TAINT_DST, x.resource)));
        }
        if(transfered_data_info[x.rr_count].size()>0){
            graph_edges.push_back(Edge(Node(SYSCALL, x.syscall), Node(NET_TX, "[tcp]"+transfered_data_info[x.rr_count])));
        }
        ////////////

 		for(uint32_t y : x.ls){
			std::cout << "\t\t\tlabel-" << y << ", " << taint_label_info[y].resource << " ";
			std::cout << "compute:" << std::dec << taint_label_info[y].propagate_count << std::endl;
		}  
	}


    /////////////////////
    std::set<std::string> tainted_mods;
    for(auto p : tainted_instrs){
        if(p.rr_count <= last_tainted_rr){
            std::string modname = procs_pc_module_mp[p.asid][p.pc].second;
            if(modname.size()>0){
                tainted_mods.insert(modname);
            }
        }
    }
    if(tainted_mods.size()>0){
//        std::cout << "\tmodule: " << std::endl;
        for(auto modname : tainted_mods){
//            std::cout << "\t\t" << modname << std::endl;
        }
    }
    /////////////////////

//	std::cout << "===Resource Access===" << std::endl;
//	for(auto x : resource_touched){
//		std::cout << x.first << std::endl;
//		for(auto info : x.second){
//			std::cout <<  "\t" << info.resource_name << " size:" << info.size << " " << std::dec << info.rr_count << " ,";
//			std::cout <<  "\tcmd:" << info.cmd << " ";
//            std::cout << std::endl;
//		}
//	}


//	std::cout << "===Network outgoing host list===" << std::endl;
    for(auto x : tx_remote_hosts){
//		std::cout << x << std::endl;
	}


//	std::cout << "=====================" << std::endl;
	for(auto x : tainted_commands){
		if(x.rr_count <= last_tainted_rr){

            std::set<std::string> cmd_resource = cmd_resource_mp[ std::make_pair(x.asid, x.cmd)];
            if(cmd_resource.size() > 0){
                graph_edges.push_back(Edge(Node(BUF, "Tainted Buffer"), Node(PROC, x.cmd)));
                for(auto y : cmd_resource){
                    graph_edges.push_back(Edge(Node(PROC, x.cmd), Node(OS_OBJECT, y)));
                }
            }
        

//            std::cout << "cmds: " << x.cmd << std::endl;
            for(auto parent : x.parent_cmds){
//                std::cout << "\tparent:" << parent << std::endl;
            }
		}
	}

std::cout << "====" << std::endl;

std::cout << "++++++++++++++++++++++" << std::endl;

    ////TaingGraph
    for(auto p : tainted_instrs){
        if(p.rr_count <= last_tainted_rr){
            std::string modname = procs_pc_module_mp[p.asid][p.pc].second;
            if(modname.size()>0){
                graph_edges.push_back(Edge(Node(BUF, "Tainted Buffer"), Node(MODULE, modname)));
            }
        }
    }
    gen_graph_dot(graph_edges);
    ////////////


//	std::cout << "===============" << std::endl;
//	std::cout << "===============" << std::endl;
//	for(auto x : taint_funcs)
//		std::cout << "t:call: " << x << std::endl;
//	for(auto x : watched_cmd_funcs)
//		std::cout << "w:call: " << x << std::endl;
//	std::cout << "===============" << std::endl;
//	std::cout << "taint: " << taint_funcs.size() << std::endl;;
//	std::cout << "watched: " << watched_cmd_funcs.size() << std::endl;;
//
//
//	std::cout << "===============" << std::endl;
//	for(auto x : taint_funcs_rr_limited)
//		std::cout << "tl:call: " << x << std::endl;
//	std::cout << "taint: " << taint_funcs_rr_limited.size() << std::endl;;
//
//
//
//	std::cout << "===============" << std::endl;
//	std::cout << "===============" << std::endl;
//	for(auto x : func_addrs)
//		std::cout << "addr: 0x" << std::hex << x << std::endl;
//	std::cout << "cnt_addrs: " << std::dec << func_addrs.size() << std::endl;;

}
