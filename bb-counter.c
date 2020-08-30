#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>
#include <errno.h>
#include <sys/user.h>
#include <stdint.h>
#include <fcntl.h>
#include <inttypes.h>
#include <capstone/capstone.h>

//#define TEXT_BASE 0x8048310
//#define TEXT_SIZE 0x1c2

uint32_t n_bb = 0;
uint32_t TEXT_BASE = 0;
uint32_t TEXT_SIZE = 0;
uint32_t MAIN_ADDR = 0;

int get_pc (pid_t pid, uint32_t *eip) {
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, pid, 0, (void*)&regs)) {
		fprintf(stderr, "Failed to fetch registers: %s\n", strerror(errno));
		return -1;
	}

	if (eip) *eip = regs.rip;
	return 0;


}

int single_step(pid_t pid) {
	int retval = 0, status = 0;
	retval = ptrace(PTRACE_SINGLESTEP, pid, 0, 0);

	if (retval) return retval;

	waitpid(pid, &status, 0);
	return status;
}

void get_codes(pid_t pid, uint32_t addr, uint8_t* codes) {
	//uint32_t data[3];
	((uint32_t*)codes)[0] = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, 0);
	((uint32_t*)codes)[1] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(addr+4), 0);
	((uint32_t*)codes)[2] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(addr+8), 0);
	((uint32_t*)codes)[3] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(addr+12), 0);
	((uint32_t*)codes)[4] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(addr+16), 0);
	//fprintf(stdout, "%x %x %x\n", ((uint32_t*)codes)[0], ((uint32_t*)codes)[1], ((uint32_t*)codes)[2]);
}

int disasm (csh handle, uint32_t addr, uint8_t* codes, cs_insn* insn, FILE* fp) {
	size_t count = cs_disasm(handle, codes, sizeof(codes)-1, addr, 0, &insn);
	if (count > 0) {
		fprintf(fp, "%lx %s %s\n", insn[0].address, insn[0].mnemonic, insn[0].op_str);

		if (insn[0].mnemonic[0] == 'j' || strstr(insn[0].mnemonic, "call") != NULL ||
				strstr(insn[0].mnemonic, "ret") != NULL) {
			n_bb++;
		}

		return 0;
	} else {
		//fprintf(stderr, "Failed to disasm: %s\n", strerror(errno));
		fprintf(stdout, "Failed to disasm at %x\n", addr);
		switch (cs_errno(handle)) {
			case CS_ERR_ARCH:
				fprintf(stderr, "Unsupported architecture: cs_open()\n");
				break;
			case CS_ERR_CSH:
				fprintf(stderr, "Invalid csh argument: cs_close(), cs_errno(), cs_option()\n");
				break;
			case CS_ERR_DETAIL:
				fprintf(stderr, "Information is unavailable because detail option is OFF\n");
				break;
			case CS_ERR_DIET:
				fprintf(stderr, "Access irrelevant data in 'diet' engine\n");
				break;
			case CS_ERR_HANDLE:
				fprintf(stderr, "Invalid handle: cs_op_count(), cs_op_index()\n");
				break;
			case CS_ERR_MEM:
				fprintf(stderr, "Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()\n");
				break;
			case CS_ERR_MEMSETUP:
				fprintf(stderr, "Dynamic memory management uninitialized (see CS_OPT_MEM)\n");
				break;
			case CS_ERR_MODE:
				fprintf(stderr, "Invalid/unsupported mode: cs_open()");
				break;
			case CS_ERR_OK:
				fprintf(stderr, "No error: everything was fine\n");
				break;
			case CS_ERR_OPTION:
				fprintf(stderr, "Invalid/unsupported option: cs_option()\n");
				break;
			case CS_ERR_SKIPDATA:
				fprintf(stderr, "Access irrelevant data for 'data' instruction in SKIPDATA mode\n");
				break;
			case CS_ERR_VERSION:
				fprintf(stderr, "Unsupported version (bindings)\n");
				break;
			case CS_ERR_X86_ATT:
				fprintf(stderr, "X86 AT&T syntax is unsupported (opt-out at compile time)\n");
				break;
			case CS_ERR_X86_INTEL:
				fprintf(stderr, "X86 Intel syntax is unsupported (opt-out at compile time)\n");
				break;
			default:
				fprintf(stderr, "unknown error\n");
				break;
		}
		return -1;
	}
}

uint set_bp(pid_t pid, uint32_t addr) {
	uint old_data = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, 0);
	uint new_data = old_data;
	uint status = 0;

	new_data = (new_data & ~0xff) | 0xcc;

	status = ptrace(PTRACE_POKETEXT, pid, (void*)addr, new_data);
	if (status == -1) return status;
	return old_data;
}

uint set_eip(pid_t pid, uint32_t addr) {
	struct user_regs_struct regs;
	uint status = 0;

	status = ptrace(PTRACE_GETREGS, pid, 0, &regs);
	if (status == -1) return status;

	regs.rip = addr;
	status = ptrace(PTRACE_SETREGS, pid, 0, &regs);
	if (status == -1) return status;
	return 0;
}

void main (int argc, char** argv) {
	pid_t target_pid = 0;

	if (argc < 2) {
		fprintf(stderr, "Usage: ./bb-count [target-process]\n");
		return;
	}

	target_pid = fork();

	if (target_pid == -1) {
		fprintf(stderr, "Failed to opend the process: %s\n", strerror(errno));
	} else if (target_pid == 0) {
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execvp(argv[1], argv + 1);
		fprintf(stderr, "Something is wrong...: %s\n", strerror(errno));
	} else {
		uint32_t eip;
		int status = 0;
		uint8_t codes[20];
		int n_sh = 0, n_sym = 0;
		int i = 0, j = 0;
		int sig_num = 0;
		uint opcode_bb = 0;
		char* sh_strtab_p = NULL, *sym_name = NULL, *p = NULL;
		csh handle = 0;
		cs_insn* insn = 0;
		struct stat st;
		Elf32_Ehdr* ehdr = NULL;
		Elf32_Shdr* shdr = NULL, *sh_strtab = NULL;
		Elf32_Sym* symtab = NULL;
		FILE* fp = fopen("trace", "w");
		int parse_fd = open(argv[1], O_RDONLY);


		if (fp != NULL && cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK) {

			waitpid(target_pid, 0, 0);
			ptrace(PTRACE_SETOPTIONS, target_pid, 0, PTRACE_O_EXITKILL);

			if (!stat(argv[1], &st)) {
				p = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, parse_fd, 0);
				ehdr = (Elf32_Ehdr*)p;
				shdr = (Elf32_Shdr*)(p + ehdr->e_shoff);
				n_sh = ehdr->e_shnum;

				sh_strtab = &shdr[ehdr->e_shstrndx];
				sh_strtab_p = p + sh_strtab->sh_offset;
				for (i = 0;i < n_sh;++i) {
					if (strstr(shdr[i].sh_name + sh_strtab_p, "text") != NULL) {
						TEXT_BASE = shdr[i].sh_addr;
						TEXT_SIZE = shdr[i].sh_size;
						//break;
					}

					if (shdr[i].sh_type == SHT_SYMTAB) {
						symtab = (Elf32_Sym*)(p + shdr[i].sh_offset);
						n_sym = (int)(shdr[i].sh_size / shdr[i].sh_entsize);
						sym_name = (char*)(p + shdr[shdr[i].sh_link].sh_offset);

						for (j = 0;j < n_sym;++j) {
							if (strstr(sym_name + symtab[j].st_name, "main") != NULL &&
									strstr(sym_name + symtab[j].st_name, "lib") == NULL 
									&& strstr(sym_name + symtab[j].st_name, "start") == NULL) {
								//fprintf(stdout, "%s %x\n", sym_name + symtab[j].st_name, symtab[j].st_value);
								MAIN_ADDR = symtab[j].st_value;
								break;
							}
						}
					}
				}
				close(parse_fd);

				opcode_bb = set_bp(target_pid, MAIN_ADDR);
				if (opcode_bb == -1) {
					fprintf(stderr, "Faild to set bp: %s\n", strerror(errno));
				}
				status = ptrace(PTRACE_CONT, target_pid, 0, 0);
				if (status == -1) {
					fprintf(stderr, "Failed to continue after bp: %s\n", strerror(errno));
					return;
				}
				waitpid(target_pid, 0, 0);

				fprintf(stdout, "hit the bp for main func\n");
				status = ptrace(PTRACE_POKETEXT, target_pid, (void*)MAIN_ADDR, opcode_bb);
				if (status == -1) {
					fprintf(stderr, "Failed to poketext: %s\n", strerror(errno));
					return;
				}
				status = set_eip(target_pid, MAIN_ADDR);
				if (status == -1) {
					fprintf(stderr, "Faild to set eip: %s\n", strerror(errno));
					return;
				}
				/*
				status = ptrace(PTRACE_CONT, target_pid, 0, 0);
				if (status == -1) {
					fprintf(stderr, "Failed to conrinue after recover eip: %s\n", strerror(errno));
					return;
				}
				*/
				fprintf(stdout, "Start to debugging!\n");
	
				while (1) {
					status = get_pc(target_pid, &eip);
					if (status == -1) break;
	
					//fprintf(stdout, "eip: %p\n", (void*)eip);

					if ((TEXT_BASE <= eip) && (eip < TEXT_BASE + TEXT_SIZE)) {
						get_codes(target_pid, eip, codes);
						//fprintf(fp, "eip: %p\n", (void*)eip);
						status = disasm(handle, eip, codes, insn, fp);
						memset(codes, 0, sizeof(codes));
					}
	
	
					status = single_step(target_pid);
					if (WIFSTOPPED(status)) {
						if (WSTOPSIG(status) == SIGSEGV) {
							fprintf(stdout, "child is dead with SIGSEGV\n");
							break;
						}
					}
				}
	
				fclose(fp);
				cs_close(&handle);
				fprintf(stdout, "Terminate debugging\n");
				fprintf(stdout, "Detach the process(%d)\n", target_pid);
				ptrace(PTRACE_DETACH, target_pid, 0, 0);

				fprintf(stdout, "# of basic blocks: %d\n", n_bb);
			} else {
				fprintf(stderr, "Failed to stat file: %s\n", strerror(errno));
			}
		} else {
			fprintf(stderr, "Failed to open file: %s\n", strerror(errno));
		}
	}

}
