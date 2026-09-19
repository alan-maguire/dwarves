/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
*/

#include <argp.h>
#include <dirent.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "dwarves.h"
#include "dwarves_emit.h"
#include "dutil.h"
#include "elf_symtab.h"

static int verbose;
static int show_inline_expansions;
static int show_variables;
static int show_externals;
static int show_cc_inlined;
static int show_cc_uninlined;
static char *symtab_name;
static bool show_prototypes;
static bool show_all_matches;
static bool expand_types;
static bool compilable_output;
static struct type_emissions emissions;
static uint64_t addr;
static char *class_name;
static char *function_name;
static const char *base_btf_file;
static const char *elf_filename;
static const char *running_object;
static bool show_inline_sites;

static struct conf_fprintf conf;

#define BTF_LOC_PARAM_SIGNED	0x1
#define BTF_LOC_PARAM_CONST	0x2
#define BTF_LOC_PARAM_ADDR	0x4
#define BTF_LOC_PARAM_REG	0x8
#define BTF_LOC_PARAM_DEREF	0x10
#define BTF_LOC_PARAM_OFFSET	0x20
#define BTF_LOC_PARAM_FBREG	0xffffffffU

static struct conf_load conf_load = {
	.conf_fprintf = &conf,
};

static struct languages languages;

struct elf_register_names {
	Dwfl			 *dwfl;
	Dwfl_Module		 *dwfl_module;
	char			 *names[32];
};

struct elf_symtab_ctx {
	int			 fd;
	Elf			 *elf;
	struct elf_symtab	 *symtab;
	struct elf_register_names regs;
};

struct elf_function {
	const char	*name;
	uint64_t	 addr;
	uint64_t	 size;
};

struct elf_functions {
	struct elf_function	*entries;
	uint32_t		 nr_entries;
	bool			 owns_names;
};

struct running_section {
	char		*name;
	uint64_t	 addr;
};

struct running_object_ctx {
	bool			vmlinux;
	uint64_t		addr_base;
	struct running_section	*sections;
	uint32_t		nr_sections;
	struct elf_functions	functions;
	struct elf_register_names regs;
};

static int elf_register_names__cache_name(void *arg, int regno,
					 const char *setname __maybe_unused,
					 const char *prefix,
					 const char *regname,
					 int bits __maybe_unused,
					 int type __maybe_unused)
{
	struct elf_register_names *regs = arg;

	if (regno < 0 || regno >= (int)ARRAY_SIZE(regs->names) || !regname)
		return DWARF_CB_OK;
	if (asprintf(&regs->names[regno], "%s%s", prefix ?: "", regname) < 0)
		return DWARF_CB_ABORT;
	return DWARF_CB_OK;
}

static void elf_register_names__init(struct elf_register_names *regs,
					     const char *filename)
{
	static const Dwfl_Callbacks callbacks = {
		.section_address = dwfl_offline_section_address,
	};
	int fd;

	regs->dwfl = dwfl_begin(&callbacks);
	if (!regs->dwfl)
		return;
	fd = open(filename, O_RDONLY);
	if (fd < 0)
		goto out_dwfl_end;
	regs->dwfl_module = dwfl_report_offline(regs->dwfl, filename, filename, fd);
	if (!regs->dwfl_module)
		goto out_dwfl_end;
	if (dwfl_report_end(regs->dwfl, NULL, NULL))
		goto out_dwfl_end;
	dwfl_module_register_names(regs->dwfl_module, elf_register_names__cache_name, regs);
	return;

out_dwfl_end:
	dwfl_end(regs->dwfl);
	regs->dwfl = NULL;
	regs->dwfl_module = NULL;
}

static void elf_register_names__exit(struct elf_register_names *regs)
{
	for (size_t i = 0; i < ARRAY_SIZE(regs->names); i++)
		free(regs->names[i]);
	if (regs->dwfl)
		dwfl_end(regs->dwfl);
}

static uint64_t elf__addr_base(Elf *elf)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	uint64_t addr_base = UINT64_MAX;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if (!gelf_getshdr(scn, &shdr))
			continue;
		if ((shdr.sh_flags & SHF_ALLOC) && shdr.sh_addr < addr_base)
			addr_base = shdr.sh_addr;
	}

	return addr_base;
}

static int elf_symtab__init(struct elf_symtab_ctx *ctx, const char *filename)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->fd = -1;
	ctx->elf = NULL;
	ctx->symtab = NULL;
	ctx->fd = open(filename, O_RDONLY);
	if (ctx->fd < 0)
		return -1;
	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "%s: cannot set libelf version.\n", __func__);
		goto out_close;
	}
	ctx->elf = elf_begin(ctx->fd, ELF_C_READ_MMAP, NULL);
	if (!ctx->elf) {
		fprintf(stderr, "%s: cannot read %s ELF file.\n", __func__, filename);
		goto out_close;
	}
	ctx->symtab = elf_symtab__new(symtab_name, ctx->elf);
	elf_register_names__init(&ctx->regs, filename);
	return 0;

	elf_end(ctx->elf);
	ctx->elf = NULL;
out_close:
	close(ctx->fd);
	ctx->fd = -1;
	return -1;
}

static void elf_symtab__exit(struct elf_symtab_ctx *ctx)
{
	elf_register_names__exit(&ctx->regs);
	elf_symtab__delete(ctx->symtab);
	if (ctx->elf)
		elf_end(ctx->elf);
	if (ctx->fd >= 0)
		close(ctx->fd);
}

static int elf_function__cmp(const void *a, const void *b)
{
	const struct elf_function *fa = a, *fb = b;

	if (fa->addr != fb->addr)
		return fa->addr < fb->addr ? -1 : 1;
	if (fa->size != fb->size)
		return fa->size < fb->size ? -1 : 1;
	return strcmp(fa->name, fb->name);
}

static int elf_functions__collect(struct elf_functions *functions,
				  const struct elf_symtab *symtab)
{
	uint32_t index;
	GElf_Sym sym;

	functions->entries = calloc(elf_symtab__nr_symbols(symtab),
				   sizeof(*functions->entries));
	if (!functions->entries && elf_symtab__nr_symbols(symtab))
		return -1;
	elf_symtab__for_each_symbol(symtab, index, sym) {
		struct elf_function *function;

		if (elf_sym__type(&sym) != STT_FUNC || !elf_sym__size(&sym) ||
		    elf_sym__section(&sym) == SHN_UNDEF || !*elf_sym__name(&sym, symtab))
			continue;
		function = &functions->entries[functions->nr_entries++];
		function->name = elf_sym__name(&sym, symtab);
		function->addr = elf_sym__value(&sym);
		function->size = elf_sym__size(&sym);
	}
	qsort(functions->entries, functions->nr_entries,
	      sizeof(*functions->entries), elf_function__cmp);
	return 0;
}

static void elf_functions__exit(struct elf_functions *functions)
{
	if (functions->owns_names)
		for (uint32_t i = 0; i < functions->nr_entries; i++)
			free((char *)functions->entries[i].name);
	free(functions->entries);
}

static const struct elf_function *
elf_functions__find(const struct elf_functions *functions, uint64_t addr)
{
	const struct elf_function *best = NULL;
	uint64_t start_addr;
	uint32_t left = 0, right = functions->nr_entries;

	while (left < right) {
		uint32_t mid = left + (right - left) / 2;

		if (functions->entries[mid].addr <= addr)
			left = mid + 1;
		else
			right = mid;
	}
	if (left == 0)
		return NULL;
	--left;
	while (left > 0 && functions->entries[left - 1].addr == functions->entries[left].addr)
		--left;
	start_addr = functions->entries[left].addr;
	for (; left < functions->nr_entries &&
	       functions->entries[left].addr == start_addr; left++) {
		const struct elf_function *function = &functions->entries[left];

		if (addr - function->addr < function->size &&
		    (!best || function->size < best->size))
			best = function;
		if (left + 1 == functions->nr_entries || functions->entries[left + 1].addr > addr)
			break;
	}
	return best;
}

static int running_object__collect_functions(struct running_object_ctx *ctx,
					     const char *module)
{
	struct elf_functions *functions = &ctx->functions;
	FILE *fp;
	char line[512], name[256], module_name[256], type;
	unsigned long long addr;

	fp = fopen("/proc/kallsyms", "r");
	if (!fp)
		return -1;
	while (fgets(line, sizeof(line), fp)) {
		struct elf_function *function;
		int fields;

		module_name[0] = '\0';
		fields = sscanf(line, "%llx %c %255s %255s", &addr, &type, name,
				module_name);
		if (fields < 3 || !addr || !strchr("TtWw", type))
			continue;
		if (module) {
			size_t len = strlen(module_name);

			if (fields != 4 || len < 3 || module_name[0] != '[' ||
			    module_name[len - 1] != ']' ||
			    strncmp(module_name + 1, module, len - 2) != 0 ||
			    module[len - 2] != '\0')
				continue;
		} else if (fields == 4) {
			continue;
		}
		function = realloc(functions->entries,
				   (functions->nr_entries + 1) * sizeof(*functions->entries));
		if (!function)
			goto out_err;
		functions->entries = function;
		function = &functions->entries[functions->nr_entries];
		function->name = strdup(name);
		if (!function->name)
			goto out_err;
		function->addr = addr;
		function->size = 0;
		functions->nr_entries++;
	}
	fclose(fp);
	functions->owns_names = true;
	qsort(functions->entries, functions->nr_entries,
	      sizeof(*functions->entries), elf_function__cmp);
	for (uint32_t i = 0; i < functions->nr_entries;) {
		uint32_t next = i + 1;

		while (next < functions->nr_entries &&
		       functions->entries[next].addr == functions->entries[i].addr)
			next++;
		if (next < functions->nr_entries)
			for (uint32_t j = i; j < next; j++)
				functions->entries[j].size =
					functions->entries[next].addr - functions->entries[j].addr;
		i = next;
	}
	return 0;

out_err:
	fclose(fp);
	functions->owns_names = true;
	elf_functions__exit(functions);
	return -1;
}

static void running_object__exit(struct running_object_ctx *ctx)
{
	elf_functions__exit(&ctx->functions);
	elf_register_names__exit(&ctx->regs);
	for (uint32_t i = 0; i < ctx->nr_sections; i++)
		free(ctx->sections[i].name);
	free(ctx->sections);
}

static uint64_t running_object__section_addr(const struct running_object_ctx *ctx,
					      const char *name)
{
	if (ctx->vmlinux)
		return strcmp(name, ".text") == 0 ? ctx->addr_base : 0;
	for (uint32_t i = 0; i < ctx->nr_sections; i++)
		if (strcmp(ctx->sections[i].name, name) == 0)
			return ctx->sections[i].addr;
	return 0;
}

static int running_object__init_vmlinux(struct running_object_ctx *ctx)
{
	FILE *fp;
	char line[512], name[256], type;
	unsigned long long addr;

	fp = fopen("/proc/kallsyms", "r");
	if (!fp)
		return -1;
	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%llx %c %255s", &addr, &type, name) != 3)
			continue;
		if (strcmp(name, "_stext") == 0) {
			ctx->vmlinux = true;
			ctx->addr_base = addr;
			fclose(fp);
			/* kptr_restrict may be active */
			if (addr == 0)
				return 0;
			return running_object__collect_functions(ctx, NULL);
		}
	}
	fclose(fp);
	return -1;
}

static int running_object__init_module(struct running_object_ctx *ctx, const char *module)
{
	char path[PATH_MAX];
	struct dirent *entry;
	DIR *dir;

	if (strchr(module, '/'))
		return -1;
	if (snprintf(path, sizeof(path), "/sys/module/%s/sections",
		     module) >= (int)sizeof(path))
		return -1;
	dir = opendir(path);
	if (!dir)
		return -1;
	while ((entry = readdir(dir)) != NULL) {
		struct running_section *section;
		FILE *fp;
		unsigned long long addr;

		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;
		if (snprintf(path, sizeof(path), "/sys/module/%s/sections/%s", module,
				     entry->d_name) >= (int)sizeof(path))
			continue;
		fp = fopen(path, "r");
		if (!fp)
			continue;
		if (fscanf(fp, "%llx", &addr) != 1) {
			fclose(fp);
			continue;
		}
		fclose(fp);
		/* kptr_restrict */
		if (addr == 0) {
			closedir(dir);
			return 0;
		}
		section = realloc(ctx->sections,
				  (ctx->nr_sections + 1) * sizeof(*ctx->sections));
		if (!section)
			goto out_err;
		ctx->sections = section;
		section = &ctx->sections[ctx->nr_sections];
		section->name = strdup(entry->d_name);
		if (!section->name)
			goto out_err;
		section->addr = addr;
		if (!ctx->addr_base || addr < ctx->addr_base)
			ctx->addr_base = addr;
		ctx->nr_sections++;
	}
	closedir(dir);
	if (!ctx->nr_sections)
		return -1;
	return running_object__collect_functions(ctx, module);

out_err:
	closedir(dir);
	running_object__exit(ctx);
	return -1;
}

static int running_object__init(struct running_object_ctx *ctx, const char *object)
{
	int err;

	memset(ctx, 0, sizeof(*ctx));
	if (strcmp(object, "vmlinux") == 0)
		err = running_object__init_vmlinux(ctx);
	else
		err = running_object__init_module(ctx, object);
	if (!err) {
		/* For --running, we can use pfunct ELF itself. */
		elf_register_names__init(&ctx->regs, "/proc/self/exe");
	}
	return err;
}

struct fn_stats {
	struct list_head node;
	struct tag	 *tag;
	const struct cu	 *cu;
	uint32_t	 nr_expansions;
	uint32_t	 size_expansions;
	uint32_t	 nr_files;
	bool		 printed;
};

static struct fn_stats *fn_stats__new(struct tag *tag, const struct cu *cu)
{
	struct fn_stats *stats = zalloc(sizeof(*stats));

	if (stats != NULL) {
		const struct function *fn = tag__function(tag);

		stats->tag = tag;
		stats->cu = cu;
		stats->nr_files = 1;
		stats->nr_expansions = fn->cu_total_nr_inline_expansions;
		stats->size_expansions = fn->cu_total_size_inline_expansions;
	}

	return stats;
}

static void fn_stats__delete(struct fn_stats *stats)
{
	free(stats);
}

static LIST_HEAD(fn_stats__list);

static struct fn_stats *fn_stats__find(const char *name)
{
	struct fn_stats *pos;

	list_for_each_entry(pos, &fn_stats__list, node)
		if (strcmp(function__name(tag__function(pos->tag)), name) == 0)
			return pos;
	return NULL;
}

static void fn_stats__delete_list(void)
{
	struct fn_stats *pos, *n;

	list_for_each_entry_safe(pos, n, &fn_stats__list, node) {
		list_del_init(&pos->node);
		fn_stats__delete(pos);
	}
}

static struct fn_stats *fn_stats__add(struct tag *tag, const struct cu *cu)
{
	struct fn_stats *fns = fn_stats__new(tag, cu);
	if (fns != NULL)
		list_add(&fns->node, &fn_stats__list);

	return fns;
}

static void fn_stats_inline_exps_fmtr(const struct fn_stats *stats)
{
	struct function *fn = tag__function(stats->tag);
	if (fn->lexblock.nr_inline_expansions > 0)
		printf("%s: %u %d\n", function__name(fn),
		       fn->lexblock.nr_inline_expansions,
		       fn->lexblock.size_inline_expansions);
}

static void fn_stats_labels_fmtr(const struct fn_stats *stats)
{
	struct function *fn = tag__function(stats->tag);
	if (fn->lexblock.nr_labels > 0)
		printf("%s: %u\n", function__name(fn), fn->lexblock.nr_labels);
}

static void fn_stats_variables_fmtr(const struct fn_stats *stats)
{
	struct function *fn = tag__function(stats->tag);
	if (fn->lexblock.nr_variables > 0)
		printf("%s: %u\n", function__name(fn), fn->lexblock.nr_variables);
}

static void fn_stats_nr_parms_fmtr(const struct fn_stats *stats)
{
	struct function *fn = tag__function(stats->tag);
	printf("%s: %u\n", function__name(fn), fn->proto.nr_parms);
}

static void fn_stats_name_len_fmtr(const struct fn_stats *stats)
{
	struct function *fn = tag__function(stats->tag);
	const char *name = function__name(fn);
	printf("%s: %zd\n", name, strlen(name));
}

static void fn_stats_size_fmtr(const struct fn_stats *stats)
{
	struct function *fn = tag__function(stats->tag);
	const size_t size = function__size(fn);

	if (size != 0)
		printf("%s: %zd\n", function__name(fn), size);
}

static void fn_stats_fmtr(const struct fn_stats *stats)
{
	if (verbose || show_prototypes) {
		tag__fprintf(stats->tag, stats->cu, &conf, stdout);
		putchar('\n');
		if (show_prototypes)
			return;
		if (show_variables || show_inline_expansions)
			function__fprintf_stats(stats->tag, stats->cu, &conf, stdout);
		printf("/* definitions: %u */\n", stats->nr_files);
		putchar('\n');
	} else {
		struct function *fn = tag__function(stats->tag);
		puts(function__name(fn));
	}
}

static void print_fn_stats(void (*formatter)(const struct fn_stats *f))
{
	struct fn_stats *pos;

	list_for_each_entry(pos, &fn_stats__list, node)
		formatter(pos);
}

static void fn_stats_inline_stats_fmtr(const struct fn_stats *stats)
{
	if (stats->nr_expansions > 1)
		printf("%-31.31s %6u %7u  %6u %6u\n",
		       function__name(tag__function(stats->tag)),
		       stats->size_expansions, stats->nr_expansions,
		       stats->size_expansions / stats->nr_expansions,
		       stats->nr_files);
}

static void print_total_inline_stats(void)
{
	printf("%-32.32s  %5.5s / %5.5s = %5.5s  %s\n",
	       "name", "totsz", "exp#", "avgsz", "src#");
	print_fn_stats(fn_stats_inline_stats_fmtr);
}

static void fn_stats__dupmsg(struct function *func,
			     const struct cu *func_cu,
			     struct function *dup __maybe_unused,
			     const struct cu *dup_cu,
			     char *hdr, const char *fmt, ...)
{
	va_list args;

	if (!*hdr)
		printf("function: %s\nfirst: %s\ncurrent: %s\n", function__name(func), func_cu->name, dup_cu->name);

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	*hdr = 1;
}

static void fn_stats__chkdupdef(struct function *func,
				const struct cu *func_cu,
				struct function *dup,
				const struct cu *dup_cu)
{
	char hdr = 0;
	const size_t func_size = function__size(func);
	const size_t dup_size = function__size(dup);

	if (func_size != dup_size)
		fn_stats__dupmsg(func, func_cu, dup, dup_cu,
				 &hdr, "size: %zd != %zd\n",
				 func_size, dup_size);

	if (func->proto.nr_parms != dup->proto.nr_parms)
		fn_stats__dupmsg(func, func_cu, dup, dup_cu,
				 &hdr, "nr_parms: %u != %u\n",
				 func->proto.nr_parms, dup->proto.nr_parms);

	/* XXX put more checks here: member types, member ordering, etc */

	if (hdr)
		putchar('\n');
}

static bool function__filter(struct function *function, struct cu *cu)
{
	struct fn_stats *fstats;
	const char *name;

	if (!function__tag(function)->top_level)
		return true;

	/*
	 * FIXME: remove this check and try to fix the parameter abstract
	 * origin code someday...
	 */
	if (!function->name)
		return true;

	name = function__name(function);
	if (show_externals && !function->external)
		return true;

	if (show_cc_uninlined &&
	    function->inlined != DW_INL_declared_not_inlined)
		return true;

	if (show_cc_inlined && function->inlined != DW_INL_inlined)
		return true;

	fstats = fn_stats__find(name);
	if (fstats != NULL) {
		struct function *fn = tag__function(fstats->tag);

		if (!fn->external)
			return false;

		if (verbose)
			fn_stats__chkdupdef(fn, fstats->cu, function, cu);
		fstats->nr_expansions   += function->cu_total_nr_inline_expansions;
		fstats->size_expansions += function->cu_total_size_inline_expansions;
		fstats->nr_files++;
		return true;
	}

	return false;
}

static int cu_unique_iterator(struct cu *cu, void *cookie)
{
	bool is_btf = cookie != NULL;

	cu__account_inline_expansions(cu);

	struct function *pos;
	uint32_t id;

	cu__for_each_function(cu, id, pos)
		if (is_btf || !function__filter(pos, cu))
			fn_stats__add(function__tag(pos), cu);
	return 0;
}

static int cu_class_iterator(struct cu *cu, void *cookie)
{
	type_id_t target_id;
	struct tag *target = cu__find_struct_by_name(cu, cookie, 0, &target_id);

	if (target == NULL)
		return 0;

	struct function *pos;
	uint32_t id;

	cu__for_each_function(cu, id, pos) {
		if (pos->inlined ||
		    !ftype__has_parm_of_type(&pos->proto, target_id, cu))
			continue;

		if (verbose)
			tag__fprintf(function__tag(pos), cu, &conf, stdout);
		else
			fputs(function__name(pos), stdout);
		putchar('\n');
	}

	return 0;
}

static int function__emit_type_definitions(struct function *func,
					   struct cu *cu, FILE *fp)
{
	struct parameter *pos;
	struct ftype *proto = func->btf ? tag__ftype(cu__type(cu, func->proto.tag.type)) : &func->proto;
	struct tag *type = cu__type(cu, proto->tag.type);

retry_return_type:
	/* type == NULL means the return is void */
	if (type == NULL)
		goto do_parameters;

	if (tag__is_pointer(type) || tag__is_modifier(type)) {
		type = cu__type(cu, type->type);
		goto retry_return_type;
	}

	if (tag__is_type(type) && !tag__type(type)->definition_emitted) {
		type__emit_definitions(type, cu, &emissions, fp);
		type__emit(type, cu, NULL, NULL, fp);
	}
do_parameters:
	ftype__for_each_parameter(proto, pos) {
		type = cu__type(cu, pos->tag.type);
	try_again:
		if (type == NULL)
			continue;

		if (tag__is_pointer(type) || tag__is_modifier(type)) {
			type = cu__type(cu, type->type);
			goto try_again;
		}

		if (type->tag == DW_TAG_subroutine_type) {
			ftype__emit_definitions(tag__ftype(type), cu, &emissions, fp);
		} else if (tag__is_type(type) && !tag__type(type)->definition_emitted) {
			type__emit_definitions(type, cu, &emissions, fp);
			if (!tag__is_typedef(type))
				type__emit(type, cu, NULL, NULL, fp);
			putchar('\n');
		}
	}

	return 0;
}

static void function__show(struct function *func, struct cu *cu)
{
	struct tag *tag = function__tag(func);
	struct fn_stats *fstats = NULL;

	if (func->abstract_origin || func->declaration)
		return;

	if (!show_all_matches) {
		fstats = fn_stats__find(func->name);

		if (fstats && fstats->printed)
			return;
		if (expand_types)
			function__emit_type_definitions(func, cu, stdout);
	}
	tag__fprintf(tag, cu, &conf, stdout);
	if (compilable_output) {
		struct tag *type = cu__type(cu, func->proto.tag.type);

		fprintf(stdout, "\n{");
		if (type != NULL && type->type != 0) { /* NULL == void */
			if (tag__is_pointer(type))
				fprintf(stdout, "\n\treturn (void *)0;");
			else if (tag__is_struct(type))
				fprintf(stdout, "\n\treturn *(struct %s *)1;", class__name(tag__class(type)));
			else if (tag__is_union(type))
				fprintf(stdout, "\n\treturn *(union %s *)1;", type__name(tag__type(type)));
			else if (tag__is_typedef(type))
				fprintf(stdout, "\n\treturn *(%s *)1;", type__name(tag__type(type)));
			else
				fprintf(stdout, "\n\treturn 0;");
		}
		fprintf(stdout, "\n}\n");
	}
	putchar('\n');
	if (show_all_matches)
		return;
	if (show_variables || show_inline_expansions)
		function__fprintf_stats(tag, cu, &conf, stdout);

	if (!fstats)
		fstats = fn_stats__add(tag, cu);
	if (fstats)
		fstats->printed = true;
}

static int cu_function_iterator(struct cu *cu, void *cookie __maybe_unused)
{
	struct function *function;
	uint32_t id;

	cu__for_each_function(cu, id, function) {
		function__show(function, cu);
	}
	return 0;
}

static const char *btf_reg_name(uint32_t reg, const struct elf_register_names *regs,
				char *buf, size_t len)
{
	if (reg == BTF_LOC_PARAM_FBREG)
		return "fbreg";
	if (regs && reg < ARRAY_SIZE(regs->names) && regs->names[reg])
		return regs->names[reg];
	snprintf(buf, len, "reg%u", reg);
	return buf;
}

static bool btf_inline_site__fprintf_loc(const struct btf_type *type,
					 const struct btf_inline_site *site,
					 uint64_t object_addr_base,
					 const struct elf_register_names *regs, FILE *fp)
{
	const uint32_t *values = (const uint32_t *)(type + 1);
	uint32_t flags = *values++;
	uint64_t value;
	char regbuf[16];
	char regbuf2[16];
	const char *reg;

	if (flags & BTF_LOC_PARAM_CONST) {
		value = values[0];
		if (type->size > sizeof(values[0]))
			value |= (uint64_t)values[1] << 32;
		if (flags & BTF_LOC_PARAM_ADDR) {
			fputs("addr ", fp);
			if (object_addr_base != UINT64_MAX)
				fprintf(fp, "%#llx", (unsigned long long)(object_addr_base + value));
			else
				fprintf(fp, "%s+%#llx", site->section_name,
					(unsigned long long)value);
			return true;
		}
		fputs("const ", fp);
		if (flags & BTF_LOC_PARAM_SIGNED) {
			if (type->size && type->size < sizeof(value)) {
				unsigned int bits = type->size * 8;

				if (value & (1ULL << (bits - 1)))
					value |= ~0ULL << bits;
			}
			fprintf(fp, "%lld", (long long)value);
		} else
			fprintf(fp, "%#llx", (unsigned long long)value);
		return true;
	}
	if (!(flags & BTF_LOC_PARAM_REG))
		return false;
	reg = btf_reg_name(values[0], regs, regbuf, sizeof(regbuf));
	if (flags & BTF_LOC_PARAM_DEREF)
		fprintf(fp, "*(%s", reg);
	else
		fputs(reg, fp);
	if (flags & BTF_LOC_PARAM_OFFSET)
		fprintf(fp, "%+d", (int32_t)values[1]);
	else if (flags == BTF_LOC_PARAM_REG && btf_vlen(type) == 2)
		fprintf(fp, ", %s", btf_reg_name(values[1], regs, regbuf2, sizeof(regbuf2)));
	if (flags & BTF_LOC_PARAM_DEREF)
		fputc(')', fp);
	return true;
}

static void btf_inline_site__fprintf(const struct btf_inline_site *site,
				     const struct cu *cu,
				     const struct elf_symtab_ctx *elf_symtab,
				     const struct elf_register_names *regs,
				     const struct elf_functions *elf_functions,
				     const struct running_object_ctx *running, FILE *fp)
{
	const struct btf_type *proto;
	const uint32_t *param_ids;
	struct ftype *ftype;
	struct parameter *param;
	uint16_t i = 0;
	uint64_t section_addr = 0;
	uint64_t object_addr_base = UINT64_MAX;
	const struct elf_function *containing_function = NULL;

	if (!site->function)
		return;
	proto = btf__type_by_id(cu->priv, site->loc_proto);
	ftype = tag__ftype(cu__type(cu, site->function->proto.tag.type));
	if (!proto || btf_kind(proto) != BTF_KIND_LOC_PROTO || !ftype)
		return;
	param_ids = (const uint32_t *)(proto + 1);
	if (running) {
		section_addr = running_object__section_addr(running, site->section_name);
		if (section_addr)
			object_addr_base = running->addr_base;
	}
	if (elf_symtab) {
		GElf_Shdr shdr;
		size_t index;

		if (elf_section_by_name(elf_symtab->elf, &shdr, site->section_name, &index))
			section_addr = shdr.sh_addr;
		object_addr_base = elf__addr_base(elf_symtab->elf);
	}
	if (elf_functions && section_addr)
		containing_function = elf_functions__find(elf_functions,
							  section_addr + site->section_offset);
	/* Raw or detached BTF has no ELF section VMA; its LOCSEC offset is
	 * still useful and is the best address available in that case.
	 */
	fprintf(fp, "%#llx [",
		(unsigned long long)(section_addr ?
			 section_addr + site->section_offset : site->section_offset));
	if (containing_function)
		fprintf(fp, "%s+0x%llx, ", containing_function->name,
			(unsigned long long)(section_addr + site->section_offset -
					     containing_function->addr));
	fprintf(fp, "%s +%#x] %s(", site->section_name, site->section_offset,
		function__name(site->function));
	ftype__for_each_parameter(ftype, param) {
		struct tag *type = cu__type(cu, param->tag.type);
		const struct btf_type *location = NULL;
		char typebuf[128];

		if (i)
			fputs(", ", fp);
		fputs(tag__name(type, cu, typebuf, sizeof(typebuf), &conf), fp);
		if (!conf.no_parm_names && parameter__name(param))
			fprintf(fp, " %s", parameter__name(param));
		if (i < btf_vlen(proto))
			location = btf__type_by_id(cu->priv, param_ids[i]);
		fputs(" [", fp);
		if (!location || btf_kind(location) != BTF_KIND_LOC_PARAM ||
		    !btf_inline_site__fprintf_loc(location, site, object_addr_base,
						 regs, fp))
			fputs("unavailable", fp);
		fputc(']', fp);
		++i;
	}
	if (i == 0)
		fputs("void", fp);
	fputs(")\n", fp);
}

struct btf_inline_sites {
	const struct elf_symtab_ctx *elf_symtab;
	const struct elf_register_names *regs;
	const struct elf_functions  *elf_functions;
	const struct running_object_ctx *running;
};

static int cu_btf_inline_sites_iterator(struct cu *cu, void *cookie)
{
	struct btf_inline_site *site;
	const struct btf_inline_sites *inline_sites = cookie;

	list_for_each_entry(site, &cu->btf_inline_sites, node)
		if (!function_name ||
		    strcmp(function__name(site->function), function_name) == 0)
			btf_inline_site__fprintf(site, cu, inline_sites->elf_symtab,
						 inline_sites->regs,
						 inline_sites->elf_functions, inline_sites->running,
						 stdout);
	return 0;
}

static int elf_symtab__show(char *filename)
{
	struct elf_symtab_ctx ctx;
	struct elf_symtab *symtab;
	int err = -1;

	if (elf_symtab__init(&ctx, filename) || !ctx.symtab) {
		elf_symtab__exit(&ctx);
		return -1;
	}
	symtab = ctx.symtab;

	GElf_Sym sym;
	uint32_t index;
	int longest_name = 0;
	elf_symtab__for_each_symbol(symtab, index, sym) {
		if (!elf_sym__is_local_function(&sym))
			continue;
		int len = strlen(elf_sym__name(&sym, symtab));
		if (len > longest_name)
			longest_name = len;
	}

	if (longest_name > 32)
		longest_name = 32;

	int index_spacing = 0;
	int nr = elf_symtab__nr_symbols(symtab);
	while (nr) {
		++index_spacing;
		nr /= 10;
	}

	elf_symtab__for_each_symbol(symtab, index, sym) {
		if (!elf_sym__is_local_function(&sym))
			continue;
		printf("%*d: %-*s %#llx %5u\n",
		       index_spacing, index, longest_name,
		       elf_sym__name(&sym, symtab),
		       (unsigned long long)elf_sym__value(&sym),
		       elf_sym__size(&sym));
	}

	err = 0;
	elf_symtab__exit(&ctx);
	return err;
}

static int elf_symtabs__show(char *filenames[])
{
	int i = 0;

	while (filenames[i] != NULL) {
		if (elf_symtab__show(filenames[i]))
			return EXIT_FAILURE;
		++i;
	}

	return EXIT_SUCCESS;
}

static enum load_steal_kind pfunct_stealer(struct cu *cu,
					   struct conf_load *conf_load __maybe_unused)
{

	if (function_name) {
		struct tag *tag = cu__find_function_by_name(cu, function_name);

		if (tag) {
			function__show(tag__function(tag), cu);
			return show_all_matches ? LSK__DELETE : LSK__STOP_LOADING;
		}
	} else if (class_name) {
		cu_class_iterator(cu, class_name);
	} else if (show_all_matches) {
		struct function *pos;
		uint32_t id;

		cu__for_each_function(cu, id, pos)
			function__show(pos, cu);
	}


	return LSK__DELETE;
}

static struct cu *cu__filter(struct cu *cu)
{
	return languages__cu_filtered(&languages, cu, verbose) ? NULL : cu;
}

/* Name and version of program.  */
ARGP_PROGRAM_VERSION_HOOK_DEF = dwarves_print_version;

#define ARGP_symtab		300
#define ARGP_no_parm_names	301
#define ARGP_compile		302
#define ARGP_devel_version	303
#define ARGP_btf_base		304
#define ARGP_elf		305
#define ARGP_running		306

static const struct argp_option pfunct__options[] = {
	{
		.key  = 'a',
		.name = "addr",
		.arg  = "ADDR",
		.doc  = "show just the function that where ADDR is",
	},
	{
		.key  = 'A',
		.name = "all",
		.doc  = "show all functions that match filter, or show all function prototypes if no filter is specified",
	},
	{
		.key  = 'b',
		.name = "expand_types",
		.doc  = "Expand types needed by the prototype",
	},
	{
		.key  = 'c',
		.name = "class",
		.arg  = "CLASS",
		.doc  = "functions that have CLASS pointer parameters",
	},
	{
		.key  = 'E',
		.name = "externals",
		.doc  = "show just external functions",
	},
	{
		.key  = 'f',
		.name = "function",
		.arg  = "FUNCTION",
		.doc  = "show just FUNCTION",
	},
	{
		.name = "format_path",
		.key  = 'F',
		.arg  = "FORMAT_LIST",
		.doc  = "List of debugging formats to try"
	},
	{
		.name = "btf_base",
		.key  = ARGP_btf_base,
		.arg  = "PATH",
		.doc  = "Path to the base BTF file for split BTF input",
	},
	{
		.name = "elf",
		.key  = ARGP_elf,
		.arg  = "PATH",
		.doc  = "ELF file used to resolve BTF inline-site addresses and containers",
	},
	{
		.name  = "running",
		.key   = ARGP_running,
		.arg   = "OBJECT",
		.flags = OPTION_ARG_OPTIONAL,
		.doc   = "Resolve inline sites against running vmlinux or module OBJECT (Default vmlinux)",
	},
	{
		.key  = 'g',
		.name = "goto_labels",
		.doc  = "show number of goto labels",
	},
	{
		.key  = 'G',
		.name = "cc_uninlined",
		.doc  = "declared inline, uninlined by compiler",
	},
	{
		.key  = 'H',
		.name = "cc_inlined",
		.doc  = "not declared inline, inlined by compiler",
	},
	{
		.key  = 'i',
		.name = "inline_expansions",
		.doc  = "show inline expansions",
	},
	{
		.key  = 'j',
		.name = "inline_sites",
		.doc  = "show BTF inline sites and parameter locations",
	},
	{
		.key  = 'I',
		.name = "inline_expansions_stats",
		.doc  = "show inline expansions stats",
	},
	{
		.key  = 'l',
		.name = "decl_info",
		.doc  = "show source code info",
	},
	{
		.key  = 't',
		.name = "total_inline_stats",
		.doc  = "show Multi-CU total inline expansions stats",
	},
	{
		.key  = 's',
		.name = "sizes",
		.doc  = "show size of functions",
	},
	{
		.key  = 'N',
		.name = "function_name_len",
		.doc  = "show size of functions names",
	},
	{
		.key  = 'p',
		.name = "nr_parms",
		.doc  = "show number of parameters",
	},
	{
		.key  = 'P',
		.name = "prototypes",
		.doc  = "show function prototypes",
	},
	{
		.key  = 'S',
		.name = "nr_variables",
		.doc  = "show number of variables",
	},
	{
		.key  = 'T',
		.name = "variables",
		.doc  = "show variables",
	},
	{
		.key  = 'V',
		.name = "verbose",
		.doc  = "be verbose",
	},
	{
		.name  = "symtab",
		.key   = ARGP_symtab,
		.arg   = "NAME",
		.flags = OPTION_ARG_OPTIONAL,
		.doc   = "show symbol table NAME (Default .symtab)",
	},
	{
		.name  = "compile",
		.key   = ARGP_compile,
		.arg   = "FUNCTION",
		.flags = OPTION_ARG_OPTIONAL,
		.doc   = "Generate compilable source code with types expanded (Default all functions)",
	},
	{
		.name  = "no_parm_names",
		.key   = ARGP_no_parm_names,
		.doc   = "Don't show parameter names",
	},
	{
		.name = "devel_version",
		.key  = ARGP_devel_version,
		.doc  = "Print development version with git SHA (e.g., v1.31-189-g437fced33da3393e)",
	},
	{
		.name = NULL,
	}
};

static void (*formatter)(const struct fn_stats *f) = fn_stats_fmtr;
static int show_total_inline_expansion_stats;

static error_t pfunct__options_parser(int key, char *arg,
				      struct argp_state *state)
{
	switch (key) {
	case ARGP_KEY_INIT:
		if (state->child_inputs != NULL)
			state->child_inputs[0] = state->input;
		break;
	case 'a': addr = strtoull(arg, NULL, 0);
		  conf_load.get_addr_info = true;	 break;
	case 'A': show_all_matches = true;		 break;
	case 'b': expand_types = true;
		  type_emissions__init(&emissions, &conf);	 break;
	case 'c': class_name = arg;			 break;
	case 'f': function_name = arg;			 break;
	case 'F': conf_load.format_path = arg;		 break;
	case 'E': show_externals = 1;			 break;
	case 's': formatter = fn_stats_size_fmtr;
		  conf_load.get_addr_info = true;	 break;
	case 'S': formatter = fn_stats_variables_fmtr;	 break;
	case 'p': formatter = fn_stats_nr_parms_fmtr;	 break;
	case 'P': show_prototypes = true;		 break;
	case 'g': formatter = fn_stats_labels_fmtr;	 break;
	case 'G': show_cc_uninlined = 1;		 break;
	case 'H': show_cc_inlined = 1;			 break;
	case 'i': show_inline_expansions = verbose = 1;
		  conf_load.extra_dbg_info = true;
		  conf_load.get_addr_info = true;	 break;
	case 'j': show_inline_sites = true;
		  if (conf_load.format_path == NULL)
			  conf_load.format_path = "btf";
		  break;
	case 'I': formatter = fn_stats_inline_exps_fmtr;
		  conf_load.get_addr_info = true;	 break;
	case 'l': conf.show_decl_info = 1;
		  conf_load.extra_dbg_info = 1;		 break;
	case 't': show_total_inline_expansion_stats = true;
		  conf_load.get_addr_info = true;	 break;
	case 'T': show_variables = 1;			 break;
	case 'N': formatter = fn_stats_name_len_fmtr;	 break;
	case 'V': verbose = 1;
		  conf_load.extra_dbg_info = true;
		  conf_load.get_addr_info = true;	 break;
	case ARGP_symtab: symtab_name = arg ?: ".symtab";  break;
	case ARGP_btf_base: base_btf_file = arg;             break;
	case ARGP_elf: elf_filename = arg;                   break;
	case ARGP_running: running_object = arg ?: "vmlinux"; break;
	case ARGP_no_parm_names: conf.no_parm_names = 1; break;
	case ARGP_compile:
		  expand_types = true;
		  type_emissions__init(&emissions, &conf);
		  compilable_output = true;
		  conf.no_semicolon = true;
		  conf.strip_inline = true;
		  if (arg)
			  function_name = arg;
		  break;
	case ARGP_devel_version:
		  dwarves_print_devel_version(stdout, state);
		  exit(0);
	default:  return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static const char pfunct__args_doc[] = "FILE";

static struct argp pfunct__argp = {
	.options  = pfunct__options,
	.parser	  = pfunct__options_parser,
	.args_doc = pfunct__args_doc,
};

int main(int argc, char *argv[])
{
	int err, remaining, rc = EXIT_FAILURE;
	struct elf_symtab_ctx elf_symtab;
	struct elf_functions elf_functions = {};
	struct btf_inline_sites inline_sites = {};
	struct running_object_ctx running = {};
	bool have_inline_elf = false;
	bool have_running = false;

	if (argp_parse(&pfunct__argp, argc, argv, 0, &remaining, NULL) ||
	    (remaining == argc && class_name == NULL && function_name == NULL)) {
                argp_help(&pfunct__argp, stderr, ARGP_HELP_SEE, argv[0]);
                goto out;
	}

	if (languages__init(&languages, argv[0]))
		return rc;

	if (languages.exclude)
		conf_load.early_cu_filter = cu__filter;

	if (symtab_name != NULL)
		return elf_symtabs__show(argv + remaining);

	if (dwarves__init()) {
		fputs("pfunct: insufficient memory\n", stderr);
		goto out;
	}
	if (running_object && (elf_filename || !show_inline_sites)) {
		fputs("pfunct: --running is only supported with --inline_sites and without --elf\n",
		      stderr);
		goto out_dwarves_exit;
	}

	dwarves__resolve_cacheline_size(&conf_load, 0);

	/* Kernel module BTF in sysfs is split against vmlinux BTF. */
	if (base_btf_file == NULL) {
		const char *filename = argv[remaining];

		if (filename && strstarts(filename, "/sys/kernel/btf/") &&
		    strcmp(filename, vmlinux_path__btf_filename()) != 0)
			base_btf_file = vmlinux_path__btf_filename();
	}

	if (base_btf_file) {
		conf_load.base_btf = btf__parse(base_btf_file, NULL);
		if (libbpf_get_error(conf_load.base_btf)) {
			fprintf(stderr, "pfunct: Failed to parse base BTF '%s': %ld\n",
				base_btf_file, libbpf_get_error(conf_load.base_btf));
			goto out_dwarves_exit;
		}

		/* A base BTF is meaningful only when loading BTF input. */
		if (conf_load.format_path == NULL)
			conf_load.format_path = "btf";
	}

	struct cus *cus = cus__new();
	if (cus == NULL) {
		fputs("pfunct: insufficient memory\n", stderr);
		goto out_dwarves_exit;
	}

	if ((function_name && !show_inline_sites) ||
	    (!function_name && show_all_matches) || class_name)
		conf_load.steal = pfunct_stealer;

try_sole_arg_as_function_name:
	err = cus__load_files(cus, &conf_load, argv + remaining);
	if (err != 0) {
		if (function_name == NULL) {
                        function_name = argv[remaining];
                        if (access(function_name, R_OK) == 0) {
                                fprintf(stderr, "pfunct: file '%s' has no %s type information.\n",
                                                function_name, conf_load.format_path ?: "supported");
                                goto out_dwarves_exit;
                        }
			conf_load.steal = pfunct_stealer;
                        remaining = argc;
			goto try_sole_arg_as_function_name;
		}
		cus__fprintf_load_files_err(cus, "pfunct", argv + remaining, err, stderr);
		goto out_cus_delete;
	}


	bool is_btf = conf_load.format_path && strcasecmp(conf_load.format_path, "btf") == 0;
	cus__for_each_cu(cus, cu_unique_iterator, is_btf ? (void *)1 : NULL, NULL);
	if (running_object) {
		if (running_object__init(&running, running_object)) {
			fprintf(stderr, "pfunct: cannot resolve running object '%s'\n", running_object);
			goto out_elf_symtab_exit;
		}
		have_running = true;
		inline_sites.running = &running;
		inline_sites.regs = &running.regs;
		inline_sites.elf_functions = &running.functions;
	} else if (show_inline_sites && (elf_filename || argv[remaining])) {
		const char *inline_elf_filename = elf_filename ?: argv[remaining];

		if (elf_symtab__init(&elf_symtab, inline_elf_filename)) {
			if (!elf_filename)
				goto no_inline_elf;
			elf_functions__exit(&elf_functions);
			elf_symtab__exit(&elf_symtab);
			goto out_cus_delete;
		}
		have_inline_elf = true;
		if (elf_symtab.symtab &&
		    elf_functions__collect(&elf_functions, elf_symtab.symtab)) {
			elf_functions__exit(&elf_functions);
			elf_symtab__exit(&elf_symtab);
			goto out_cus_delete;
		}
		inline_sites.elf_symtab = &elf_symtab;
		inline_sites.regs = &elf_symtab.regs;
		inline_sites.elf_functions = &elf_functions;
	}
no_inline_elf:

	if (addr) {
		struct cu *cu;
		struct function *f = cus__find_function_at_addr(cus, addr, &cu);

		if (f == NULL) {
			fprintf(stderr, "pfunct: No function found at %#llx!\n",
				(unsigned long long)addr);
			goto out_elf_symtab_exit;
		}
		function__show(f, cu);
	} else if (show_total_inline_expansion_stats)
		print_total_inline_stats();
	else if (show_inline_sites)
		cus__for_each_cu(cus, cu_btf_inline_sites_iterator, &inline_sites, NULL);
	else if (expand_types)
		cus__for_each_cu(cus, cu_function_iterator, NULL, NULL);
	else if (function_name == NULL)
		print_fn_stats(formatter);

	rc = EXIT_SUCCESS;
out_elf_symtab_exit:
	if (have_running)
		running_object__exit(&running);
	if (have_inline_elf) {
		elf_functions__exit(&elf_functions);
		elf_symtab__exit(&elf_symtab);
	}
out_cus_delete:
	cus__delete(cus);
	fn_stats__delete_list();
out_dwarves_exit:
	btf__free(conf_load.base_btf);
	conf_load.base_btf = NULL;
	dwarves__exit();
out:
	return rc;
}
