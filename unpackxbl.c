// SPDX-License-Identifier: MIT
// clang-format off
/*
 * Copyright 2023 Linaro Ltd.
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 *
 * This program extracts the sbl1.elf, XBL_Core.elf, and xbl_sec.mbn
 * binaries from a packed XBL image. The XBL_Core.elf binary has its own ELF header
 * merged into the XBL.elf image when producing the final xbl.mbn.
 *
 * Example XBL image layout (SDM845):
 *
 * Elf file type is EXEC (Executable file)
 * Entry point 0x148492b8
 * There are 16 program headers, starting at offset 64
 *
 * Program Headers:
 *   Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
 *   NULL           0x000000 0x0000000000000000 0x0000000000000000 0x0003c0 0x000000     0
 *   NULL           0x001000 0x000000009fe00000 0x000000009fe00000 0x001b28 0x002000     0x1000
 *   LOAD           0x003000 0x000000001483f000 0x000000001483f000 0x04d7e0 0x04d7e0 R E 0x1000
 *   LOAD           0x0507e0 0x000000001488f000 0x000000001488f000 0x000000 0x003000 RW  0x1000
 *   LOAD           0x0507e0 0x0000000014892000 0x0000000014892000 0x00cb86 0x00cb86 RW  0x1000
 *   LOAD           0x05d370 0x000000001489f000 0x000000001489f000 0x000000 0x018c00 RW  0x1000
 *   LOAD           0x05d370 0x0000000085e00000 0x0000000085e00000 0x000000 0x027ba0 RW  0x1000
 *   LOAD           0x05d370 0x00000000146ae000 0x00000000146ae000 0x001380 0x001380 R E 0x1000
 *   LOAD           0x05e6f0 0x00000000146b1000 0x00000000146b1000 0x000844 0x000844 RW  0x1000
 *   LOAD           0x05ef40 0x00000000148bf000 0x00000000148bf000 0x0218c0 0x0218c0 RWE 0x1000 <-- XBLRamdump (probably??) 
 *   LOAD           0x080800 0x00000000146b2000 0x00000000146b2000 0x000000 0x002d34 RW  0x1000
 *   LOAD           0x080800 0x000000009fc00000 0x000000009fc00000 0x200000 0x200000 RWE 0x1000 <-- xbl_core.elf (ELF header stripped) 
 *   LOAD           0x280800 0x0000000014699000 0x0000000014699000 0x013b25 0x013b25 R E 0x1000 <-- xbl_sec.mbn (includes ELF header)
 *   LOAD           0x294330 0x0000000085e35000 0x0000000085e35000 0x042b1b 0x042b1b R E 0x1000
 *   LOAD           0x2d6e50 0x0000000085ea7000 0x0000000085ea7000 0x04b800 0x04b804 RW  0x1000
 *   LOAD           0x322650 0x0000000085e97000 0x0000000085e97000 0x000000 0x001dd0 RW  0x1000
 */
// clang-format on

#include <elf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BIT(x) (1 << (x))

#define XBL_SEC_FLAGS (BIT(24) | BIT(26))

/*
 * On at least SDM845 and QRB4210, the lowest 28 bits of
 * the address are the same. So for now use this heuristic
 * to detect it.
 */
#define XBL_CORE_ADDR_MATCH 0xfc00000

static bool verbose = false;
static void *sbl1 = NULL;
static uint64_t sbl1_offset = 0;
static size_t sbl1_size = 4096;
// static Elf64_Ehdr xblldr_ehdr;

#define log(...)                                      \
	do {                                          \
		if (verbose)                          \
			fprintf(stderr, __VA_ARGS__); \
	} while (0)

static int usage()
{
	// clang-format off
	fprintf(stderr, "unpackxbl: extract sbl1.elf, XBL_Core.elf, and xbl_sec.mbn\n");
	fprintf(stderr, "-------------------------------------------\n");
	fprintf(stderr, "unpackxbl [-v] [-o OUTDIR] /path/to/xbl.elf\n");
	fprintf(stderr, "    -v           enable verbose logging\n");
	// clang-format on

	return 1;
}

static void init_header(void *buf, uint64_t addr)
{
	Elf64_Ehdr ehdr = {
		.e_ident = {
			[EI_CLASS] = ELFCLASS64,
			[EI_DATA] = ELFDATA2LSB,
			[EI_VERSION] = EV_CURRENT,
			[EI_OSABI] = ELFOSABI_NONE,
		},
		.e_type = ET_EXEC,
		.e_machine = EM_AARCH64,
		.e_version = EV_CURRENT,
		.e_entry = addr,
		.e_phoff = sizeof(ehdr),
		.e_shoff = 0,
		.e_flags = 0,
		.e_ehsize = sizeof(ehdr),
		.e_phentsize = sizeof(Elf64_Phdr),
		.e_phnum = 1,
		.e_shentsize = 0,
		.e_shnum = 0,
		.e_shstrndx = 0,
	};

	/* Copy in the ELF magic */
	memcpy(ehdr.e_ident, ELFMAG, SELFMAG);

	memcpy(buf, &ehdr, sizeof(ehdr));
}

static void init_phdr(void *buf, uint64_t addr, size_t size)
{
	Elf64_Phdr phdr = {
		.p_type = PT_LOAD,
		/* Yes we need the write attribute too */
		.p_flags = PF_R | PF_X | PF_W,
		.p_offset = sizeof(Elf64_Ehdr) + sizeof(phdr),
		.p_vaddr = addr,
		.p_paddr = addr,
		.p_filesz = size,
		.p_memsz = size,
		.p_align = 0x1000,
	};

	memcpy(buf, &phdr, sizeof(phdr));
}

/* Create a new ELF header with a single program header and write it out */
static int write_part(FILE *out, uint64_t addr, void *buf, size_t size)
{
	Elf64_Ehdr ehdr = { 0 };
	Elf64_Phdr phdr = { 0 };

	init_header(&ehdr, addr);

	init_phdr(&phdr, addr, size);

	if (fwrite(&ehdr, sizeof(ehdr), 1, out) != 1) {
		fprintf(stderr, "Failed to write ELF header\n");
		return -1;
	}

	if (fwrite(&phdr, sizeof(phdr), 1, out) != 1) {
		fprintf(stderr, "Failed to write program header\n");
		return -1;
	}

	if (fwrite(buf, size, 1, out) != 1) {
		fprintf(stderr, "Failed to write %lu bytes\n", size);
		return -1;
	}

	fflush(out);

	return 0;
}

static int unpack_xbl(FILE *xbl)
{
	Elf64_Ehdr ehdr;
	int n_phdrs = 0;
	Elf64_Phdr xbl_core_phdr = { 0 };
	Elf64_Phdr xbl_sec_phdr = { 0 };

	if (fread(&ehdr, sizeof(ehdr), 1, xbl) != 1) {
		fprintf(stderr, "Failed to read ELF header\n");
		return 1;
	}

	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
		fprintf(stderr, "Invalid ELF magic\n");
		return 1;
	}

	if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "Only 64-bit ELF supported\n");
		return 1;
	}

	if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
		fprintf(stderr, "Only little endian ELF supported\n");
		return 1;
	}

	/* Initially allocate space for the header, we'll grow this on demand */
	sbl1 = malloc(sbl1_size);
	init_header(sbl1, ehdr.e_entry);
	sbl1_offset += sizeof(Elf64_Ehdr);

	/* Iterate through the program headers, skip the hash segments, XBL_Core and XBLSec */
	for (int i = 0; i < ehdr.e_phnum; i++) {
		Elf64_Phdr phdr;

		if (fseek(xbl, ehdr.e_phoff + (i * sizeof(phdr)), SEEK_SET) != 0) {
			fprintf(stderr, "Failed to seek to program header %d\n", i);
			return 1;
		}

		if (fread(&phdr, sizeof(phdr), 1, xbl) != 1) {
			fprintf(stderr, "Failed to read program header %d\n", i);
			return 1;
		}

		log("%d: type=%d offset=%#8lx vaddr=%#18lx paddr=%#18lx filesz=%#8lx memsz=0x%lx flags=0x%x align=%#06lx\n",
		    i, phdr.p_type, phdr.p_offset, phdr.p_vaddr, phdr.p_paddr, phdr.p_filesz,
		    phdr.p_memsz, phdr.p_flags, phdr.p_align);

		/* Skip non-loadable segments */
		if (phdr.p_type != PT_LOAD)
			continue;

		/* Skip XBL_Core and XBLSec */
		if ((phdr.p_paddr & 0xFFFFFFF) == XBL_CORE_ADDR_MATCH) {
			memcpy(&xbl_core_phdr, &phdr, sizeof(phdr));
			continue;
		}

		if ((phdr.p_flags & XBL_SEC_FLAGS) == XBL_SEC_FLAGS) {
			memcpy(&xbl_sec_phdr, &phdr, sizeof(phdr));
			continue;
		}

		/* Copy the program header to the sbl1 buffer */
		memcpy(sbl1 + sbl1_offset, &phdr, sizeof(phdr));
		sbl1_offset += sizeof(phdr);
		n_phdrs++;
	}

	if (!xbl_core_phdr.p_paddr) {
		fprintf(stderr, "Failed to find XBL_Core program header\n");
		return -1;
	}

	if (!xbl_sec_phdr.p_paddr) {
		fprintf(stderr, "Failed to find XBLSec program header\n");
		return -1;
	}

	/* Set the number of program headers */
	((Elf64_Ehdr *)sbl1)->e_phnum = n_phdrs;

	/* We have now figured out which program headers are for which of the three images. XBL_Core.elf
	 * is always made up of a single image (one program header), same for xbl_sec.mbn. And all the rest
	 * are what make up sbl1.elf.
	 * So at this point, we walk through all the program headers which we know are for sbl1.elf
	 * and write their associated data to the buffer.
	 */
	for (int i = 0; i < n_phdrs; i++) {
		Elf64_Phdr *phdr =
			(Elf64_Phdr *)(sbl1 + sizeof(Elf64_Ehdr) + (i * sizeof(Elf64_Phdr)));

		if (fseek(xbl, phdr->p_offset, SEEK_SET) != 0) {
			fprintf(stderr, "Failed to seek to offset 0x%lx\n", phdr->p_offset);
			return -1;
		}

		/* Grow the buffer if needed */
		if (sbl1_offset + phdr->p_filesz > sbl1_size) {
			sbl1 = realloc(sbl1, sbl1_offset + phdr->p_filesz);
			if (!sbl1) {
				fprintf(stderr, "Failed to allocate %lu bytes\n",
					sbl1_offset + phdr->p_filesz);
				return -1;
			}

			/* FIXME: Don't forget to update the pointer :sob: */
			phdr = (Elf64_Phdr *)(sbl1 + sizeof(Elf64_Ehdr) +
					      (i * sizeof(Elf64_Phdr)));
		}

		/* Update p_offset to point to the right file offset */
		phdr->p_offset = sbl1_offset;

		/* Some empty program headers are just used to reserve RAM, now that we've
		 * updated the offset, we can skip them.
		 */
		if (!phdr->p_filesz)
			continue;

		/* Read the data into the buffer */
		if (fread(sbl1 + sbl1_offset, phdr->p_filesz, 1, xbl) != 1) {
			fprintf(stderr, "Failed to read %lu bytes (phdr vaddr %#012lx)\n",
				phdr->p_filesz, phdr->p_vaddr);
			return -1;
		}
		sbl1_offset += phdr->p_filesz;
	}

	/* Write out the sbl1 binary */
	FILE *out = fopen("sbl1.elf", "wb");
	if (!out) {
		fprintf(stderr, "Failed to open sbl1.elf for writing\n");
		return -1;
	}

	if (fwrite(sbl1, sbl1_offset, 1, out) != 1) {
		fprintf(stderr, "Failed to write sbl1.elf\n");
		return -1;
	}

	fflush(out);
	fclose(out);

	/* Write out the XBL_Core binary */
	out = fopen("xbl_core.elf", "wb");
	if (!out) {
		fprintf(stderr, "Failed to open XBL_Core.elf for writing\n");
		return -1;
	}

	void *buf = malloc(xbl_core_phdr.p_filesz);

	if (fseek(xbl, xbl_core_phdr.p_offset, SEEK_SET) != 0) {
		fprintf(stderr, "Failed to seek to offset 0x%lx\n", xbl_core_phdr.p_offset);
		return -1;
	}

	if (fread(buf, xbl_core_phdr.p_filesz, 1, xbl) != 1) {
		fprintf(stderr, "Failed to read %lu bytes\n", xbl_core_phdr.p_filesz);
		return -1;
	}

	write_part(out, xbl_core_phdr.p_paddr, buf, xbl_core_phdr.p_filesz);

	fclose(out);

	/*
	 * Write out the xbl_sec.mbn blob (it contains it's own embedded ELF header so we don't need
	 * to add one).
	 */
	out = fopen("xbl_sec.mbn", "wb");
	if (!out) {
		fprintf(stderr, "Failed to open xbl_sec.mbn for writing\n");
		return -1;
	}

	buf = malloc(xbl_sec_phdr.p_filesz);

	if (fseek(xbl, xbl_sec_phdr.p_offset, SEEK_SET) != 0) {
		fprintf(stderr, "Failed to seek to offset 0x%lx\n", xbl_sec_phdr.p_offset);
		return -1;
	}

	if (fread(buf, xbl_sec_phdr.p_filesz, 1, xbl) != 1) {
		fprintf(stderr, "Failed to read %lu bytes\n", xbl_sec_phdr.p_filesz);
		return -1;
	}

	fwrite(buf, xbl_sec_phdr.p_filesz, 1, out);

	fflush(out);
	fclose(out);

	return 0;
}

int main(int argc, char **argv)
{
	int optflag, ret;
	char *xbl_path = NULL;

	if (argc < 2)
		return usage();

	while ((optflag = getopt(argc, argv, "v")) != -1) {
		switch (optflag) {
		case 'v':
			verbose = true;
			break;
		default:
			return usage();
		}
	}

	xbl_path = argv[optind];
	if (!xbl_path)
		return usage();

	FILE *xbl = fopen(xbl_path, "rb");
	if (!xbl) {
		fprintf(stderr, "Failed to open %s\n", xbl_path);
		return 1;
	}

	ret = unpack_xbl(xbl);
	printf("\nAll done!\n");

	return ret;
}
