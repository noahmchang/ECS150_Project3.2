#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "disk.h"
#include "fs.h"

#define FS_SIGNATURE "ECS150FS"
#define FS_BLOCK_SIZE 4096

#pragma pack(push, 1)
struct superblock {
	//from superblock table in prompt
    uint8_t signature[8];
    uint16_t total_blocks;
    uint16_t root_index;
    uint16_t data_index;
    uint16_t data_blocks;
    uint8_t fat_blocks;
    uint8_t padding[4079];
};
#pragma pack(pop)

struct root_directory {
	char filename[FS_FILENAME_LEN]; //16 byte
	uint32_t size; //4 byte
	uint16_t first_data_index; //2 byte
	uint8_t padding[10]; //10 byte
};

// Struct for open files (entry for file table)
struct open_file {
	int fd;
	uint32_t offset; //read/wrtie offset for fd
	struct root_directory *rd_metadata; // point to the rd entry to access metadata
	bool in_use; //tbale entry is currently being used
}

static bool is_mounted = false;
static struct superblock sb;
static uint16_t *fat = NULL;
static struct root_directory root[FS_FILE_MAX_COUNT];
static struct open_file opened_files[FS_OPEN_MAX_COUNT]; //all open files

int fs_mount(const char *diskname) //NOTE: for all functions, return -1 if failure
{
	if (is_mounted) {
		return -1;
	}
	
    if (block_disk_open(diskname) < 0) {
		return -1;
	}
	if (block_read(0, &sb) < 0) { //read superblock
		block_disk_close();
		return -1;
	}
	//INTIALIZE
	if (memcmp(sb.signature, FS_SIGNATURE, 8) != 0) {
		block_disk_close();
		return -1;
	}
	if ((uint16_t)block_disk_count() != sb.total_blocks) {
		block_disk_close();
		return -1;
	}
	//FAT
	size_t fat_entry_count = sb.fat_blocks * FS_BLOCK_SIZE / sizeof(uint16_t);
	fat = malloc(fat_entry_count * sizeof(uint16_t));
	if (fat == NULL) {
		block_disk_close();
		return -1;
	}

	for (uint16_t i = 0; i < sb.fat_blocks; i++) {
		if (block_read(1 + i, (uint8_t *)fat + (i * FS_BLOCK_SIZE)) < 0) {  //read fat blocks
			free(fat);
			block_disk_close();
			return -1;
		}
	}
	if (block_read(sb.root_index, root) < 0) { //read root index
		free(fat);
		block_disk_close();
		return -1;
	}

	is_mounted = true;
	return 0;
}

int fs_umount(void)
{
	if (!is_mounted || block_disk_close() < 0) { //call close virtual disk file
		return -1;
	}
	free(fat);
	fat = NULL;
	is_mounted = false;
	return 0;
}

int fs_info(void)
{
	if (!is_mounted) {
		return -1;
	}

	size_t free_fat = 0;
	for (uint32_t i = 0; i < sb.data_blocks; i++) {
		if (fat[i] == 0) { //free fat directory found
			free_fat++;
		}
	}
	size_t free_rdir = 0;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (root[i].filename[0] == '\0') { //free root directory found
			free_rdir++;
		}
	}
	printf("FS Info:\n");
    printf("total_blk_count=%u\n", sb.total_blocks);
    printf("fat_blk_count=%u\n", sb.fat_blocks);
    printf("rdir_blk=%u\n", sb.root_index);
    printf("data_blk=%u\n", sb.data_index);
    printf("data_blk_count=%u\n", sb.data_blocks);
	printf("fat_free_ratio=%zu/%u\n", free_fat, sb.data_blocks);
	printf("rdir_free_ratio=%zu/%d\n", free_rdir, FS_FILE_MAX_COUNT);
	return 0;
}

int fs_create(const char *filename)
{
	/* TODO: Phase 2 */
}

int fs_delete(const char *filename)
{
	/* TODO: Phase 2 */
}

int fs_ls(void)
{
	/* TODO: Phase 2 */
}

int fs_open(const char *filename)
{
	// not mounted
	if (is_mounted) {
		return -1;
	}
	// invalid filename = null, empty, too long
	if (filename == NULL || strlen(filename) == 0 || strlen(filename >= FS_FILENAME_LEN)){
		return -1; 
	}
	//FS_OPEN_MAX_COUNT already opened
	int num_open = 0;
	for (int i = 0; i < FS_OPEN_MAX_COUNT; i++){
		if (of[1] in_use) {
			num_open++;
		}
	}
	if ( num_open > = FS_OPEN_MAX_COUNT){
		return -1;
	}

	

	return 0;
}

int fs_close(int fd)
{
	// not mounted
	if (is_mounted) {
		return -1;
	}

	// invalid fd
	// out of bounds
	
	// not currently open
}

int fs_stat(int fd)
{
	/* TODO: Phase 3 */
}

int fs_lseek(int fd, size_t offset)
{
	/* TODO: Phase 3 */
}

int fs_write(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
}

int fs_read(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
}
