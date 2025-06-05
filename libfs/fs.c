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
#define FAT_EOC 0xFFFF

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
	uint32_t offset; //read/wrtie offset for fd
	struct root_directory *root_dir; // point to the rd entry to access metadata
	bool in_use; //tbale entry is currently being used
};

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

	//initialize opened_files file table
	for (int i = 0; i < FS_OPEN_MAX_COUNT; i++){
		opened_files[i].offset = 0;
		opened_files[i].in_use = false;
		opened_files[i].root_dir = NULL;
	}

	is_mounted = true;
	return 0;
}

int fs_umount(void)
{
	if (!is_mounted) {
		return -1;
	}

	//for phase 2, write fat block to disk
	for (uint16_t i = 0; i < sb.fat_blocks; i++) {
        if (block_write(1 + i, (uint8_t *)fat + (i * FS_BLOCK_SIZE)) < 0) {
            return -1;
        }
    }
	block_write(sb.root_index, root); //write root back to disk

	block_disk_close(); //call close virtual disk file
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
	if (!is_mounted || filename == NULL) {
		return -1;
	}
	int name_len = strlen(filename);
	if (name_len == 0 || name_len > FS_FILENAME_LEN - 1) {
		return -1;
	}

	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) { //look for duplicate file name first
		if (strncmp(root[i].filename, filename, FS_FILENAME_LEN) == 0) {
			return -1;
		}
	}
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) { //create file in empty root dir index

		if (root[i].filename[0] == '\0') {
			root[i].size = 0;
			root[i].first_data_index = FAT_EOC;
			strcpy(root[i].filename, filename);
			block_write(sb.root_index, root);
			return 0;
		}
	}
	return -1;
}

int fs_delete(const char *filename)
{
	if (!is_mounted || filename == NULL) {
		return -1;
	}

	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (strncmp(root[i].filename, filename, FS_FILENAME_LEN) == 0) {
			uint16_t current_block = root[i].first_data_index;
			uint16_t next_block;
			while (current_block != FAT_EOC) { //free all data blocks in fat
				next_block = fat[current_block];
				fat[current_block] = 0;
				current_block = next_block;
			}
			//clear root dir entry
			memset(root[i].filename, 0, FS_FILENAME_LEN);
			root[i].size = 0;
			root[i].first_data_index = 0;
			for (int j = 0; j < sb.fat_blocks; j++) { //send updated fat to disk
				int result = block_write(1 + j, (uint8_t *)fat + j * FS_BLOCK_SIZE);
				if (result < 0) {
					return -1;
				} else {
					continue;
				}
			}
			block_write(sb.root_index, root); //send updated root dir to disk
			return 0;
		}
	}
	return -1;
}

int fs_ls(void)
{
	if (!is_mounted) {
		return -1;
	}
	printf("FS Ls:\n");
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (root[i].filename[0] != '\0') {
			printf("file: %s, size: %u, data_blk: %u\n", root[i].filename, root[i].size, root[i].first_data_index);
		}
	}
	return 0;
}

int fs_open(const char *filename)
{
	// not mounted
	if (!is_mounted) {
		return -1;
	}
	// invalid filename = null, empty, too long
	if (filename == NULL || strlen(filename) == 0 || strlen(filename) >= FS_FILENAME_LEN) {
		return -1; 
	}
	//FS_OPEN_MAX_COUNT already opened
	int num_open = 0;
	for (int i = 0; i < FS_OPEN_MAX_COUNT; i++){
		if (opened_files[i].in_use) {
			num_open++;
		}
	}
	if ( num_open >= FS_OPEN_MAX_COUNT){
		return -1;
	}
	
	// look for the file in rd
	struct root_directory *rd_file = NULL;
	for (int s = 0; s < FS_FILE_MAX_COUNT; s++) {
		if ((root[s].filename[0] != '\0') && (strncmp(root[s].filename, filename, FS_FILENAME_LEN) == 0)){
			rd_file = &root[s];
			break; //found file
		}
	} 
	if (rd_file == NULL){
		return -1; // can't find filename file
	}

	// find first open spot on file table (i think)
	int fd = -1;
	for (int m = 0; m < FS_OPEN_MAX_COUNT; m++){
		if (!opened_files[m].in_use){
			fd = m;
			break; //cuz found free index
		}
	}

	if (fd < 0){
		return -1;
	}
	
	// create the table entry for file
	opened_files[fd].in_use = true;
	opened_files[fd].offset = 0; //initially 0
	opened_files[fd].root_dir = rd_file;

	return fd;
}

int fs_close(int fd)
{
	// not mounted
	if (!is_mounted) {
		return -1;
	}
	// invalid fd
	// out of bounds
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) {
		return -1;
	}
	// not open
	if (!opened_files[fd].in_use){
		return -1;
	}

	//reset
	opened_files[fd].in_use = false;
	opened_files[fd].offset = 0; //initially 0
	opened_files[fd].root_dir = NULL;

	return 0;
}

int fs_stat(int fd)
{
	// invalid checks same as fs_close()
	if (!is_mounted) {
		return -1;
	}
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) {
		return -1;
	}
	if (!opened_files[fd].in_use){
		return -1;
	}

	struct root_directory *file_metadata = opened_files[fd].root_dir;
	int file_size = file_metadata->size;

	return file_size;
}

int fs_lseek(int fd, size_t offset)
{
	if (!is_mounted) {
		return -1;
	}
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) {
		return -1;
	}
	if (!opened_files[fd].in_use){
		return -1;
	}
	int file_size = fs_stat(fd);
	
	if (offset > (size_t)file_size){ // offset bigger than file
		return -1;
	}

	opened_files[fd].offset = offset;

	return 0;
}

// helper function fo rgetting data block index
static int get_data_block_index(struct root_directory *file_rd, uint32_t offset){
	uint16_t cur_dbi = file_rd->first_data_index; // current data block index
	if (cur_dbi == FAT_EOC){
		// the file is empty or offset = 0
		return FAT_EOC;
	}
	uint32_t actual_block = offset/FS_BLOCK_SIZE; 

	// actually look for the datablock index
	for (uint32_t i = 0; i < actual_block; i++){
		if(cur_dbi == FAT_EOC) { //fat ends too early
			return -1;
		}
		cur_dbi = fat[cur_dbi];
	}
	return cur_dbi;
}

int fs_write(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
	(void) fd;
    (void) buf;
    (void) count;
	return 0;
}

int fs_read(int fd, void *buf, size_t count)
{
	// validity check
	if (!is_mounted || fd < 0 || fd >= FS_OPEN_MAX_COUNT || !opened_files[fd].in_use || buf == NULL){
		return -1;
	}
	
	// setup
	struct open_file *open_file_entry = &opened_files[fd];
	struct root_directory *file_rd = open_file_entry->root_dir;
	uint32_t file_size = file_rd->size;
	uint32_t cur_offset = open_file_entry->offset;

	//check how many bytes we can read
	uint32_t bytes_til_end = 0; 
	if (file_size > cur_offset) {
		bytes_til_end = file_size - cur_offset;
	}
	if (bytes_til_end == 0){ //nothing to read
		return -1;
	} 

	size_t bytes_to_read = bytes_til_end; // num bytes to read either count or bytes until the end of the file
	if (count < bytes_til_end) { bytes_to_read = count; }

	// buffer read section
	char *buf_ptr = (char*)buf; //pointer to user buffer
	size_t num_bytes_actually_read = 0;

	char bounce_buf[FS_BLOCK_SIZE]; // temp buf to read into

	uint16_t cur_dbi = get_data_block_index(file_rd, cur_offset); //get starting data block and offset

	uint32_t cur_block_offset = cur_offset % FS_BLOCK_SIZE;
	while (num_bytes_actually_read < bytes_to_read) {
		uint16_t phys_block_num = sb.data_index + cur_dbi;
		//read to bounce buf
		if (block_read(phys_block_num, bounce_buf) < 0){
			return -1;
		}

		// determine bytes from bounce buf to user buf
		size_t bytes_remaining = FS_BLOCK_SIZE - cur_block_offset;
		size_t bytes_to_copy = bytes_to_read - num_bytes_actually_read; 
		if (bytes_to_copy > bytes_remaining){
			bytes_to_copy = bytes_remaining;
		}

		// copy the right amount from bounce buffer to user buffer
		memcpy(buf_ptr, bounce_buf + cur_block_offset, bytes_to_copy);

		//update ptrs
		buf_ptr += bytes_to_copy;
		num_bytes_actually_read += bytes_to_copy;
		open_file_entry->offset += bytes_to_copy;

		// if filled up fat entry
		if(num_bytes_actually_read<bytes_to_read){
			cur_dbi = fat[cur_dbi]; //move to the next block
			if(cur_dbi == FAT_EOC){
				break; //ended too early
			}
			cur_block_offset = 0;
		}
	}
	
	return num_bytes_actually_read;
}
