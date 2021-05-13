#ifndef __LINUX_OBJ_H
#define __LINUX_OBJ_H
struct obj_system_type{
	__le16  magic;  //magic signature
  char name[16];  //application name
  __le64 start_objno; //start object id
	__le32 ctime;  //creation time
	__le64 size; //max size in bytes
};

#define OBJ_SYSTEM_SIZE 64
#define OBJ_SYSTEM_MAGIC  0xBABA
#define OBJ_SYSTEM_MAX  8

//exports
//maybe const?
extern struct obj_system_type *find_objsystem(const char *);
extern int register_objsystem(struct obj_system_type *);
extern int unregister_objsystem(struct obj_system_type *);
//obj.c
extern int objms_new_obj(unsigned long *);
extern int objms_delete_obj(unsigned long);
extern long objms_allocate_obj(unsigned long objno, int mode, loff_t offset,
			    loff_t len);
extern ssize_t objms_read_obj_user(int, char __user *, size_t, loff_t *);
extern ssize_t objms_read_obj_kernel(int, char *, size_t, loff_t *);
extern ssize_t objms_write_obj_user(int, const char __user *, size_t, loff_t *);
extern ssize_t objms_write_obj_kernel(int, const char *, size_t, loff_t *);

#endif
