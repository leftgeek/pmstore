#
# Makefile for the linux objms routines.
#

#obj-$(CONFIG_OBJMS) += pmfs.o
#obj-$(CONFIG_OBJMS_TEST_MODULE) += pmfs_test.o

obj-y += objms.o
objms-y := balloc.o inode.o super.o journal.o bbuild.o obj.o xattr.o mmap.o olock.o

#pmfs-$(CONFIG_OBJMS_WRITE_PROTECT) += wprotect.o
#pmfs-$(CONFIG_OBJMS_XIP) += xip.o
