#!/bin/bash
rmmod syscall_protect
insmod syscall_protect_kmod/syscall_protect.ko
