#!/bin/bash
qemu-system-x86_64 \
  -kernel kernel/arch/x86_64/boot/bzImage \
  -drive format=raw,file=rootfs,if=virtio \
  -append "root=/dev/vda1 console=ttyS0 nokaslr" \
  -nographic \
  -m 4G \
  -enable-kvm \
  -cpu host \
  -smp $(nproc) \
  -virtfs local,path=.,mount_tag=host0,security_model=passthrough,id=host0
