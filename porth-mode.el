;;; porth-mode.el --- A major mode for the Porth programming language -*- lexical-binding: t -*-

;; Version: 0.0.1
;; Author: XXIV
;; Keywords: files, porth
;; Package-Requires: ((emacs "24.3"))
;; Homepage: https://github.com/thechampagne/porth-mode

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; A major mode for the Porth programming language.

;;;; Installation

;; You can use built-in package manager (package.el) or do everything by your hands.

;;;;; Using package manager

;; Add the following to your Emacs config file

;; (require 'package)
;; (add-to-list 'package-archives
;;              '("melpa" . "https://melpa.org/packages/") t)
;; (package-initialize)

;; Then use `M-x package-install RET porth-mode RET` to install the mode.
;; Use `M-x porth-mode` to change your current mode.

;;;;; Manual

;; Download the mode to your local directory.  You can do it through `git clone` command:

;; git clone git://github.com/thechampagne/porth-mode.git

;; Then add path to porth-mode to load-path list — add the following to your Emacs config file

;; (add-to-list 'load-path
;; 	     "/path/to/porth-mode/")
;; (require 'porth-mode)

;; Use `M-x porth-mode` to change your current mode.

;;; Code:

(defconst porth-mode-syntax-table
  (let ((table (make-syntax-table)))
    (modify-syntax-entry ?/ ". 124b" table)
    (modify-syntax-entry ?* ". 23" table)
    (modify-syntax-entry ?\n "> b" table)
    (modify-syntax-entry ?\' "\"" table)
    (modify-syntax-entry ?\" "\"" table)

    (modify-syntax-entry ?@ "w" table)
    (modify-syntax-entry ?\) "w" table)
    (modify-syntax-entry ?\( "w" table)
    (modify-syntax-entry ?? "w" table)
    (modify-syntax-entry ?! "w" table)
    (modify-syntax-entry ?= "w" table)
    (modify-syntax-entry ?+ "w" table)
    (modify-syntax-entry ?- "w" table)
    (modify-syntax-entry ?> "w" table)
    (modify-syntax-entry ?< "w" table)
    table))


(defcustom porth-std-syntax-highlight t
  "When non nil, porth standard library syntax will be highlighted."
  :type 'boolean
  :group 'porth-mode)


(defconst porth-keywords
  '("if" "else" "end" ;; "if*"
    "while" "do" "include"
    "memory" "proc" "const"
    "offset" "reset" "assert"
    "in" "inline" "here"
    "addr-of" "call-like"
    "let" "peek" "--"))


(defconst porth-data-types
  '("ptr" "bool" "int" "addr"))


(defconst porth-builtins
  '("+" "-" "*" "divmod"
    "idivmod" "max" "print"
    "=" ">" "<" ">=" "<="
    "!=" "shr" "shl" "or"
    "and" "not" "dup" "swap"
    "drop" "over" "rot" "!8"
    "@8" "!16" "@16" "!32"
    "@32" "!64" "@64" "argc"
    "argv" "envp" "syscall0"
    "syscall1" "syscall2"
    "syscall3" "syscall4"
    "syscall5" "syscall6"
    "cast(ptr)" "cast(int)"
    "cast(bool)" "cast(addr)"
    "???"))


(defconst porth-todos
  '("TODO" "XXX" "FIXME" "NOTE"))


(defconst porth-std-procedures
  '("nth_argv" "cstrlen"
    "cstreq" "cstr-to-str"
    "fputs" "puts"
    "eputs" "Str.count"
    "Str.data" "@Str.count"
    "@Str.data" "!Str.count"
    "!Str.data" "@Str"
    "!Str" "str-null"
    "str-chop-one-left" "str-chop-one-right"
    "?space" "str-trim-left"
    "str-chop-by-predicate" "str-chop-by-delim"
    "str-chop-by-delim-2" "str-starts-with"
    "?str-empty" "streq"
    "?digit" "isdigit"
    "?alpha" "isalpha"
    "?alnum" "isalnum"
    "try-parse-int" "fputu"
    "fputi" "fput0u"
    "puti" "putu"
    "put0u" "eputu"
    "memcpy" "memset"
    "srand" "rand"
    "getenv" "tmp-clean"
    "tmp-end" "tmp-rewind"
    "tmp-alloc" "tmp-str-to-cstr"
    "tmp-append" "tmp-append-ptr"
    "execvp" "append-item"
    "tmp-utos" "map-file"
    "?file-exist" "?shell-safe-char"
    "?shell-safe-str" "shell-escape"
    "timeit/from-here" "timeit/to-here"
    "str" "dirname"
    "putch" "remove-ext"
    "cmd-echoed" "normpath"
    "isabs" "abspath"
    "bflush" "bputs"
    "bputu"))


(defconst porth-std-core-procedures
  '("@ptr" "@@ptr"
    "@bool" "@int"
    "@addr" "!bool"
    "!ptr" "!int"
    "!addr" "ptr+"
    "ptr-" "ptr!="
    "ptr=" "ptr<"
    "+ptr" "ptr-diff"
    "/" "%"
    "mod" "div"
    "imod" "idiv"
    "emod" "lnot"
    "land" "lor"
    "inc64-by" "inc64"
    "dec64" "inc32"
    "dec32" "inc8"
    "dec8" "neg"
    "?null" "toggle"))


(defconst porth-std-linux-procedures
  '("stat.st_dev" "stat.st_ino"
    "stat.st_mode" "stat.st_nlink"
    "stat.st_uid" "stat.st_gid"
    "stat.st_rdev" "stat.st_size"
    "@stat.st_size" "stat.st_blksize"
    "stat.st_blocks" "stat.st_atim"
    "stat.st_mtim" "stat.st_ctim"
    "htons" "write"
    "read" "openat"
    "fstat" "stat"
    "close" "exit"
    "mmap" "clock_nanosleep"
    "clock_gettime" "fork"
    "getpid" "execve"
    "wait4" "rename"
    "fcntl" "kill"
    "dup2" "socket"
    "bind" "listen"
    "accept" "getcwd"
    "chroot" "ioctl"
    "WIFSTOPPED" "WIFCONTINUED"
    "WIFSIGNALED" "WTERMSIG"
    "WIFEXITED" "WEXITSTATUS"
    "isatty"))


(defconst porth-std-termios-procedures
  '("tcgetattr" "tcgetattr"))


(defconst porth-std-constants
  '("stdin" "stdout"
    "stderr" "offsetof(Str.count)"
    "offsetof(Str.data)" "sizeof(Str)"
    "PUTU_BUFFER_CAP" "RAND_A"
    "RAND_C" "TMP_CAP"
    "1e9" "BFD_CAP"
    "Bfd.fd" "Bfd.buff"
    "Bfd.size" "sizeof(Bfd)"))


(defconst porth-std-core-constants
  '("NULL" "true" "false"
    "sizeof(u64)" "sizeof(u32)"
    "sizeof(u16)" "sizeof(u8)"
    "sizeof(ptr)" "sizeof(bool)"
    "sizeof(int)" "sizeof(addr)"))


(defconst porth-std-linux-constants
  '("SYS_read" "SYS_write"
    "SYS_open" "SYS_close"
    "SYS_stat" "SYS_fstat"
    "SYS_lstat" "SYS_poll"
    "SYS_lseek" "SYS_mmap"
    "SYS_mprotect" "SYS_munmap"
    "SYS_brk" "SYS_rt_sigaction"
    "SYS_rt_sigprocmask" "SYS_rt_sigreturn"
    "SYS_ioctl" "SYS_pread64"
    "SYS_pwrite64" "SYS_readv"
    "SYS_writev" "SYS_access"
    "SYS_pipe" "SYS_select"
    "SYS_sched_yield" "SYS_mremap"
    "SYS_msync" "SYS_mincore"
    "SYS_madvise" "SYS_shmget"
    "SYS_shmat" "SYS_shmctl"
    "SYS_dup" "SYS_dup2"
    "SYS_pause" "SYS_nanosleep"
    "SYS_getitimer" "SYS_alarm"
    "SYS_setitimer" "SYS_getpid"
    "SYS_sendfile" "SYS_socket"
    "SYS_connect" "SYS_accept"
    "SYS_sendto" "SYS_recvfrom"
    "SYS_sendmsg" "SYS_recvmsg"
    "SYS_shutdown" "SYS_bind"
    "SYS_listen" "SYS_getsockname"
    "SYS_getpeername" "SYS_socketpair"
    "SYS_setsockopt" "SYS_getsockopt"
    "SYS_clone" "SYS_fork"
    "SYS_vfork" "SYS_execve"
    "SYS_exit" "SYS_wait4"
    "SYS_kill" "SYS_uname"
    "SYS_semget" "SYS_semop"
    "SYS_semctl" "SYS_shmdt"
    "SYS_msgget" "SYS_msgsnd"
    "SYS_msgrcv" "SYS_msgctl"
    "SYS_fcntl" "SYS_flock"
    "SYS_fsync" "SYS_fdatasync"
    "SYS_truncate" "SYS_ftruncate"
    "SYS_getdents" "SYS_getcwd"
    "SYS_chdir" "SYS_fchdir"
    "SYS_rename" "SYS_mkdir"
    "SYS_rmdir" "SYS_creat"
    "SYS_link" "SYS_unlink"
    "SYS_symlink" "SYS_readlink"
    "SYS_chmod" "SYS_fchmod"
    "SYS_chown" "SYS_fchown"
    "SYS_lchown" "SYS_umask"
    "SYS_gettimeofday" "SYS_getrlimit"
    "SYS_getrusage" "SYS_sysinfo"
    "SYS_times" "SYS_ptrace"
    "SYS_getuid" "SYS_syslog"
    "SYS_getgid" "SYS_setuid"
    "SYS_setgid" "SYS_geteuid"
    "SYS_getegid" "SYS_setpgid"
    "SYS_getppid" "SYS_getpgrp"
    "SYS_setsid" "SYS_setreuid"
    "SYS_setregid" "SYS_getgroups"
    "SYS_setgroups" "SYS_setresuid"
    "SYS_getresuid" "SYS_setresgid"
    "SYS_getresgid" "SYS_getpgid"
    "SYS_setfsuid" "SYS_setfsgid"
    "SYS_getsid" "SYS_capget"
    "SYS_capset" "SYS_rt_sigpending"
    "SYS_rt_sigtimedwait" "SYS_rt_sigqueueinfo"
    "SYS_rt_sigsuspend" "SYS_sigaltstack"
    "SYS_utime" "SYS_mknod"
    "SYS_uselib" "SYS_personality"
    "SYS_ustat" "SYS_statfs"
    "SYS_fstatfs" "SYS_sysfs"
    "SYS_getpriority" "SYS_setpriority"
    "SYS_sched_setparam" "SYS_sched_getparam"
    "SYS_sched_setscheduler" "SYS_sched_getscheduler"
    "SYS_sched_get_priority_max" "SYS_sched_get_priority_min"
    "SYS_sched_rr_get_interval" "SYS_mlock"
    "SYS_munlock" "SYS_mlockall"
    "SYS_munlockall" "SYS_vhangup"
    "SYS_modify_ldt" "SYS_pivot_root"
    "SYS__sysctl" "SYS_prctl"
    "SYS_arch_prctl" "SYS_adjtimex"
    "SYS_setrlimit" "SYS_chroot"
    "SYS_sync" "SYS_acct"
    "SYS_settimeofday" "SYS_mount"
    "SYS_umount2" "SYS_swapon"
    "SYS_swapoff" "SYS_reboot"
    "SYS_sethostname" "SYS_setdomainname"
    "SYS_iopl" "SYS_ioperm"
    "SYS_create_module" "SYS_init_module"
    "SYS_delete_module" "SYS_get_kernel_syms"
    "SYS_query_module" "SYS_quotactl"
    "SYS_nfsservctl" "SYS_getpmsg"
    "SYS_putpmsg" "SYS_afs_syscall"
    "SYS_tuxcall" "SYS_security"
    "SYS_gettid" "SYS_readahead"
    "SYS_setxattr" "SYS_lsetxattr"
    "SYS_fsetxattr" "SYS_getxattr"
    "SYS_lgetxattr" "SYS_fgetxattr"
    "SYS_listxattr" "SYS_llistxattr"
    "SYS_flistxattr" "SYS_removexattr"
    "SYS_lremovexattr" "SYS_fremovexattr"
    "SYS_tkill" "SYS_time"
    "SYS_futex" "SYS_sched_setaffinity"
    "SYS_sched_getaffinity" "SYS_set_thread_area"
    "SYS_io_setup" "SYS_io_destroy"
    "SYS_io_getevents" "SYS_io_submit"
    "SYS_io_cancel" "SYS_get_thread_area"
    "SYS_lookup_dcookie" "SYS_epoll_create"
    "SYS_epoll_ctl_old" "SYS_epoll_wait_old"
    "SYS_remap_file_pages" "SYS_getdents64"
    "SYS_set_tid_address" "SYS_restart_syscall"
    "SYS_semtimedop" "SYS_fadvise64"
    "SYS_timer_create" "SYS_timer_settime"
    "SYS_timer_gettime" "SYS_timer_getoverrun"
    "SYS_timer_delete" "SYS_clock_settime"
    "SYS_clock_gettime" "SYS_clock_getres"
    "SYS_clock_nanosleep" "SYS_exit_group"
    "SYS_epoll_wait" "SYS_epoll_ctl"
    "SYS_tgkill" "SYS_utimes"
    "SYS_vserver" "SYS_mbind"
    "SYS_set_mempolicy" "SYS_get_mempolicy"
    "SYS_mq_open" "SYS_mq_unlink"
    "SYS_mq_timedsend" "SYS_mq_timedreceive"
    "SYS_mq_notify" "SYS_mq_getsetattr"
    "SYS_kexec_load" "SYS_waitid"
    "SYS_add_key" "SYS_request_key"
    "SYS_keyctl" "SYS_ioprio_set"
    "SYS_ioprio_get" "SYS_inotify_init"
    "SYS_inotify_add_watch" "SYS_inotify_rm_watch"
    "SYS_migrate_pages" "SYS_openat"
    "SYS_mkdirat" "SYS_mknodat"
    "SYS_fchownat" "SYS_futimesat"
    "SYS_newfstatat" "SYS_unlinkat"
    "SYS_renameat" "SYS_linkat"
    "SYS_symlinkat" "SYS_readlinkat"
    "SYS_fchmodat" "SYS_faccessat"
    "SYS_pselect6" "SYS_ppoll"
    "SYS_unshare" "SYS_set_robust_list"
    "SYS_get_robust_list" "SYS_splice"
    "SYS_tee" "SYS_sync_file_range"
    "SYS_vmsplice" "SYS_move_pages"
    "SYS_utimensat" "SYS_epoll_pwait"
    "SYS_signalfd" "SYS_timerfd_create"
    "SYS_eventfd" "SYS_fallocate"
    "SYS_timerfd_settime" "SYS_timerfd_gettime"
    "SYS_accept4" "SYS_signalfd4"
    "SYS_eventfd2" "SYS_epoll_create1"
    "SYS_dup3" "SYS_pipe2"
    "SYS_inotify_init1" "SYS_preadv"
    "SYS_pwritev" "SYS_rt_tgsigqueueinfo"
    "SYS_perf_event_open" "SYS_recvmmsg"
    "SYS_fanotify_init" "SYS_fanotify_mark"
    "SYS_prlimit64" "SYS_name_to_handle_at"
    "SYS_open_by_handle_at" "SYS_clock_adjtime"
    "SYS_syncfs" "SYS_sendmmsg"
    "SYS_setns" "SYS_getcpu"
    "SYS_process_vm_readv" "SYS_process_vm_writev"
    "SYS_kcmp" "SYS_finit_module"
    "AT_FDCWD" "O_RDONLY"
    "O_WRONLY" "O_RDWR"
    "O_CREAT" "O_TRUNC"
    "O_NONBLOCK" "F_SETFL"
    "F_GETFL" "EACCES"
    "EAGAIN" "EFAULT"
    "EIO" "ELOOP"
    "ENAMETOOLONG" "ENOENT"
    "ENOMEM" "ENOTDIR"
    "EPERM" "EINVAL"
    "CLOCK_MONOTONIC" "TIMER_ABSTIME"
    "MAP_PRIVATE" "MAP_ANONYMOUS"
    "PROT_READ" "PROT_WRITE"
    "SIGQUIT" "timespec.tv_sec"
    "timespec.tv_nsec" "sizeof(timespec)"
    "sizeof(stat)"

    "sizeof(stat.st_dev)" "sizeof(stat.st_ino)"
    "sizeof(stat.st_mode)" "sizeof(stat.st_nlink)"
    "sizeof(stat.st_uid)" "sizeof(stat.st_gid)"
    "sizeof(stat.st_rdev)" "sizeof(stat.st_size)"
    "sizeof(stat.st_blksize)" "sizeof(stat.st_blocks)"
    "sizeof(stat.st_atim)" "sizeof(stat.st_mtim)"
    "sizeof(stat.st_ctim)" "sizeof(sockaddr)"
    "sockaddr_in.sin_family" "sockaddr_in.sin_port"
    "sockaddr_in.sin_addr" "sizeof(sockaddr_in.sin_family)"
    "sizeof(sockaddr_in.sin_port)" "sizeof(sockaddr_in.sin_addr)"
    "AF_INET" "SOCK_STREAM"
    "INADDR_LOCAL"

    "PATH_MAX" "sizeof(tcflag_t)"
    "sizeof(cc_t)" "NCCS"
    "termios.c_iflag" "termios.c_oflag"
    "termios.c_cflag" "termios.c_lflag"
    "termios.c_cc" "sizeof(termios)"
    "winsize.ws_row" "winsize.ws_col"
    "winsize.ws_xpixel" "winsize.ws_ypixel"
    "sizeof(winsize)" "TIOCGWINSZ"
    "TCGETS" "TCSETS"
    "ICANON" "ECHO"
    "VTIME" "VMIN"
    "TCSAFLUSH" "TCSANOW"))


(defconst porth-font-lock-keywords
  (if porth-std-syntax-highlight
      (list
       `(,(regexp-opt porth-data-types 'words) . font-lock-type-face)
       `(,(regexp-opt porth-keywords 'symbols) . font-lock-keyword-face)
       `(,(regexp-opt porth-builtins 'words) . font-lock-builtin-face)
       `(,(regexp-opt porth-todos 'words) . font-lock-warning-face)
       `(,(regexp-opt porth-std-constants 'words) . font-lock-constant-face)
       `(,(regexp-opt porth-std-core-constants 'words) . font-lock-constant-face)
       `(,(regexp-opt porth-std-linux-constants 'words) . font-lock-constant-face)
       `(,(regexp-opt porth-std-procedures 'words) . font-lock-builtin-face)
       `(,(regexp-opt porth-std-core-procedures 'words) . font-lock-builtin-face)
       `(,(regexp-opt porth-std-linux-procedures 'words) . font-lock-builtin-face)
       `(,(regexp-opt porth-std-termios-procedures 'words) . font-lock-builtin-face))
  (list
   `(,(regexp-opt porth-data-types 'words) . font-lock-type-face)
   `(,(regexp-opt porth-keywords 'symbols) . font-lock-keyword-face)
   `(,(regexp-opt porth-builtins 'words) . font-lock-builtin-face)
   `(,(regexp-opt porth-todos 'words) . font-lock-warning-face))))

;;;###autoload
(define-derived-mode porth-mode prog-mode "Porth"
  "A major mode for the Porth programming language."
  :syntax-table porth-mode-syntax-table
  (setq-local font-lock-defaults '(porth-font-lock-keywords)))

;;;###autoload
(add-to-list 'auto-mode-alist '("\\.porth\\'" . porth-mode))

(provide 'porth-mode)

;;; porth-mode.el ends here
