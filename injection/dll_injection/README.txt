++++++++++++++
+-+ README +-+
++++++++++++++

The script ./injektor.py (without the --hijack-primary-thread-option) will generate a payload buffer (using libshellcode.shellcode module) 
that looks as follows (EP stands for 'Entry Point'):

.              .
.              .
+              +
+              +
+              +
++++++++++++++++<-ejection_failure_EP
+              +
+              +
+              +
+              +
+              +
++++++++++++++++<-injection_failure_EP
+              +
+              +
+              +
+              +
+              +
++++++++++++++++<-freelibraryandexitthread_EP
+              +
+              +
+              +
+              +
+              +
++++++++++++++++<-exitthread_EP (prolog)
+              +
+              +
+              +
+              +
+              +
++++++++++++++++<-codecave_addr + CODECAVE_SIZE
