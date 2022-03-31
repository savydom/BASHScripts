projmod -a  -K 'project.max-shm-memory=(privileged,'$1'G,deny)' default
projmod -a  -K 'process.max-file-descriptor=(privileged,4096,deny)' default
