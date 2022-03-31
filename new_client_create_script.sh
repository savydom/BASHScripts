/usr/bin/cat <<EOF | nsradmin -s sscprodeng -i - 
create type: NSR client;name: C27ITSMcnlaD1A;
                      server: sscprodeng;
            scheduled backup: Disabled;
                     comment: "W:;";
             Save operations: ;
                    schedule: Full Every Friday;
               browse policy: Year;
            retention policy: Year;
                   directive: ;
                       group: INDEX, VADP-Devpriv-Ch2-620-B5, 
                              Automated-NON-PROD-VADP-Reruns;
                    save set: *FULL*;
  Backup renamed directories: Disabled;
          Checkpoint enabled: Disabled;
      Checkpoint granularity: Directory;
Parallel save streams per save set: Disabled;
                    priority: 1;
               remote access: ;
                 remote user: ;
                    password: ;
              backup command: nsrvadp_save;
                 Pre command: ;
                Post command: ;
     application information: VADP_DISABLE_CBT=YES, VADP_QUIESCE_SNAPSHOT=no, 
                              VADP_VM_NAME=C27ITSMcnlaD1A, 
                              VADP_HYPERVISOR=VMware55-NOLA;
     ndmp vendor information: ;
                        ndmp: No;
             NDMP array name: ;
storage replication policy name: ;
                        Pool: ;
               Client direct: Disabled;
         Probe resource name: ;
              virtual client: Yes;
          Block based backup: No;
               physical host: prodspec-ch1-620-b1-esx;
           Proxy backup type: VADP;
           Proxy backup host: bkproxy2;
             executable path: ;
    server network interface: sscprodeng;
                     aliases: c27itsmcnlad1a, c27itsmcnlad1a.sscnola.oob, 
                              c27itsmcnlad1a.ahds.nmci.navy.mil, 
                              c27itsmcnlad1a.ahds.navy.mil;
          owner notification: ;
                 parallelism: 7;
 physical client parallelism: Disabled;
     autoselect storage node: Disabled;
               storage nodes: sscprodeng;
       recover storage nodes: ;
   save session distribution: max sessions;
                  hard links: Disabled;
             short filenames: Disabled;
                 backup type: ;
              client OS type: Windows NT Server on Intel;
                        CPUs: 48;
           NetWorker version: 8.2.2.6.Build.985;
              enabler in use: Yes;
       licensed applications: ;
               licensed PSPs: ;
EOF

