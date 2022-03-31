/usr/bin/cat <<EOF | nsradmin -s sscprodeng2 -i - 

create type: NSR pool;name: AFTD_POOL;
                     comment: ;
                     enabled: Yes;
                   pool type: Backup;
              label template: AFTD;
            retention policy: Week;
                      groups: AFTD-Test;
                     clients: ;
                   save sets: ;
                      levels: ;
         store index entries: Yes;
           auto media verify: No;
      Recycle to other pools: No;
    Recycle from other pools: No;
         media type required: ;
      volume type preference: ;
             max parallelism: 0;
                 mount class: default;
                   WORM pool: No;
              create DLTWORM: No;
              barcode prefix: ;
               recycle start: ;
            recycle interval: "24:00";
      max volumes to recycle: 200;

create type: NSR pool;name: NATO;
                     comment: ;
                     enabled: Yes;
                   pool type: Backup;
              label template: SscnolaADIC;
            retention policy: ;
                      groups: ;
                     clients: ;
                   save sets: ;
                      levels: ;
         store index entries: Yes;
           auto media verify: No;
      Recycle to other pools: No;
    Recycle from other pools: No;
         media type required: ;
      volume type preference: ;
             max parallelism: 0;
                 mount class: default;
                   WORM pool: No;
              create DLTWORM: No;
              barcode prefix: ;
               recycle start: ;
            recycle interval: "24:00";
      max volumes to recycle: 200;

create type: NSR pool;name: NavyNuclear;
                     comment: ;
                     enabled: Yes;
                   pool type: Backup;
              label template: NavyNuclear;
            retention policy: ;
                      groups: ;
                     clients: ;
                   save sets: ;
                      levels: ;
         store index entries: Yes;
           auto media verify: No;
      Recycle to other pools: No;
    Recycle from other pools: No;
         media type required: ;
      volume type preference: LTO Ultrium-5;
             max parallelism: 0;
                 mount class: default;
                   WORM pool: No;
              create DLTWORM: No;
              barcode prefix: ;
               recycle start: ;
            recycle interval: "24:00";
      max volumes to recycle: 200;

create type: NSR pool;name: SSCNOLALTO5;
                     comment: ;
                     enabled: Yes;
                   pool type: Backup;
              label template: SSCNOLA;
            retention policy: ;
                      groups: ADHOC-Full, ADHOC-Full-2, ADHOC-Full-3, 
                              ADHOC-Incr, ADHOC-Incr-2, ADHOC-Incr-3, 
                              ADHOC-Incr-4, ADHOC-Incr-5, 
                              Automated-Daily-Reruns, 
                              Automated-NON-PROD-Reruns, 
                              Automated-NON-PROD-VADP-Reruns, 
                              Automated-PROD-Reruns, 
                              Automated-PROD-VADP-Reruns, BigandSlow, CSA, 
                              INDEX, LINUX, LINUX-Prod, MIDNIGHT, 
                              NetworkerConsole, PROBLEMS, Production1, 
                              Production2, SDDATA, SSCNOLA1, SSCNOLA2, 
                              VADP-Devpriv-Ch1-600-B4, 
                              VADP-Devpriv-Ch1-610-B14, 
                              VADP-Devpriv-Ch1-610-B15, 
                              VADP-Devpriv-Ch1-610-B7, 
                              VADP-Devpriv-Ch1-610-B8, 
                              VADP-Devpriv-Ch2-620-B12, 
                              VADP-Devpriv-Ch2-620-B13, 
                              VADP-Devpriv-Ch2-620-B4, 
                              VADP-Devpriv-Ch2-620-B5, 
                              VADP-Devpriv-Ch2-910-B1, 
                              VADP-Devpriv-Ch2-910-B2, 
                              VADP-Devpriv-Ch2-910-B3, VADP-Ops2-610-B1, 
                              VADP-Ops2-610-B10, VADP-Ops2-610-B11, 
                              VADP-Ops2-610-B12-22a, VADP-Ops2-610-B2, 
                              VADP-Ops2-610-B3, VADP-Ops2-610-B4, 
                              VADP-Ops2-610-B5, VADP-Ops2-610-B9, 
                              VADP-Ops2-Ch1-610-B6, VADP-Ops2-Ch1-610-B7, 
                              VADP-Opsmgmt-610-B1, VADP-Opsmgmt-610-B2, 
                              VADP-Opsmgmt-610-B3, VADP-Opsmgmt-610-B4, 
                              VADP-Opsmgmt-610-B6, VADP-Prodint-Ch1-610-B1, 
                              VADP-Prodint-Ch1-620-B13, 
                              VADP-Prodint-Ch1-620-B14, 
                              VADP-Prodint-Ch1-620-B15, 
                              VADP-Prodint-Ch1-620-B16, 
                              VADP-Prodint-Ch2-610-B1, 
                              VADP-Prodint-Ch2-610-B10, 
                              VADP-Prodint-Ch2-610-B12, 
                              VADP-Prodint-Ch2-610-B14, 
                              VADP-Prodint-Ch2-610-B2, 
                              VADP-Prodint-Ch2-610-B4, 
                              VADP-Prodint-Ch2-610-B6, 
                              VADP-Prodint-Ch2-610-B9, 
                              VADP-Prodnipr-Ch1-610-B1, 
                              VADP-Prodnipr-Ch1-610-B10, 
                              VADP-Prodnipr-Ch1-610-B2, 
                              VADP-Prodpriv-Ch1-600-B12, 
                              VADP-Prodpriv-Ch1-600-B5, 
                              VADP-Prodpriv-Ch1-600-B6, 
                              VADP-Prodpriv-Ch1-620-B1, 
                              VADP-Prodpriv-Ch1-620-B10, 
                              VADP-Prodpriv-Ch1-620-B2, 
                              VADP-Prodpriv-Ch1-620-B9, 
                              VADP-Prodpriv-Ch1-910-B7, 
                              VADP-Prodpriv-Ch1-910-B8, 
                              VADP-Prodpriv-Ch2-610-B15, 
                              VADP-Prodpriv-Ch2-620-B1, 
                              VADP-Prodpriv-Ch2-620-B10, 
                              VADP-Prodpriv-Ch2-620-B2, 
                              VADP-Prodpriv-Ch2-620-B7, 
                              VADP-Prodpriv-Ch2-620-B8, 
                              VADP-Prodpriv-Ch2-620-B9, 
                              VADP-Prodpriv-Ch2-910-B3, 
                              VADP-Prodpriv-Ch2-910-B4, 
                              VADP-Prodpriv-Ch2-910-B5, 
                              VADP-Prodpriv-Ch2-910-B6, 
                              VADP-Prodspec-Ch1-610-B12, 
                              VADP-Prodspec-Ch1-610-B13, 
                              VADP-Prodspec-Ch1-610-B5, 
                              VADP-Prodspec-Ch1-610-B6, 
                              VADP-Prodspec-Ch1-610-B7, 
                              VADP-Prodspec-Ch1-620-B1, 
                              VADP-Prodspec-Ch1-620-B10, 
                              VADP-Prodspec-Ch1-620-B15, 
                              VADP-Prodspec-Ch1-620-B16, 
                              VADP-Prodspec-Ch1-620-B2, 
                              VADP-Prodspec-Ch1-620-B8, 
                              VADP-Transdev-Ch1-610-B10, 
                              VADP-Transdev-Ch1-610-B2, 
                              VADP-Transdev-Ch1-620-B11, 
                              VADP-Transdev-Ch1-620-B3, 
                              VADP-Transprod-Ch1-610-B1, 
                              VADP-Transprod-Ch1-610-B9, 
                              VADP-Transqa-Ch1-610-B10, 
                              VADP-Transqa-Ch1-610-B14, 
                              VADP-Transqa-Ch1-610-B15, 
                              VADP-Transqa-Ch1-610-B4, 
                              VADP-Transqa-Ch1-610-B5, 
                              VADP-Transqa-Ch1-610-B6, 
                              VADP-Transqa-Ch1-610-B7, 
                              VADP-Transqa-Ch1-610-B8, VMS-P2, WINDOWS, 
                              WINDOWS-PROD;
                     clients: ;
                   save sets: ;
                      levels: ;
         store index entries: Yes;
           auto media verify: No;
      Recycle to other pools: No;
    Recycle from other pools: No;
         media type required: ;
      volume type preference: LTO Ultrium-5;
             max parallelism: 0;
                 mount class: default;
                   WORM pool: No;
              create DLTWORM: No;
              barcode prefix: ;
               recycle start: ;
            recycle interval: "24:00";
      max volumes to recycle: 200;

create type: NSR pool;name: SscnolaADIC;
                     comment: ;
                     enabled: Yes;
                   pool type: Backup;
              label template: SSCNCLN;
            retention policy: Year;
                      groups: ;
                     clients: ;
                   save sets: ;
                      levels: ;
                     devices: ;
         store index entries: Yes;
           auto media verify: No;
      Recycle to other pools: No;
    Recycle from other pools: No;
         media type required: ;
      volume type preference: LTO Ultrium-3;
             max parallelism: 0;
                 mount class: default;
                   WORM pool: No;
              create DLTWORM: No;
              barcode prefix: ;
               recycle start: ;
            recycle interval: "24:00";
      max volumes to recycle: 200;
EOF
ADP-Transdev-Ch1-620-B3, 
                              VADP-Transprod-Ch1-610-B1, 
                              VADP-Transprod-Ch1-610-B9, 
                              VADP-Transqa-Ch1-610-B10, 
                              VADP-Transqa-Ch1-610-B14, 
                              VADP-Transqa-Ch1-610-B15, 
                              VADP-Transqa-Ch1-610-B4, 
                              VADP-Transqa-Ch1-610-B5, 
                              VADP-Transqa-Ch1-610-B6, 
                              VADP-Transqa-Ch1-610-B7, 
                              VADP-Transqa-Ch1-610-B8, VMS-P2, WINDOWS, 
                              WINDOWS-PROD;
                     clients: ;
                   save sets: ;
                      levels: ;
         store index entries: Yes;
           auto media verify: No;
      Recycle to other pools: No;
    Recycle from other pools: No;
         media type required: ;
      volume type preference: LTO Ultrium-5;
             max parallelism: 0;
                 mount class: default;
                   WORM pool: No;
              create DLTWORM: No;
              barcode prefix: ;
               recycle start: ;
            recycle interval: "24:00";
      max volumes to recycle: 200;

create type: NSR pool;name: SscnolaADIC;
                     comment: ;
                     enabled: Yes;
                   pool type: Backup;
              label template: SSCNCLN;
            retention policy: Year;
                      groups: ;
                     clients: ;
                   save sets: ;
                      levels: ;
         store index entries: Yes;
           auto media verify: No;
      Recycle to other pools: No;
    Recycle from other pools: No;
         media type required: ;
      volume type preference: LTO Ultrium-3;
             max parallelism: 0;
                 mount class: default;
                   WORM pool: No;
              create DLTWORM: No;
              barcode prefix: ;
               recycle start: ;
            recycle interval: "24:00";
      max volumes to recycle: 200;
EOF
