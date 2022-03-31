/usr/bin/cat <<EOF | nsradmin -s sscprodeng2 -i - 

create type: NSR label;name: AFTD;
                     comment: ;
                      fields: AFTD, 001-999;
                   separator: .;
                        next: AFTD.011;

create type: NSR label;name: AFTDClone;
                     comment: ;
                      fields: ANN, 001-999;
                   separator: ;
                        next: ANN099;

create type: NSR label;name: DecadeA;
                     comment: Archive for Decade;
                      fields: UNA, 000-999, L3;
                   separator: ;
                        next: UNA000L3;

create type: NSR label;name: DecadeB;
                     comment: Archive Copy for Decade;
                      fields: UNB, 000-999, L3;
                   separator: ;
                        next: UNB000L3;

create type: NSR label;name: NavyNuclear;
                     comment: Navy Nuclear to meet data separation;
                      fields: UNN, 001-999, L3;
                   separator: ;
                        next: UNN001L3;

create type: NSR label;name: SSCNCLN;
                     comment: SSC Nola Clone Pool;
                      fields: UN, 0001-9999, L3;
                   separator: ;
                        next: UN0001L3;

create type: NSR label;name: SSCNOLA;
                     comment: ;
                      fields: SSCN, 0000-9999, L3;
                   separator: ;
                        next: SSCN0000L3;

create type: NSR label;name: ServerRecover;
                     comment: ;
                      fields: ServerRecover, 001-999;
                   separator: .;
                        next: ServerRecover.001;

create type: NSR label;name: SscnolaADIC;
                     comment: ;
                      fields: SscnolaADIC, 001-999;
                   separator: .;
                        next: SscnolaADIC.015;

create type: NSR label;name: adhoc;
                     comment: ;
                      fields: SW, 0000-1276, L2;
                   separator: ;
                        next: SW0000L2;
