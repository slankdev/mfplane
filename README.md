# hyperplane

```
slankdev:~/git/hyperplane[main]$ de CLOS tcpdump -nni any not icmp6 and not tcp port 179
tcpdump: data link type LINUX_SLL2
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes

12:24:19.117265 hv1   In  IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 360518314:360518329, ack 3696981341, win 502, options [nop,nop,TS val 3648615937 ecr 1107733048], length 15
12:24:19.117281 l1    Out IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 0:15, ack 1, win 502, options [nop,nop,TS val 3648615937 ecr 1107733048], length 15
12:24:19.117312 l1    In  IP6 fc00:1:: > fc00:11:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 0:15, ack 1, win 502, options [nop,nop,TS val 3648615937 ecr 1107733048], length 15
12:24:19.117318 n1    Out IP6 fc00:1:: > fc00:11:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 0:15, ack 1, win 502, options [nop,nop,TS val 3648615937 ecr 1107733048], length 15
12:24:19.117352 n1    In  IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 0:15, ack 1, win 502, options [nop,nop,TS val 3648615937 ecr 1107733048], length 15
12:24:19.117360 c1    Out IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 0:15, ack 1, win 502, options [nop,nop,TS val 3648615937 ecr 1107733048], length 15

12:24:19.117371 c1    In  IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 15, win 509, options [nop,nop,TS val 1107737143 ecr 3648615937], length 0
12:24:19.117384 l1    Out IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 15, win 509, options [nop,nop,TS val 1107737143 ecr 3648615937], length 0
12:24:19.117393 l1    In  IP6 fc00:1:: > fc00:11:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 15, win 509, options [nop,nop,TS val 1107737143 ecr 3648615937], length 0
12:24:19.117396 n1    Out IP6 fc00:1:: > fc00:11:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 15, win 509, options [nop,nop,TS val 1107737143 ecr 3648615937], length 0
12:24:19.117407 n1    In  IP6 fc00:11:: > fc00:201:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:201:1::) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 15, win 509, options [nop,nop,TS val 1107737143 ecr 3648615937], length 0
12:24:19.117411 hv1   Out IP6 fc00:11:: > fc00:201:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:201:1::) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 15, win 509, options [nop,nop,TS val 1107737143 ecr 3648615937], length 0

12:24:23.330987 hv1   In  IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 15:31, ack 1, win 502, options [nop,nop,TS val 3648620151 ecr 1107737143], length 16
12:24:23.331002 l1    Out IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 15:31, ack 1, win 502, options [nop,nop,TS val 3648620151 ecr 1107737143], length 16
12:24:23.331032 l1    In  IP6 fc00:1:: > fc00:11:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 15:31, ack 1, win 502, options [nop,nop,TS val 3648620151 ecr 1107737143], length 16
12:24:23.331037 n1    Out IP6 fc00:1:: > fc00:11:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 15:31, ack 1, win 502, options [nop,nop,TS val 3648620151 ecr 1107737143], length 16
12:24:23.331072 n1    In  IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 15:31, ack 1, win 502, options [nop,nop,TS val 3648620151 ecr 1107737143], length 16
12:24:23.331080 c1    Out IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 15:31, ack 1, win 502, options [nop,nop,TS val 3648620151 ecr 1107737143], length 16

12:24:23.331092 c1    In  IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 31, win 509, options [nop,nop,TS val 1107741357 ecr 3648620151], length 0
12:24:23.331099 l1    Out IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 31, win 509, options [nop,nop,TS val 1107741357 ecr 3648620151], length 0
12:24:23.331113 l1    In  IP6 fc00:1:: > fc00:11:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 31, win 509, options [nop,nop,TS val 1107741357 ecr 3648620151], length 0
12:24:23.331116 n1    Out IP6 fc00:1:: > fc00:11:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 31, win 509, options [nop,nop,TS val 1107741357 ecr 3648620151], length 0
12:24:23.331143 n1    In  IP6 fc00:11:: > fc00:201:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:201:1::) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 31, win 509, options [nop,nop,TS val 1107741357 ecr 3648620151], length 0
12:24:23.331147 hv1   Out IP6 fc00:11:: > fc00:201:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:201:1::) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 31, win 509, options [nop,nop,TS val 1107741357 ecr 3648620151], length 0

===
===

12:24:40.696331 hv1   In  IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 31:44, ack 1, win 502, options [nop,nop,TS val 3648637516 ecr 1107741357], length 13
12:24:40.696364 l1    Out IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 31:44, ack 1, win 502, options [nop,nop,TS val 3648637516 ecr 1107741357], length 13
12:24:40.696394 l1    In  IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 31:44, ack 1, win 502, options [nop,nop,TS val 3648637516 ecr 1107741357], length 13
12:24:40.696402 n2    Out IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 31:44, ack 1, win 502, options [nop,nop,TS val 3648637516 ecr 1107741357], length 13
12:24:40.696412 n2    In  IP6 fc00:12:: > fc00:11:1::1: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::1) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 31:44, ack 1, win 502, options [nop,nop,TS val 3648637516 ecr 1107741357], length 13
12:24:40.696417 n1    Out IP6 fc00:12:: > fc00:11:1::1: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::1) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 31:44, ack 1, win 502, options [nop,nop,TS val 3648637516 ecr 1107741357], length 13
12:24:40.696455 n1    In  IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 31:44, ack 1, win 502, options [nop,nop,TS val 3648637516 ecr 1107741357], length 13
12:24:40.696463 c1    Out IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 31:44, ack 1, win 502, options [nop,nop,TS val 3648637516 ecr 1107741357], length 13

12:24:40.696477 c1    In  IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 44, win 509, options [nop,nop,TS val 1107758722 ecr 3648637516], length 0
12:24:40.696487 l1    Out IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 44, win 509, options [nop,nop,TS val 1107758722 ecr 3648637516], length 0
12:24:40.696495 l1    In  IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 44, win 509, options [nop,nop,TS val 1107758722 ecr 3648637516], length 0
12:24:40.696498 n2    Out IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 44, win 509, options [nop,nop,TS val 1107758722 ecr 3648637516], length 0
12:24:40.696506 n2    In  IP6 fc00:12:: > fc00:11:1::1: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::1) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 44, win 509, options [nop,nop,TS val 1107758722 ecr 3648637516], length 0
12:24:40.696508 n1    Out IP6 fc00:12:: > fc00:11:1::1: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::1) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 44, win 509, options [nop,nop,TS val 1107758722 ecr 3648637516], length 0
12:24:40.696518 n1    In  IP6 fc00:11:: > fc00:201:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:201:1::) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 44, win 509, options [nop,nop,TS val 1107758722 ecr 3648637516], length 0
12:24:40.696521 hv1   Out IP6 fc00:11:: > fc00:201:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:201:1::) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 44, win 509, options [nop,nop,TS val 1107758722 ecr 3648637516], length 0

12:24:46.241114 hv1   In  IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 44:56, ack 1, win 502, options [nop,nop,TS val 3648643061 ecr 1107758722], length 12
12:24:46.241127 l1    Out IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 44:56, ack 1, win 502, options [nop,nop,TS val 3648643061 ecr 1107758722], length 12
12:24:46.241157 l1    In  IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 44:56, ack 1, win 502, options [nop,nop,TS val 3648643061 ecr 1107758722], length 12
12:24:46.241163 n2    Out IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 44:56, ack 1, win 502, options [nop,nop,TS val 3648643061 ecr 1107758722], length 12
12:24:46.241177 n2    In  IP6 fc00:12:: > fc00:11:1::1: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::1) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 44:56, ack 1, win 502, options [nop,nop,TS val 3648643061 ecr 1107758722], length 12
12:24:46.241184 n1    Out IP6 fc00:12:: > fc00:11:1::1: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::1) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 44:56, ack 1, win 502, options [nop,nop,TS val 3648643061 ecr 1107758722], length 12
12:24:46.241219 n1    In  IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 44:56, ack 1, win 502, options [nop,nop,TS val 3648643061 ecr 1107758722], length 12
12:24:46.241227 c1    Out IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [P.], seq 44:56, ack 1, win 502, options [nop,nop,TS val 3648643061 ecr 1107758722], length 12

12:24:46.241240 c1    In  IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 56, win 509, options [nop,nop,TS val 1107764267 ecr 3648643061], length 0
12:24:46.241253 l1    Out IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 56, win 509, options [nop,nop,TS val 1107764267 ecr 3648643061], length 0
12:24:46.241269 l1    In  IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 56, win 509, options [nop,nop,TS val 1107764267 ecr 3648643061], length 0
12:24:46.241271 n2    Out IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 56, win 509, options [nop,nop,TS val 1107764267 ecr 3648643061], length 0
12:24:46.241284 n2    In  IP6 fc00:12:: > fc00:11:1::1: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::1) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 56, win 509, options [nop,nop,TS val 1107764267 ecr 3648643061], length 0
12:24:46.241286 n1    Out IP6 fc00:12:: > fc00:11:1::1: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::1) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 56, win 509, options [nop,nop,TS val 1107764267 ecr 3648643061], length 0
12:24:46.241298 n1    In  IP6 fc00:11:: > fc00:201:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:201:1::) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 56, win 509, options [nop,nop,TS val 1107764267 ecr 3648643061], length 0
12:24:46.241302 hv1   Out IP6 fc00:11:: > fc00:201:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:201:1::) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [.], ack 56, win 509, options [nop,nop,TS val 1107764267 ecr 3648643061], length 0

=====

12:24:53.126553 hv1   In  IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [F.], seq 56, ack 1, win 502, options [nop,nop,TS val 3648649946 ecr 1107764267], length 0
12:24:53.126568 l1    Out IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [F.], seq 56, ack 1, win 502, options [nop,nop,TS val 3648649946 ecr 1107764267], length 0
12:24:53.126594 l1    In  IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [F.], seq 56, ack 1, win 502, options [nop,nop,TS val 3648649946 ecr 1107764267], length 0
12:24:53.126599 n2    Out IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [F.], seq 56, ack 1, win 502, options [nop,nop,TS val 3648649946 ecr 1107764267], length 0
12:24:53.126610 n2    In  IP6 fc00:12:: > fc00:11:1::1: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::1) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [F.], seq 56, ack 1, win 502, options [nop,nop,TS val 3648649946 ecr 1107764267], length 0
12:24:53.126615 n1    Out IP6 fc00:12:: > fc00:11:1::1: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::1) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [F.], seq 56, ack 1, win 502, options [nop,nop,TS val 3648649946 ecr 1107764267], length 0
12:24:53.126649 n1    In  IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [F.], seq 56, ack 1, win 502, options [nop,nop,TS val 3648649946 ecr 1107764267], length 0
12:24:53.126657 c1    Out IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [F.], seq 56, ack 1, win 502, options [nop,nop,TS val 3648649946 ecr 1107764267], length 0

12:24:53.126723 c1    In  IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [F.], seq 1, ack 57, win 509, options [nop,nop,TS val 1107771152 ecr 3648649946], length 0
12:24:53.126729 l1    Out IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [F.], seq 1, ack 57, win 509, options [nop,nop,TS val 1107771152 ecr 3648649946], length 0
12:24:53.126751 l1    In  IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [F.], seq 1, ack 57, win 509, options [nop,nop,TS val 1107771152 ecr 3648649946], length 0
12:24:53.126756 n2    Out IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [F.], seq 1, ack 57, win 509, options [nop,nop,TS val 1107771152 ecr 3648649946], length 0
12:24:53.126764 n2    In  IP6 fc00:12:: > fc00:11:1::1: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::1) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [F.], seq 1, ack 57, win 509, options [nop,nop,TS val 1107771152 ecr 3648649946], length 0
12:24:53.126766 n1    Out IP6 fc00:12:: > fc00:11:1::1: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::1) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [F.], seq 1, ack 57, win 509, options [nop,nop,TS val 1107771152 ecr 3648649946], length 0
12:24:53.126781 n1    In  IP6 fc00:11:: > fc00:201:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:201:1::) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [F.], seq 1, ack 57, win 509, options [nop,nop,TS val 1107771152 ecr 3648649946], length 0
12:24:53.126785 hv1   Out IP6 fc00:11:: > fc00:201:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:201:1::) IP 10.255.100.1.7777 > 10.254.0.10.54676: Flags [F.], seq 1, ack 57, win 509, options [nop,nop,TS val 1107771152 ecr 3648649946], length 0

12:24:53.126889 hv1   In  IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [.], ack 2, win 502, options [nop,nop,TS val 3648649946 ecr 1107771152], length 0
12:24:53.126892 l1    Out IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [.], ack 2, win 502, options [nop,nop,TS val 3648649946 ecr 1107771152], length 0
12:24:53.126908 l1    In  IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [.], ack 2, win 502, options [nop,nop,TS val 3648649946 ecr 1107771152], length 0
12:24:53.126910 n2    Out IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [.], ack 2, win 502, options [nop,nop,TS val 3648649946 ecr 1107771152], length 0
12:24:53.126919 n2    In  IP6 fc00:12:: > fc00:11:1::1: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::1) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [.], ack 2, win 502, options [nop,nop,TS val 3648649946 ecr 1107771152], length 0
12:24:53.126921 n1    Out IP6 fc00:12:: > fc00:11:1::1: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:11:1::1) IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [.], ack 2, win 502, options [nop,nop,TS val 3648649946 ecr 1107771152], length 0
12:24:53.126932 n1    In  IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [.], ack 2, win 502, options [nop,nop,TS val 3648649946 ecr 1107771152], length 0
12:24:53.126935 c1    Out IP 10.254.0.10.54676 > 10.255.100.1.7777: Flags [.], ack 2, win 502, options [nop,nop,TS val 3648649946 ecr 1107771152], length 0

====
====

12:25:04.051422 hv1   In  IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [S], seq 824228831, win 64240, options [mss 1460,sackOK,TS val 3648660871 ecr 0,nop,wscale 7], length 0
12:25:04.051436 l1    Out IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [S], seq 824228831, win 64240, options [mss 1460,sackOK,TS val 3648660871 ecr 0,nop,wscale 7], length 0
12:25:04.051461 l1    In  IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [S], seq 824228831, win 64240, options [mss 1460,sackOK,TS val 3648660871 ecr 0,nop,wscale 7], length 0
12:25:04.051466 n2    Out IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [S], seq 824228831, win 64240, options [mss 1460,sackOK,TS val 3648660871 ecr 0,nop,wscale 7], length 0
12:25:04.051519 n2    In  IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [S], seq 824228831, win 64240, options [mss 1460,sackOK,TS val 3648660871 ecr 0,nop,wscale 7], length 0
12:25:04.051526 c1    Out IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [S], seq 824228831, win 64240, options [mss 1460,sackOK,TS val 3648660871 ecr 0,nop,wscale 7], length 0

12:25:04.051544 c1    In  IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [S.], seq 2516902141, ack 824228832, win 65160, options [mss 1460,sackOK,TS val 1107782077 ecr 3648660871,nop,wscale 7], length 0
12:25:04.051547 l1    Out IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [S.], seq 2516902141, ack 824228832, win 65160, options [mss 1460,sackOK,TS val 1107782077 ecr 3648660871,nop,wscale 7], length 0
12:25:04.051552 l1    In  IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [S.], seq 2516902141, ack 824228832, win 65160, options [mss 1460,sackOK,TS val 1107782077 ecr 3648660871,nop,wscale 7], length 0
12:25:04.051570 n2    Out IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [S.], seq 2516902141, ack 824228832, win 65160, options [mss 1460,sackOK,TS val 1107782077 ecr 3648660871,nop,wscale 7], length 0
12:25:04.051583 n2    In  IP6 fc00:12:: > fc00:201:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:201:1::) IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [S.], seq 2516902141, ack 824228832, win 65160, options [mss 1460,sackOK,TS val 1107782077 ecr 3648660871,nop,wscale 7], length 0
12:25:04.051587 hv1   Out IP6 fc00:12:: > fc00:201:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:201:1::) IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [S.], seq 2516902141, ack 824228832, win 65160, options [mss 1460,sackOK,TS val 1107782077 ecr 3648660871,nop,wscale 7], length 0

12:25:04.051633 hv1   In  IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [.], ack 1, win 502, options [nop,nop,TS val 3648660871 ecr 1107782077], length 0
12:25:04.051635 l1    Out IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [.], ack 1, win 502, options [nop,nop,TS val 3648660871 ecr 1107782077], length 0
12:25:04.051643 l1    In  IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [.], ack 1, win 502, options [nop,nop,TS val 3648660871 ecr 1107782077], length 0
12:25:04.051645 n2    Out IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [.], ack 1, win 502, options [nop,nop,TS val 3648660871 ecr 1107782077], length 0
12:25:04.051656 n2    In  IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [.], ack 1, win 502, options [nop,nop,TS val 3648660871 ecr 1107782077], length 0
12:25:04.051658 c1    Out IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [.], ack 1, win 502, options [nop,nop,TS val 3648660871 ecr 1107782077], length 0

12:25:08.134113 hv1   In  IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [P.], seq 1:14, ack 1, win 502, options [nop,nop,TS val 3648664954 ecr 1107782077], length 13
12:25:08.134126 l1    Out IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [P.], seq 1:14, ack 1, win 502, options [nop,nop,TS val 3648664954 ecr 1107782077], length 13
12:25:08.134151 l1    In  IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [P.], seq 1:14, ack 1, win 502, options [nop,nop,TS val 3648664954 ecr 1107782077], length 13
12:25:08.134155 n2    Out IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [P.], seq 1:14, ack 1, win 502, options [nop,nop,TS val 3648664954 ecr 1107782077], length 13
12:25:08.134187 n2    In  IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [P.], seq 1:14, ack 1, win 502, options [nop,nop,TS val 3648664954 ecr 1107782077], length 13
12:25:08.134195 c1    Out IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [P.], seq 1:14, ack 1, win 502, options [nop,nop,TS val 3648664954 ecr 1107782077], length 13

12:25:08.134210 c1    In  IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [.], ack 14, win 509, options [nop,nop,TS val 1107786160 ecr 3648664954], length 0
12:25:08.134213 l1    Out IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [.], ack 14, win 509, options [nop,nop,TS val 1107786160 ecr 3648664954], length 0
12:25:08.134218 l1    In  IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [.], ack 14, win 509, options [nop,nop,TS val 1107786160 ecr 3648664954], length 0
12:25:08.134219 n2    Out IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [.], ack 14, win 509, options [nop,nop,TS val 1107786160 ecr 3648664954], length 0
12:25:08.134229 n2    In  IP6 fc00:12:: > fc00:201:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:201:1::) IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [.], ack 14, win 509, options [nop,nop,TS val 1107786160 ecr 3648664954], length 0
12:25:08.134235 hv1   Out IP6 fc00:12:: > fc00:201:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:201:1::) IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [.], ack 14, win 509, options [nop,nop,TS val 1107786160 ecr 3648664954], length 0

12:25:12.055501 hv1   In  IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [P.], seq 14:36, ack 1, win 502, options [nop,nop,TS val 3648668875 ecr 1107786160], length 22
12:25:12.055513 l1    Out IP6 fc00:201:: > fc00:1:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:1:1::) IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [P.], seq 14:36, ack 1, win 502, options [nop,nop,TS val 3648668875 ecr 1107786160], length 22
12:25:12.055536 l1    In  IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [P.], seq 14:36, ack 1, win 502, options [nop,nop,TS val 3648668875 ecr 1107786160], length 22
12:25:12.055541 n2    Out IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [P.], seq 14:36, ack 1, win 502, options [nop,nop,TS val 3648668875 ecr 1107786160], length 22
12:25:12.055688 n2    In  IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [P.], seq 14:36, ack 1, win 502, options [nop,nop,TS val 3648668875 ecr 1107786160], length 22
12:25:12.055701 c1    Out IP 10.254.0.10.48418 > 10.255.100.1.7777: Flags [P.], seq 14:36, ack 1, win 502, options [nop,nop,TS val 3648668875 ecr 1107786160], length 22

12:25:12.055718 c1    In  IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [.], ack 36, win 509, options [nop,nop,TS val 1107790081 ecr 3648668875], length 0
12:25:12.055738 l1    Out IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [.], ack 36, win 509, options [nop,nop,TS val 1107790081 ecr 3648668875], length 0
12:25:12.055762 l1    In  IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [.], ack 36, win 509, options [nop,nop,TS val 1107790081 ecr 3648668875], length 0
12:25:12.055770 n2    Out IP6 fc00:1:: > fc00:12:1::11: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:12:1::11) IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [.], ack 36, win 509, options [nop,nop,TS val 1107790081 ecr 3648668875], length 0
12:25:12.055789 n2    In  IP6 fc00:12:: > fc00:201:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:201:1::) IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [.], ack 36, win 509, options [nop,nop,TS val 1107790081 ecr 3648668875], length 0
12:25:12.055794 hv1   Out IP6 fc00:12:: > fc00:201:1::: RT6 (len=2, type=4, segleft=0, last-entry=0, tag=0, [0]fc00:201:1::) IP 10.255.100.1.7777 > 10.254.0.10.48418: Flags [.], ack 36, win 509, options [nop,nop,TS val 1107790081 ecr 3648668875], length 0
```
