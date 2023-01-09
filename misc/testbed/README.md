# MF-plane user testbed

You can use mf-plane as trial.
To construct your wireguard endpoint,
you will submitt the user registration like bellow.

- example1: https://github.com/slankdev/mfplane/pull/16

```
diff --git a/misc/testbed/config.yaml b/misc/testbed/config.yaml
index fd20409..6839e7f 100644
--- a/misc/testbed/config.yaml
+++ b/misc/testbed/config.yaml
@@ -17,3 +17,7 @@ users:
   name: slankdev.imac
   owner: Hiroki Shirokura
   description: test2
+- id: f2cc8de6-9e06-4fe5-aca5-05b54f358f62  <--- please generate yourself
+  name: slankdev.imac
+  owner: Hiroki Shirokura
+  description: test3
```

Then, administrator will execute

```shell
$ ssh vpn.slank.dev
$ sudo bash
# cd /home/slankdev/mfplane/misc/testbed
# git pull
# ./reload.py
wg-quick down /etc/wireguard/cache/server.conf
wg-quick up /etc/wireguard/cache/server.conf

# wg-quick down /etc/wireguard/cache/server.conf
# wg-quick up /etc/wireguard/cache/server.conf
# cat /etc/wireguard/cache/client_f2cc8de6-9e06-4fe5-aca5-05b54f358f62.conf
```
