# Variables

#CC=gcc

OPTIONS_COMPILE_DEBUG=-D_DEBUG -DDEBUG -DUNIX -DUNIX_LINUX -DCPU_64 -D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64 -I./ -I./Cedar/ -I./Mayaqua/ -g -fsigned-char

OPTIONS_LINK_DEBUG=-g -fsigned-char -lm -ldl -lrt -lpthread -lssl -lcrypto -lreadline -lncurses -lz

OPTIONS_COMPILE_RELEASE=-DNDEBUG -DVPN_SPEED -DUNIX -DUNIX_LINUX -DCPU_64 -D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64 -I./ -I./Cedar/ -I./Mayaqua/ -O2 -fsigned-char

OPTIONS_LINK_RELEASE=-O2 -fsigned-char -lm -ldl -lrt -lpthread -lssl -lcrypto -lreadline -lncurses -lz

ifeq ($(DEBUG),YES)
	OPTIONS_COMPILE=$(OPTIONS_COMPILE_DEBUG)
	OPTIONS_LINK=$(OPTIONS_LINK_DEBUG)
else
	OPTIONS_COMPILE=$(OPTIONS_COMPILE_RELEASE)
	OPTIONS_LINK=$(OPTIONS_LINK_RELEASE)
endif

# Files
HEADERS_MAYAQUA=Mayaqua/Cfg.h Mayaqua/cryptoki.h Mayaqua/Encrypt.h Mayaqua/FileIO.h Mayaqua/intelaes/iaesni.h Mayaqua/Internat.h Mayaqua/Kernel.h Mayaqua/Mayaqua.h Mayaqua/MayaType.h Mayaqua/Memory.h Mayaqua/Microsoft.h Mayaqua/Network.h Mayaqua/Object.h Mayaqua/OS.h Mayaqua/Pack.h Mayaqua/pkcs11.h Mayaqua/pkcs11f.h Mayaqua/pkcs11t.h Mayaqua/Secure.h Mayaqua/Str.h Mayaqua/Table.h Mayaqua/TcpIp.h Mayaqua/Tick64.h Mayaqua/Tracking.h Mayaqua/TunTap.h Mayaqua/Unix.h Mayaqua/Win32.h Mayaqua/zlib/zconf.h Mayaqua/zlib/zlib.h

HEADERS_CEDAR=Cedar/Account.h Cedar/Admin.h Cedar/AzureClient.h Cedar/AzureServer.h Cedar/Bridge.h Cedar/BridgeUnix.h Cedar/BridgeWin32.h Cedar/Cedar.h Cedar/CedarPch.h Cedar/CedarType.h Cedar/Client.h Cedar/CM.h Cedar/CMInner.h Cedar/Command.h Cedar/Connection.h Cedar/Console.h Cedar/Database.h Cedar/DDNS.h Cedar/EM.h Cedar/EMInner.h Cedar/EtherLog.h Cedar/Hub.h Cedar/Interop_OpenVPN.h Cedar/Interop_SSTP.h Cedar/IPsec.h Cedar/IPsec_EtherIP.h Cedar/IPsec_IKE.h Cedar/IPsec_IkePacket.h Cedar/IPsec_IPC.h Cedar/IPsec_L2TP.h Cedar/IPsec_PPP.h Cedar/IPsec_Win7.h Cedar/IPsec_Win7Inner.h Cedar/Layer3.h Cedar/Link.h Cedar/Listener.h Cedar/Logging.h Cedar/Nat.h Cedar/NativeStack.h Cedar/netcfgn.h Cedar/netcfgx.h Cedar/NM.h Cedar/NMInner.h Cedar/NullLan.h Cedar/Protocol.h Cedar/Radius.h Cedar/Remote.h Cedar/Sam.h Cedar/SecureInfo.h Cedar/SecureNAT.h Cedar/SeLowUser.h Cedar/Server.h Cedar/Session.h Cedar/SM.h Cedar/SMInner.h Cedar/SW.h Cedar/SWInner.h Cedar/UdpAccel.h Cedar/UT.h Cedar/VG.h Cedar/Virtual.h Cedar/VLan.h Cedar/VLanUnix.h Cedar/VLanWin32.h Cedar/WaterMark.h Cedar/WebUI.h Cedar/Win32Com.h Cedar/winpcap/bittypes.h Cedar/winpcap/bucket_lookup.h Cedar/winpcap/count_packets.h Cedar/winpcap/Devioctl.h Cedar/winpcap/Gnuc.h Cedar/winpcap/ip6_misc.h Cedar/winpcap/memory_t.h Cedar/winpcap/normal_lookup.h Cedar/winpcap/Ntddndis.h Cedar/winpcap/Ntddpack.h Cedar/winpcap/Packet32.h Cedar/winpcap/pcap.h Cedar/winpcap/pcap-bpf.h Cedar/winpcap/pcap-int.h Cedar/winpcap/pcap-stdinc.h Cedar/winpcap/pthread.h Cedar/winpcap/remote-ext.h Cedar/winpcap/sched.h Cedar/winpcap/semaphore.h Cedar/winpcap/tcp_session.h Cedar/winpcap/time_calls.h Cedar/winpcap/tme.h Cedar/winpcap/Win32-Extensions.h Cedar/WinUi.h Cedar/Wpc.h Cedar/DC.h Cedar/Desk.h Cedar/DeskType.h Cedar/DG.h Cedar/DG_Inner.h Cedar/DI.h Cedar/DI_Inner.h Cedar/DS.h Cedar/DsRpc.h Cedar/DU.h Cedar/DU_Inner.h Cedar/Wide.h Cedar/Wt.h Cedar/WtClient.h Cedar/WtGate.h Cedar/WtServer.h Cedar/WtType.h Cedar/WtWpc.h

OBJECTS_MAYAQUA=tmp/objs/Mayaqua/Cfg.o tmp/objs/Mayaqua/Encrypt.o tmp/objs/Mayaqua/FileIO.o tmp/objs/Mayaqua/Internat.o tmp/objs/Mayaqua/Kernel.o tmp/objs/Mayaqua/Mayaqua.o tmp/objs/Mayaqua/Memory.o tmp/objs/Mayaqua/Microsoft.o tmp/objs/Mayaqua/Network.o tmp/objs/Mayaqua/Object.o tmp/objs/Mayaqua/OS.o tmp/objs/Mayaqua/Pack.o tmp/objs/Mayaqua/Secure.o tmp/objs/Mayaqua/Str.o tmp/objs/Mayaqua/Table.o tmp/objs/Mayaqua/TcpIp.o tmp/objs/Mayaqua/Tick64.o tmp/objs/Mayaqua/Tracking.o tmp/objs/Mayaqua/Unix.o tmp/objs/Mayaqua/Win32.o

OBJECTS_CEDAR=tmp/objs/Cedar/Account.o tmp/objs/Cedar/Admin.o tmp/objs/Cedar/AzureClient.o tmp/objs/Cedar/AzureServer.o tmp/objs/Cedar/Bridge.o tmp/objs/Cedar/BridgeUnix.o tmp/objs/Cedar/BridgeWin32.o tmp/objs/Cedar/Cedar.o tmp/objs/Cedar/CedarPch.o tmp/objs/Cedar/Client.o tmp/objs/Cedar/CM.o tmp/objs/Cedar/Command.o tmp/objs/Cedar/Connection.o tmp/objs/Cedar/Console.o tmp/objs/Cedar/Database.o tmp/objs/Cedar/DDNS.o tmp/objs/Cedar/EM.o tmp/objs/Cedar/EtherLog.o tmp/objs/Cedar/Hub.o tmp/objs/Cedar/Interop_OpenVPN.o tmp/objs/Cedar/Interop_SSTP.o tmp/objs/Cedar/IPsec.o tmp/objs/Cedar/IPsec_EtherIP.o tmp/objs/Cedar/IPsec_IKE.o tmp/objs/Cedar/IPsec_IkePacket.o tmp/objs/Cedar/IPsec_IPC.o tmp/objs/Cedar/IPsec_L2TP.o tmp/objs/Cedar/IPsec_PPP.o tmp/objs/Cedar/IPsec_Win7.o tmp/objs/Cedar/Layer3.o tmp/objs/Cedar/Link.o tmp/objs/Cedar/Listener.o tmp/objs/Cedar/Logging.o tmp/objs/Cedar/Nat.o tmp/objs/Cedar/NativeStack.o tmp/objs/Cedar/NM.o tmp/objs/Cedar/NullLan.o tmp/objs/Cedar/Protocol.o tmp/objs/Cedar/Radius.o tmp/objs/Cedar/Remote.o tmp/objs/Cedar/Sam.o tmp/objs/Cedar/SecureInfo.o tmp/objs/Cedar/SecureNAT.o tmp/objs/Cedar/SeLowUser.o tmp/objs/Cedar/Server.o tmp/objs/Cedar/Session.o tmp/objs/Cedar/SM.o tmp/objs/Cedar/SW.o tmp/objs/Cedar/UdpAccel.o tmp/objs/Cedar/UT.o tmp/objs/Cedar/VG.o tmp/objs/Cedar/Virtual.o tmp/objs/Cedar/VLan.o tmp/objs/Cedar/VLanUnix.o tmp/objs/Cedar/VLanWin32.o tmp/objs/Cedar/WaterMark.o tmp/objs/Cedar/WebUI.o tmp/objs/Cedar/WinUi.o tmp/objs/Cedar/Wpc.o tmp/objs/Cedar/DC.o tmp/objs/Cedar/Desk.o tmp/objs/Cedar/DG.o tmp/objs/Cedar/DI.o tmp/objs/Cedar/DS.o tmp/objs/Cedar/DsRpc.o tmp/objs/Cedar/DU.o tmp/objs/Cedar/Wide.o tmp/objs/Cedar/Wt.o tmp/objs/Cedar/WtClient.o tmp/objs/Cedar/WtGate.o tmp/objs/Cedar/WtServer.o tmp/objs/Cedar/WtWpc.o

HAMCORE_FILES=src/bin/hamcore/authors.txt src/bin/hamcore/backup_dir_readme.txt src/bin/hamcore/empty.config src/bin/hamcore/empty_sevpnclient.config src/bin/hamcore/eula.txt src/bin/hamcore/install_src.dat src/bin/hamcore/lang.config src/bin/hamcore/languages.txt src/bin/hamcore/languages_wine.txt src/bin/hamcore/legal.txt src/bin/hamcore/openvpn_readme.pdf src/bin/hamcore/openvpn_readme.txt src/bin/hamcore/openvpn_sample.ovpn src/bin/hamcore/root_certs.dat src/bin/hamcore/SOURCES_OF_BINARY_FILES.TXT src/bin/hamcore/strtable_cn.stb src/bin/hamcore/strtable_en.stb src/bin/hamcore/strtable_ja.stb src/bin/hamcore/vpnserver_api_doc.html src/bin/hamcore/vpnweb_sample_cn.htm src/bin/hamcore/vpnweb_sample_en.htm src/bin/hamcore/vpnweb_sample_ja.htm src/bin/hamcore/warning_cn.txt src/bin/hamcore/warning_en.txt src/bin/hamcore/warning_ja.txt src/bin/hamcore/webui/cryptcom.cgi src/bin/hamcore/webui/edituser.cgi src/bin/hamcore/webui/error.cgi src/bin/hamcore/webui/hub.cgi src/bin/hamcore/webui/license.cgi src/bin/hamcore/webui/listener.cgi src/bin/hamcore/webui/localbridge.cgi src/bin/hamcore/webui/login.cgi src/bin/hamcore/webui/newhub.cgi src/bin/hamcore/webui/redirect.cgi src/bin/hamcore/webui/securenat.cgi src/bin/hamcore/webui/server.cgi src/bin/hamcore/webui/session.cgi src/bin/hamcore/webui/user.cgi src/bin/hamcore/webui/webui.css src/bin/hamcore/wwwroot/admin/default/.gitignore src/bin/hamcore/wwwroot/admin/default/.vscode/launch.json src/bin/hamcore/wwwroot/admin/default/.vscode/settings.json src/bin/hamcore/wwwroot/admin/default/.vscode/tasks.json src/bin/hamcore/wwwroot/admin/default/hub.html src/bin/hamcore/wwwroot/admin/default/include_footer.html src/bin/hamcore/wwwroot/admin/default/include_head.html src/bin/hamcore/wwwroot/admin/default/include_menu.html src/bin/hamcore/wwwroot/admin/default/index.html src/bin/hamcore/wwwroot/admin/default/out_webpack/bundle.js src/bin/hamcore/wwwroot/admin/default/out_webpack/ts/index.d.ts src/bin/hamcore/wwwroot/admin/default/out_webpack/ts/index.d.ts.map src/bin/hamcore/wwwroot/admin/default/out_webpack/ts/main.d.ts src/bin/hamcore/wwwroot/admin/default/out_webpack/ts/main.d.ts.map src/bin/hamcore/wwwroot/admin/default/out_webpack/ts/vpnadmin.d.ts src/bin/hamcore/wwwroot/admin/default/out_webpack/ts/vpnadmin.d.ts.map src/bin/hamcore/wwwroot/admin/default/package.json src/bin/hamcore/wwwroot/admin/default/package-lock.json src/bin/hamcore/wwwroot/admin/default/src/ts/main.ts src/bin/hamcore/wwwroot/admin/default/theme.css src/bin/hamcore/wwwroot/admin/default/tsconfig.json src/bin/hamcore/wwwroot/admin/default/tsconfig_webpack.json src/bin/hamcore/wwwroot/admin/default/tslint.json src/bin/hamcore/wwwroot/admin/default/webpack.config.js src/bin/hamcore/wwwroot/admin/index.html src/bin/hamcore/wwwroot/admin/README.md src/bin/hamcore/wwwroot/index.html

# Build Action
default:	build

build:	$(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) bin/widegate bin/ham

# Mayaqua Kernel Code
tmp/objs/Mayaqua/Cfg.o: Mayaqua/Cfg.c $(HEADERS_MAYAQUA)
	@mkdir -p tmp/
	@mkdir -p tmp/objs/
	@mkdir -p tmp/objs/Mayaqua/
	@mkdir -p tmp/objs/Cedar/
	@mkdir -p tmp/as/
	@mkdir -p bin/
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Cfg.c -o tmp/objs/Mayaqua/Cfg.o

tmp/objs/Mayaqua/Encrypt.o: Mayaqua/Encrypt.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Encrypt.c -o tmp/objs/Mayaqua/Encrypt.o

tmp/objs/Mayaqua/FileIO.o: Mayaqua/FileIO.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/FileIO.c -o tmp/objs/Mayaqua/FileIO.o

tmp/objs/Mayaqua/Internat.o: Mayaqua/Internat.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Internat.c -o tmp/objs/Mayaqua/Internat.o

tmp/objs/Mayaqua/Kernel.o: Mayaqua/Kernel.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Kernel.c -o tmp/objs/Mayaqua/Kernel.o

tmp/objs/Mayaqua/Mayaqua.o: Mayaqua/Mayaqua.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Mayaqua.c -o tmp/objs/Mayaqua/Mayaqua.o

tmp/objs/Mayaqua/Memory.o: Mayaqua/Memory.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Memory.c -o tmp/objs/Mayaqua/Memory.o

tmp/objs/Mayaqua/Microsoft.o: Mayaqua/Microsoft.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Microsoft.c -o tmp/objs/Mayaqua/Microsoft.o

tmp/objs/Mayaqua/Network.o: Mayaqua/Network.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Network.c -o tmp/objs/Mayaqua/Network.o

tmp/objs/Mayaqua/Object.o: Mayaqua/Object.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Object.c -o tmp/objs/Mayaqua/Object.o

tmp/objs/Mayaqua/OS.o: Mayaqua/OS.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/OS.c -o tmp/objs/Mayaqua/OS.o

tmp/objs/Mayaqua/Pack.o: Mayaqua/Pack.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Pack.c -o tmp/objs/Mayaqua/Pack.o

tmp/objs/Mayaqua/Secure.o: Mayaqua/Secure.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Secure.c -o tmp/objs/Mayaqua/Secure.o

tmp/objs/Mayaqua/Str.o: Mayaqua/Str.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Str.c -o tmp/objs/Mayaqua/Str.o

tmp/objs/Mayaqua/Table.o: Mayaqua/Table.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Table.c -o tmp/objs/Mayaqua/Table.o

tmp/objs/Mayaqua/TcpIp.o: Mayaqua/TcpIp.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/TcpIp.c -o tmp/objs/Mayaqua/TcpIp.o

tmp/objs/Mayaqua/Tick64.o: Mayaqua/Tick64.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Tick64.c -o tmp/objs/Mayaqua/Tick64.o

tmp/objs/Mayaqua/Tracking.o: Mayaqua/Tracking.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Tracking.c -o tmp/objs/Mayaqua/Tracking.o

tmp/objs/Mayaqua/Unix.o: Mayaqua/Unix.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Unix.c -o tmp/objs/Mayaqua/Unix.o

tmp/objs/Mayaqua/Win32.o: Mayaqua/Win32.c $(HEADERS_MAYAQUA)
	$(CC) $(OPTIONS_COMPILE) -c Mayaqua/Win32.c -o tmp/objs/Mayaqua/Win32.o

# Cedar Communication Module Code
tmp/objs/Cedar/Account.o: Cedar/Account.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Account.c -o tmp/objs/Cedar/Account.o

tmp/objs/Cedar/Admin.o: Cedar/Admin.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Admin.c -o tmp/objs/Cedar/Admin.o

tmp/objs/Cedar/AzureClient.o: Cedar/AzureClient.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/AzureClient.c -o tmp/objs/Cedar/AzureClient.o

tmp/objs/Cedar/AzureServer.o: Cedar/AzureServer.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/AzureServer.c -o tmp/objs/Cedar/AzureServer.o

tmp/objs/Cedar/Bridge.o: Cedar/Bridge.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) Cedar/BridgeUnix.c
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Bridge.c -o tmp/objs/Cedar/Bridge.o

tmp/objs/Cedar/BridgeUnix.o: Cedar/BridgeUnix.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/BridgeUnix.c -o tmp/objs/Cedar/BridgeUnix.o

tmp/objs/Cedar/BridgeWin32.o: Cedar/BridgeWin32.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/BridgeWin32.c -o tmp/objs/Cedar/BridgeWin32.o

tmp/objs/Cedar/Cedar.o: Cedar/Cedar.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Cedar.c -o tmp/objs/Cedar/Cedar.o

tmp/objs/Cedar/CedarPch.o: Cedar/CedarPch.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/CedarPch.c -o tmp/objs/Cedar/CedarPch.o

tmp/objs/Cedar/Client.o: Cedar/Client.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Client.c -o tmp/objs/Cedar/Client.o

tmp/objs/Cedar/CM.o: Cedar/CM.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/CM.c -o tmp/objs/Cedar/CM.o

tmp/objs/Cedar/Command.o: Cedar/Command.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Command.c -o tmp/objs/Cedar/Command.o

tmp/objs/Cedar/Connection.o: Cedar/Connection.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Connection.c -o tmp/objs/Cedar/Connection.o

tmp/objs/Cedar/Console.o: Cedar/Console.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Console.c -o tmp/objs/Cedar/Console.o

tmp/objs/Cedar/Database.o: Cedar/Database.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Database.c -o tmp/objs/Cedar/Database.o

tmp/objs/Cedar/DDNS.o: Cedar/DDNS.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/DDNS.c -o tmp/objs/Cedar/DDNS.o

tmp/objs/Cedar/EM.o: Cedar/EM.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/EM.c -o tmp/objs/Cedar/EM.o

tmp/objs/Cedar/EtherLog.o: Cedar/EtherLog.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/EtherLog.c -o tmp/objs/Cedar/EtherLog.o

tmp/objs/Cedar/Hub.o: Cedar/Hub.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Hub.c -o tmp/objs/Cedar/Hub.o

tmp/objs/Cedar/Interop_OpenVPN.o: Cedar/Interop_OpenVPN.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Interop_OpenVPN.c -o tmp/objs/Cedar/Interop_OpenVPN.o

tmp/objs/Cedar/Interop_SSTP.o: Cedar/Interop_SSTP.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Interop_SSTP.c -o tmp/objs/Cedar/Interop_SSTP.o

tmp/objs/Cedar/IPsec.o: Cedar/IPsec.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/IPsec.c -o tmp/objs/Cedar/IPsec.o

tmp/objs/Cedar/IPsec_EtherIP.o: Cedar/IPsec_EtherIP.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/IPsec_EtherIP.c -o tmp/objs/Cedar/IPsec_EtherIP.o

tmp/objs/Cedar/IPsec_IKE.o: Cedar/IPsec_IKE.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/IPsec_IKE.c -o tmp/objs/Cedar/IPsec_IKE.o

tmp/objs/Cedar/IPsec_IkePacket.o: Cedar/IPsec_IkePacket.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/IPsec_IkePacket.c -o tmp/objs/Cedar/IPsec_IkePacket.o

tmp/objs/Cedar/IPsec_IPC.o: Cedar/IPsec_IPC.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/IPsec_IPC.c -o tmp/objs/Cedar/IPsec_IPC.o

tmp/objs/Cedar/IPsec_L2TP.o: Cedar/IPsec_L2TP.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/IPsec_L2TP.c -o tmp/objs/Cedar/IPsec_L2TP.o

tmp/objs/Cedar/IPsec_PPP.o: Cedar/IPsec_PPP.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/IPsec_PPP.c -o tmp/objs/Cedar/IPsec_PPP.o

tmp/objs/Cedar/IPsec_Win7.o: Cedar/IPsec_Win7.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/IPsec_Win7.c -o tmp/objs/Cedar/IPsec_Win7.o

tmp/objs/Cedar/Layer3.o: Cedar/Layer3.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Layer3.c -o tmp/objs/Cedar/Layer3.o

tmp/objs/Cedar/Link.o: Cedar/Link.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Link.c -o tmp/objs/Cedar/Link.o

tmp/objs/Cedar/Listener.o: Cedar/Listener.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Listener.c -o tmp/objs/Cedar/Listener.o

tmp/objs/Cedar/Logging.o: Cedar/Logging.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Logging.c -o tmp/objs/Cedar/Logging.o

tmp/objs/Cedar/Nat.o: Cedar/Nat.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Nat.c -o tmp/objs/Cedar/Nat.o

tmp/objs/Cedar/NativeStack.o: Cedar/NativeStack.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/NativeStack.c -o tmp/objs/Cedar/NativeStack.o

tmp/objs/Cedar/NM.o: Cedar/NM.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/NM.c -o tmp/objs/Cedar/NM.o

tmp/objs/Cedar/NullLan.o: Cedar/NullLan.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/NullLan.c -o tmp/objs/Cedar/NullLan.o

tmp/objs/Cedar/Protocol.o: Cedar/Protocol.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Protocol.c -o tmp/objs/Cedar/Protocol.o

tmp/objs/Cedar/Radius.o: Cedar/Radius.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Radius.c -o tmp/objs/Cedar/Radius.o

tmp/objs/Cedar/Remote.o: Cedar/Remote.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Remote.c -o tmp/objs/Cedar/Remote.o

tmp/objs/Cedar/Sam.o: Cedar/Sam.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Sam.c -o tmp/objs/Cedar/Sam.o

tmp/objs/Cedar/SecureInfo.o: Cedar/SecureInfo.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/SecureInfo.c -o tmp/objs/Cedar/SecureInfo.o

tmp/objs/Cedar/SecureNAT.o: Cedar/SecureNAT.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/SecureNAT.c -o tmp/objs/Cedar/SecureNAT.o

tmp/objs/Cedar/SeLowUser.o: Cedar/SeLowUser.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/SeLowUser.c -o tmp/objs/Cedar/SeLowUser.o

tmp/objs/Cedar/Server.o: Cedar/Server.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Server.c -o tmp/objs/Cedar/Server.o

tmp/objs/Cedar/Session.o: Cedar/Session.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Session.c -o tmp/objs/Cedar/Session.o

tmp/objs/Cedar/SM.o: Cedar/SM.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/SM.c -o tmp/objs/Cedar/SM.o

tmp/objs/Cedar/SW.o: Cedar/SW.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/SW.c -o tmp/objs/Cedar/SW.o

tmp/objs/Cedar/UdpAccel.o: Cedar/UdpAccel.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/UdpAccel.c -o tmp/objs/Cedar/UdpAccel.o

tmp/objs/Cedar/UT.o: Cedar/UT.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/UT.c -o tmp/objs/Cedar/UT.o

tmp/objs/Cedar/VG.o: Cedar/VG.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/VG.c -o tmp/objs/Cedar/VG.o

tmp/objs/Cedar/Virtual.o: Cedar/Virtual.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Virtual.c -o tmp/objs/Cedar/Virtual.o

tmp/objs/Cedar/VLan.o: Cedar/VLan.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/VLan.c -o tmp/objs/Cedar/VLan.o

tmp/objs/Cedar/VLanUnix.o: Cedar/VLanUnix.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/VLanUnix.c -o tmp/objs/Cedar/VLanUnix.o

tmp/objs/Cedar/VLanWin32.o: Cedar/VLanWin32.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/VLanWin32.c -o tmp/objs/Cedar/VLanWin32.o

tmp/objs/Cedar/WaterMark.o: Cedar/WaterMark.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/WaterMark.c -o tmp/objs/Cedar/WaterMark.o

tmp/objs/Cedar/WebUI.o: Cedar/WebUI.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/WebUI.c -o tmp/objs/Cedar/WebUI.o

tmp/objs/Cedar/WinUi.o: Cedar/WinUi.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/WinUi.c -o tmp/objs/Cedar/WinUi.o

tmp/objs/Cedar/Wpc.o: Cedar/Wpc.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Wpc.c -o tmp/objs/Cedar/Wpc.o



tmp/objs/Cedar/DC.o: Cedar/DC.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/DC.c -o tmp/objs/Cedar/DC.o


tmp/objs/Cedar/Desk.o: Cedar/Desk.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Desk.c -o tmp/objs/Cedar/Desk.o


tmp/objs/Cedar/DG.o: Cedar/DG.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/DG.c -o tmp/objs/Cedar/DG.o


tmp/objs/Cedar/DI.o: Cedar/DI.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/DI.c -o tmp/objs/Cedar/DI.o


tmp/objs/Cedar/DS.o: Cedar/DS.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/DS.c -o tmp/objs/Cedar/DS.o


tmp/objs/Cedar/DsRpc.o: Cedar/DsRpc.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/DsRpc.c -o tmp/objs/Cedar/DsRpc.o


tmp/objs/Cedar/DU.o: Cedar/DU.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/DU.c -o tmp/objs/Cedar/DU.o


tmp/objs/Cedar/Wide.o: Cedar/Wide.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Wide.c -o tmp/objs/Cedar/Wide.o


tmp/objs/Cedar/Wt.o: Cedar/Wt.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/Wt.c -o tmp/objs/Cedar/Wt.o


tmp/objs/Cedar/WtClient.o: Cedar/WtClient.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/WtClient.c -o tmp/objs/Cedar/WtClient.o


tmp/objs/Cedar/WtGate.o: Cedar/WtGate.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/WtGate.c -o tmp/objs/Cedar/WtGate.o


tmp/objs/Cedar/WtServer.o: Cedar/WtServer.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/WtServer.c -o tmp/objs/Cedar/WtServer.o


tmp/objs/Cedar/WtWpc.o: Cedar/WtWpc.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Cedar/WtWpc.c -o tmp/objs/Cedar/WtWpc.o




# WideGate
bin/widegate: tmp/as/WideGate.a $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) tmp/as/WideGate.a $(OPTIONS_LINK) -o bin/widegate

tmp/as/WideGate.a: tmp/objs/WideGate.o $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	rm -f tmp/as/WideGate.a
	ar r tmp/as/WideGate.a $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) tmp/objs/WideGate.o
	ranlib tmp/as/WideGate.a

tmp/objs/WideGate.o: WideGate/WideGate.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c WideGate/WideGate.c -o tmp/objs/WideGate.o


# Ham
bin/ham: tmp/as/Ham.a $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) tmp/as/Ham.a $(OPTIONS_LINK) -o bin/ham

tmp/as/Ham.a: tmp/objs/Ham.o $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	rm -f tmp/as/Ham.a
	ar r tmp/as/Ham.a $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR) tmp/objs/Ham.o
	ranlib tmp/as/Ham.a

tmp/objs/Ham.o: Ham/Ham.c $(HEADERS_MAYAQUA) $(HEADERS_CEDAR) $(OBJECTS_MAYAQUA) $(OBJECTS_CEDAR)
	$(CC) $(OPTIONS_COMPILE) -c Ham/Ham.c -o tmp/objs/Ham.o


# Clean
clean:
	-rm -f $(OBJECTS_MAYAQUA)
	-rm -f $(OBJECTS_CEDAR)
	-rm -f tmp/objs/WideGate.o
	-rm -f tmp/as/WideGate.a
	-rm -f bin/WideGate/WideGate

# Help Strings
help:
	@echo "make [DEBUG=YES]"
	@echo "make install"
	@echo "make clean"

