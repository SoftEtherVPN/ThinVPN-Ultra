// Thin Telework System Global Const

#pragma warning(disable : 4819)

#ifndef	GLOBAL_CONST_H
#define	GLOBAL_CONST_H

//// For DeskVPN
#define DESK_SECURE_PACK_EASY_MODE		// 有効にすると簡易モードになる
#define DU_SHOW_THEEND_KEY_NAME			"ShowTheEndDialog_Ver01"		// お疲れ様でした有効化キー
#define	DU_ENABLE_RELAX_KEY_NAME		"EnableRelaxMode"				// リラックスモード
#define	DESK_SVC_NAME					"DESK"	// WideTunnel 内でのサービス名

#define DS_CONFIG_FILENAME			"@ThinSvr.config"
#define DS_CONFIG_FILENAME2			L"ThinSvr.config"
#define	DC_CONFIG_FILENAME			L"ThinClient.config"
#define DU_WHITELIST_FILENAME		"|WhiteListRules.txt"
#define DI_FILENAME_SETUPINI		L"@ThinSetup.ini"

#define DS_EXE_COPY_FILENAME_FOR_EVENTLOG_RES	L"_EventLogResource.exe"

// マスター証明書ファイル名。このファイルが同一ディレクトリに置いてあったら、自分自身の証明書は動的生成する
#define WT_MASTER_CERT_NAME			"@00_Master.cer"
#define WT_MASTER_KET_NAME			"@00_Master.key"

//#define WT_TEST_WIDECONTROL_PROXY_CLIENT		// 本家と接続できないことのシミュレーション


// ここから下は おそらくいじらなくて OK
#define DC_RDP_PORT_START				3500	// Client の RDP ポートの開始番号
#define DS_URDP_PORT					3457	// User-mode RDP ポート
#define DS_RDP_PORT						3389	// RDP のデフォルトのポート番号



//// Basic Variables
#define	CEDAR_SERVER_STR			"SoftEther VPN Server"
#define	CEDAR_BRIDGE_STR			"SoftEther VPN Bridge"
#define	CEDAR_BETA_SERVER			"SoftEther VPN Server Pre Release"
#define	CEDAR_MANAGER_STR			"SoftEther VPN Server Manager"
#define	CEDAR_CUI_STR				"SoftEther VPN Command-Line Admin Tool"
#define CEDAR_ELOG					"SoftEther EtherLogger"
#define	CEDAR_CLIENT_STR			"SoftEther VPN Client"
#define CEDAR_CLIENT_MANAGER_STR	"SoftEther VPN Client Connection Manager"
#define	CEDAR_ROUTER_STR			"SoftEther VPN User-mode Router"
#define	CEDAR_SERVER_LINK_STR		"SoftEther VPN Server (Cascade Mode)"
#define	CEDAR_BRIDGE_LINK_STR		"SoftEther VPN Bridge (Cascade Mode)"
#define	CEDAR_SERVER_FARM_STR		"SoftEther VPN Server (Cluster RPC Mode)"



//// Default Port Number

#define	GC_DEFAULT_PORT		5555
#define	GC_CLIENT_CONFIG_PORT	9930
#define	GC_CLIENT_NOTIFY_PORT	9983


//// Software Name

#define	GC_SVC_NAME_VPNSERVER		"SEVPNSERVER"
#define	GC_SVC_NAME_VPNCLIENT		"SEVPNCLIENT"
#define	GC_SVC_NAME_VPNBRIDGE		"SEVPNBRIDGE"






//// Setup Wizard

#define	GC_SW_UIHELPER_REGVALUE		"SoftEther VPN Client UI Helper"
#define	GC_SW_SOFTETHER_PREFIX		""
#define	GC_SW_SOFTETHER_PREFIX_W	L""



//// VPN UI Components

#define	GC_UI_APPID_CM				L"SoftEther.SoftEther VPN Client"



#include "Vars.h"


#endif	// GLOBAL_CONST_H

