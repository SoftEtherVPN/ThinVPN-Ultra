// WideTunnel Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// WtType.h
// 型一覧

#ifndef	WTTYPE_H
#define	WTTYPE_H

// Wt.h
typedef struct WT WT;
typedef struct SOCKTHREAD SOCKTHREAD;
typedef struct SOCKIO SOCKIO;
typedef struct USED_TUNNELID USED_TUNNELID;

// WtGate.h
typedef struct WT_GATE_CONNECT_PARAM WT_GATE_CONNECT_PARAM;
typedef struct TSESSION TSESSION;
typedef struct TTCP TTCP;
typedef struct TUNNEL TUNNEL;
typedef struct DATABLOCK DATABLOCK;

// WtServer.h
typedef struct WT_CONNECT WT_CONNECT;
typedef struct WTS_CONNECT_THREAD_PARAM WTS_CONNECT_THREAD_PARAM;
typedef struct WTS_NEW_TUNNEL_THREAD_PARAM WTS_NEW_TUNNEL_THREAD_PARAM;
typedef void (WT_ACCEPT_PROC)(THREAD *thread, SOCKIO *sock, void *param);

// WtWpc.h
typedef struct INTERNET_SETTING INTERNET_SETTING;
typedef struct URL_DATA URL_DATA;
typedef struct WPC_ENTRY WPC_ENTRY;
typedef struct WPC_PACKET WPC_PACKET;

// Wide.h
typedef struct WIDE WIDE;
typedef struct SECURE_PACK_FOLDER SECURE_PACK_FOLDER;
typedef struct MACHINE_ID MACHINE_ID;
typedef struct WIDE_LOGIN_INFO WIDE_LOGIN_INFO;
typedef struct CONNECT_MAIN_THREAD_PARAM CONNECT_MAIN_THREAD_PARAM;
typedef struct SESSION_AND_CLIENT SESSION_AND_CLIENT;
typedef struct SESSION_INFO_CACHE SESSION_INFO_CACHE;
typedef void (WIDE_RESET_CERT_PROC)(WIDE *wide, void *param);
typedef struct ACCEPT_QUEUE ACCEPT_QUEUE;
typedef struct ACCEPT_QUEUE_ENTRY ACCEPT_QUEUE_ENTRY;

#endif	// WTTYPE_H

